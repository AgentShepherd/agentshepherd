//go:build unix

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BakeLens/crust/internal/fileutil"
	"golang.org/x/sys/unix"
)

// pidLockFile holds the open PID file to maintain the flock advisory lock.
// The lock is held for the lifetime of the daemon process.
var pidLockFile *os.File

// WritePID writes the current process ID to the PID file with an exclusive
// advisory lock (flock). The lock prevents two daemon instances from running
// simultaneously. The returned file handle must remain open to hold the lock;
// call CleanupPID on shutdown.
func WritePID() error {
	path := pidFile()
	f, err := fileutil.SecureOpenFile(path, os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return fmt.Errorf("open PID file: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // Fd() fits in int on all supported platforms
		f.Close()
		return fmt.Errorf("another instance is running (flock %s): %w", path, err)
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return fmt.Errorf("truncate PID file: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d", os.Getpid()); err != nil {
		f.Close()
		return fmt.Errorf("write PID file: %w", err)
	}
	pidLockFile = f
	return nil
}

// CleanupPID releases the flock and removes the PID, port, and socket files.
func CleanupPID() {
	if pidLockFile != nil {
		pidLockFile.Close()
		pidLockFile = nil
	}
	_ = os.Remove(pidFile())
	_ = os.Remove(portFile())
	// Clean up any stale socket files matching the pattern crust-api-*.sock
	matches, err := filepath.Glob(filepath.Join(DataDir(), socketPrefix+"*.sock"))
	_ = err // glob pattern is well-formed; only errors on malformed patterns
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// IsRunning checks if the daemon is running by sending signal 0.
func IsRunning() (bool, int) {
	pid, err := ReadPID()
	if err != nil {
		return false, 0
	}

	// Check if process exists
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, 0
	}

	// Send signal 0 to check if process is alive
	err = process.Signal(syscall.Signal(0))
	if err != nil {
		// Process doesn't exist, clean up stale PID file
		_ = RemovePID() //nolint:errcheck // cleanup best effort
		return false, 0
	}

	return true, pid
}

// Stop stops the running daemon with SIGTERM, falling back to SIGKILL.
func Stop() error {
	running, pid := IsRunning()
	if !running {
		return errors.New("crust is not running")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process: %w", err)
	}

	// Send SIGTERM for graceful shutdown
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to stop crust: %w", err)
	}

	// Wait for process to exit (with timeout)
	for range 30 {
		time.Sleep(100 * time.Millisecond)
		if running, _ := IsRunning(); !running {
			return nil
		}
	}

	// Force kill if still running
	_ = process.Signal(syscall.SIGKILL)
	_ = RemovePID() //nolint:errcheck // cleanup best effort

	return nil
}

// Daemonize starts the current program as a background daemon.
// It re-executes the program with CRUST_DAEMON=1 and detaches from the terminal
// via setsid.
func Daemonize(args []string) (int, error) {
	// Open log file for daemon output
	logFile, err := fileutil.SecureOpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return 0, fmt.Errorf("failed to open log file: %w", err)
	}

	// Prepare command to re-execute self
	executable, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Add daemon flag after the "start" subcommand
	// args[0] should be "start", insert --daemon-mode after it
	daemonArgs := make([]string, 0, len(args)+1)
	if len(args) > 0 {
		daemonArgs = append(daemonArgs, args[0])         // "start"
		daemonArgs = append(daemonArgs, "--daemon-mode") // flag for start subcommand
		daemonArgs = append(daemonArgs, args[1:]...)     // rest of args
	} else {
		daemonArgs = append(daemonArgs, "--daemon-mode")
	}

	// SECURITY: Validate executable path is absolute
	if !filepath.IsAbs(executable) {
		return 0, fmt.Errorf("executable path must be absolute: %s", executable)
	}

	cmd := exec.CommandContext(context.Background(), executable, daemonArgs...) // nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command -- validated absolute path above
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = nil

	// SECURITY: Use restricted environment to prevent injection attacks
	// Only propagate essential environment variables
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
		"CRUST_DAEMON=1",
	}
	// Propagate secret environment variables if set
	if apiKey := os.Getenv("LLM_API_KEY"); apiKey != "" {
		cmd.Env = append(cmd.Env, "LLM_API_KEY="+apiKey)
	}
	if dbKey := os.Getenv("DB_KEY"); dbKey != "" {
		cmd.Env = append(cmd.Env, "DB_KEY="+dbKey)
	}
	// Propagate proxy environment variables (required for upstream connectivity)
	for _, key := range []string{
		"HTTP_PROXY", "http_proxy",
		"HTTPS_PROXY", "https_proxy",
		"NO_PROXY", "no_proxy",
		"ALL_PROXY", "all_proxy",
	} {
		if v := os.Getenv(key); v != "" {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}

	// Start in new session (detach from terminal)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("failed to start daemon: %w", err)
	}

	pid := cmd.Process.Pid

	// Don't wait for the process - it's now a daemon
	_ = cmd.Process.Release()

	return pid, nil
}
