package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pidFileName = "crust.pid"
	logFileName = "crust.log"
)

// DataDir returns the crust data directory and creates it if needed
func DataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp" // Fallback if home dir unavailable
	}
	dir := filepath.Join(home, ".crust")
	_ = os.MkdirAll(dir, 0700) //nolint:errcheck // best effort - dir may exist
	return dir
}

// pidFile returns the path to the PID file
func pidFile() string {
	return filepath.Join(DataDir(), pidFileName)
}

// LogFile returns the path to the log file
func LogFile() string {
	return filepath.Join(DataDir(), logFileName)
}

// pidLockFile holds the open PID file to maintain the flock advisory lock.
// The lock is held for the lifetime of the daemon process.
var pidLockFile *os.File

// WritePID writes the current process ID to the PID file with an exclusive
// advisory lock (flock). The lock prevents two daemon instances from running
// simultaneously. The returned file handle must remain open to hold the lock;
// call CleanupPID on shutdown.
func WritePID() error {
	path := pidFile()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open PID file: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
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

// CleanupPID releases the flock and removes the PID file.
func CleanupPID() {
	if pidLockFile != nil {
		pidLockFile.Close()
		pidLockFile = nil
	}
	_ = os.Remove(pidFile())
}

// ReadPID reads the PID from the PID file
func ReadPID() (int, error) {
	data, err := os.ReadFile(pidFile())
	if err != nil {
		return 0, err
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("invalid PID file content: %w", err)
	}

	// SECURITY: Validate PID is in valid range (1 to max PID)
	// Linux max PID is typically 4194304 (2^22), but 32768 is default
	if pid < 1 || pid > 4194304 {
		return 0, fmt.Errorf("invalid PID value: %d", pid)
	}

	return pid, nil
}

// RemovePID removes the PID file
func RemovePID() error {
	return os.Remove(pidFile())
}

// IsRunning checks if the daemon is running
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

// Stop stops the running daemon
func Stop() error {
	running, pid := IsRunning()
	if !running {
		return fmt.Errorf("crust is not running")
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
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if running, _ := IsRunning(); !running {
			return nil
		}
	}

	// Force kill if still running
	_ = process.Signal(syscall.SIGKILL) //nolint:errcheck // best effort
	_ = RemovePID()                     //nolint:errcheck // cleanup best effort

	return nil
}

// Daemonize starts the current program as a daemon
// It re-executes the program with special environment variable to indicate daemon mode
func Daemonize(args []string) (int, error) {
	// Open log file for daemon output
	logFile, err := os.OpenFile(LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
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

	cmd := exec.Command(executable, daemonArgs...)
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

// IsDaemonMode checks if we're running in daemon mode
func IsDaemonMode() bool {
	return os.Getenv("CRUST_DAEMON") == "1"
}
