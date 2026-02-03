//go:build linux

package sandbox

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// PersistentSandbox wraps commands using a long-running helper process.
// The helper applies Landlock once at startup, then accepts commands via pipe.
// This reduces per-command overhead from ~500µs to ~150µs.
type PersistentSandbox struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
	closed bool
}

// persistentExecPaths lists possible locations for the sandbox helper.
var persistentExecPaths = []string{
	"/usr/libexec/agentshepherd/sandbox-exec",
	"/usr/local/libexec/agentshepherd/sandbox-exec",
	"./sandbox-exec",
	"./cmd/sandbox-exec/sandbox-exec",
}

// findPersistentExec locates the sandbox-exec helper binary.
func findPersistentExec() (string, error) {
	// Check env var first (supports both old and new names)
	if path := os.Getenv("SANDBOX_EXEC_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	if path := os.Getenv("SANDBOX_EXEC_PERSISTENT_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Check relative to executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, "sandbox-exec"),
			filepath.Join(dir, "..", "libexec", "agentshepherd", "sandbox-exec"),
		}
		for _, path := range candidates {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}

	// Check standard paths
	for _, path := range persistentExecPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("sandbox-exec helper not found; build with 'make -C cmd/sandbox-exec'")
}

// NewPersistentSandbox creates a new persistent sandbox helper.
// The helper applies Landlock and waits for commands.
func NewPersistentSandbox(allowPaths []string) (*PersistentSandbox, error) {
	helperPath, err := findPersistentExec()
	if err != nil {
		return nil, err
	}

	// Build environment
	env := os.Environ()
	if len(allowPaths) > 0 {
		env = append(env, "LANDLOCK_PATHS="+strings.Join(allowPaths, ":"))
	}
	abi := detectLandlockABI()
	env = append(env, fmt.Sprintf("LANDLOCK_ABI=%d", abi))

	// Start helper
	cmd := exec.Command(helperPath)
	cmd.Env = env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("start helper: %w", err)
	}

	reader := bufio.NewReader(stdout)

	// Wait for READY signal
	line, err := reader.ReadString('\n')
	if err != nil {
		stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("waiting for READY: %w", err)
	}

	if strings.TrimSpace(line) != "READY" {
		stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("unexpected response: %s", line)
	}

	return &PersistentSandbox{
		cmd:    cmd,
		stdin:  stdin,
		stdout: reader,
	}, nil
}

// Exec runs a command in the sandbox and returns the exit code.
func (p *PersistentSandbox) Exec(args []string) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return 0, fmt.Errorf("sandbox closed")
	}

	// Build argument data: arg0\0arg1\0...argN\0
	var totalSize int
	for _, arg := range args {
		totalSize += len(arg) + 1
	}

	// Write protocol: nargs\ntotal_size\ndata
	if _, err := fmt.Fprintf(p.stdin, "%d\n%d\n", len(args), totalSize); err != nil {
		return 0, fmt.Errorf("write header: %w", err)
	}

	for _, arg := range args {
		if _, err := p.stdin.Write([]byte(arg)); err != nil {
			return 0, fmt.Errorf("write arg: %w", err)
		}
		if _, err := p.stdin.Write([]byte{0}); err != nil {
			return 0, fmt.Errorf("write null: %w", err)
		}
	}

	// Read response: EXIT <code>\n
	line, err := p.stdout.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read response: %w", err)
	}

	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "EXIT ") {
		return 0, fmt.Errorf("unexpected response: %s", line)
	}

	code, err := strconv.Atoi(strings.TrimPrefix(line, "EXIT "))
	if err != nil {
		return 0, fmt.Errorf("parse exit code: %w", err)
	}

	return code, nil
}

// Close shuts down the persistent helper.
func (p *PersistentSandbox) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	// Close stdin to signal EOF
	p.stdin.Close()

	// Wait for process to exit
	return p.cmd.Wait()
}
