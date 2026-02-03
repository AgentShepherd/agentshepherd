//go:build darwin

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
)

// execute runs the command inside sandbox-exec on macOS.
func (s *Sandbox) execute(profilePath string, command []string) (int, error) {
	if err := checkSandboxExec(); err != nil {
		return 0, err
	}

	// sandbox-exec -f <profile> <command> <args...>
	args := []string{"-f", profilePath}
	args = append(args, command...)

	cmd := exec.Command("sandbox-exec", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("sandbox-exec failed: %w", err)
	}
	return 0, nil
}

// checkSandboxExec verifies sandbox-exec is available.
func checkSandboxExec() error {
	_, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return fmt.Errorf("sandbox-exec not found (should be available on all macOS systems): %w", err)
	}
	return nil
}

// isLandlockSupported returns false on macOS (uses sandbox-exec instead).
func isLandlockSupported() bool {
	return false
}

// detectLandlockABI returns 0 on macOS (not applicable).
func detectLandlockABI() int {
	return 0
}
