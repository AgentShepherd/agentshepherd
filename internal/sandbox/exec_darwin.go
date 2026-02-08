//go:build darwin

package sandbox

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// darwinPolicyJSON is the JSON structure for macOS (Seatbelt).
// Must match the Rust Policy struct in policy.rs.
type darwinPolicyJSON struct {
	Version         int      `json:"version"`
	SeatbeltProfile *string  `json:"seatbelt_profile,omitempty"`
	Command         []string `json:"command"`
}

// execute runs the command inside a sandbox on macOS using bakelens-sandbox.
// The Seatbelt profile is embedded in the JSON policy sent on stdin.
func (s *Sandbox) execute(command []string) (int, error) {
	bakelensPath, err := findBakelensSandbox()
	if err != nil {
		return 0, err
	}

	// Generate profile content in memory and embed it in the JSON policy.
	profileContent := s.mapper.GenerateProfileContent()
	if profileContent == "" {
		return 0, fmt.Errorf("empty seatbelt profile")
	}

	policy := darwinPolicyJSON{
		Version:         1,
		SeatbeltProfile: &profileContent,
		Command:         command,
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return 0, fmt.Errorf("marshal policy: %w", err)
	}

	cmd := exec.Command(bakelensPath) //nolint:gosec // trusted path from findBakelensSandbox
	cmd.Stdin = bytes.NewReader(policyJSON)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = sanitizedEnv()

	err = cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("bakelens-sandbox failed: %w", err)
	}
	return 0, nil
}

// findBakelensSandbox searches for the bakelens-sandbox binary on macOS.
// Uses the same trusted path strategy as Linux: user-local → system → relative to binary.
func findBakelensSandbox() (string, error) {
	const binaryName = "bakelens-sandbox"

	// User-local
	if home, err := os.UserHomeDir(); err == nil {
		userPath := filepath.Join(home, ".local", "libexec", "crust", binaryName)
		if fi, err := os.Lstat(userPath); err == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode()&0002 == 0 {
			return userPath, nil
		}
	}

	// System paths
	systemPaths := []string{
		"/usr/local/libexec/crust/" + binaryName,
		"/usr/libexec/crust/" + binaryName,
	}
	for _, path := range systemPaths {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
	}

	// Relative to executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, binaryName),
			filepath.Join(dir, "..", "libexec", "crust", binaryName),
		}
		for _, path := range candidates {
			if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink == 0 && fi.Mode()&0002 == 0 {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("bakelens-sandbox not found; install to ~/.local/libexec/crust/")
}

// isLandlockSupported returns false on macOS (uses Seatbelt instead).
func isLandlockSupported() bool {
	return false
}

// detectLandlockABI returns 0 on macOS (not applicable).
func detectLandlockABI() int {
	return 0
}
