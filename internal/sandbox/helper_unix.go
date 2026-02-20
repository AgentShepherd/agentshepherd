//go:build unix

package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// helperBinaryName is the sandbox helper binary name.
const helperBinaryName = "bakelens-sandbox"

// findBakelensSandbox locates the bakelens-sandbox binary.
// Search order: user-local (~/.local/libexec/crust/) → relative to crust executable.
// System-wide paths are NOT searched — crust is installed per-user.
func findBakelensSandbox() (string, error) {
	if helperPathOverride != "" {
		return helperPathOverride, nil
	}

	// Check user-local path (~/.local/libexec/crust/bakelens-sandbox)
	if home, err := os.UserHomeDir(); err == nil {
		userPath := filepath.Join(home, ".local", "libexec", "crust", helperBinaryName)
		if verifyCurrentUserOwnership(userPath) {
			return userPath, nil
		}
	}

	// Fallback: check relative to crust executable (same dir or ../libexec/crust/)
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, helperBinaryName),
			filepath.Join(dir, "..", "libexec", "crust", helperBinaryName),
		}
		for _, path := range candidates {
			if verifyCurrentUserOwnership(path) {
				return path, nil
			}
		}
	}

	return "", errors.New("bakelens-sandbox not found; install to ~/.local/libexec/crust/")
}

// verifyCurrentUserOwnership checks that the helper binary exists, is owned by
// the current user, and is not world-writable or group-writable.
func verifyCurrentUserOwnership(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	// Reject symlinks to prevent TOCTOU attacks
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := os.Getuid()
	if uid < 0 || stat.Uid != uint32(uid) { //nolint:gosec // uid is non-negative on Unix
		return false
	}
	// Reject world-writable or group-writable (another user in the group could substitute)
	if fi.Mode()&0022 != 0 {
		return false
	}
	// Must be a regular file (not a device, socket, etc.)
	if !fi.Mode().IsRegular() {
		return false
	}
	return true
}
