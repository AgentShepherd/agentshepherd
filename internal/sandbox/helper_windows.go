//go:build windows

package sandbox

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// helperBinaryName is the sandbox helper binary name on Windows.
const helperBinaryName = "bakelens-sandbox.exe"

// findBakelensSandbox locates the bakelens-sandbox binary on Windows.
// Search order: user-local (%LOCALAPPDATA%\Crust\) → relative to crust executable.
// System-wide paths are NOT searched — crust is installed per-user.
func findBakelensSandbox() (string, error) {
	if helperPathOverride != "" {
		return helperPathOverride, nil
	}

	// Check user-local path (%LOCALAPPDATA%\Crust\bakelens-sandbox.exe)
	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		userPath := filepath.Join(localAppData, "Crust", helperBinaryName)
		if verifyCurrentUserOwnership(userPath) {
			return userPath, nil
		}
	}

	// Fallback: check relative to crust executable (same dir or ..\libexec\crust\)
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

	return "", errors.New(`bakelens-sandbox.exe not found; install to %LOCALAPPDATA%\Crust\`)
}

// verifyCurrentUserOwnership checks that the helper binary exists, is a regular file,
// is not a reparse point (symlink/junction), and is owned by the current user.
func verifyCurrentUserOwnership(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	// Reject reparse points (symlinks/junctions)
	if fi.Mode()&os.ModeSymlink != 0 {
		return false
	}
	// Must be a regular file
	if !fi.Mode().IsRegular() {
		return false
	}
	// Verify the file owner SID matches the current user SID
	return fileOwnedByCurrentUser(path)
}

// fileOwnedByCurrentUser checks that the file's owner SID matches the current
// process token's user SID. This prevents binary substitution by other users.
func fileOwnedByCurrentUser(path string) bool {
	// Get the file's security descriptor with owner information
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return false
	}

	// Extract owner SID from security descriptor
	ownerSID, _, err := sd.Owner()
	if err != nil || ownerSID == nil {
		return false
	}

	// Get the current process token's user SID
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return false
	}

	return windows.EqualSid(ownerSID, tokenUser.User.Sid)
}
