//go:build windows

package fileutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// SecureWriteFile writes data to a file and restricts access to the current
// user via a Windows DACL. This is the Windows equivalent of Unix chmod 0600.
// If the DACL cannot be applied, the file is removed to avoid leaving a
// permissive file on disk.
func SecureWriteFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	if err := restrictToOwner(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// SecureMkdirAll creates a directory tree and restricts the leaf directory
// to the current user via a Windows DACL. Equivalent of Unix chmod 0700.
func SecureMkdirAll(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return restrictToOwner(path)
}

// SecureOpenFile opens a file for writing and restricts access to the current
// user via a Windows DACL. Equivalent of Unix chmod 0600.
func SecureOpenFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag, 0600)
	if err != nil {
		return nil, err
	}
	if err := restrictToOwner(path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// restrictToOwner sets a protected DACL on the given path that grants
// GENERIC_ALL only to the current user. All inherited and other ACEs are
// removed (PROTECTED_DACL prevents inheritance from parent directories).
func restrictToOwner(path string) error {
	// Get the current user's SID from the process token.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open process token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("get token user: %w", err)
	}

	// Build an explicit access entry: current user gets full control.
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}

	// Create ACL with only this entry (no inherited ACEs).
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{ea}, nil)
	if err != nil {
		return fmt.Errorf("build ACL: %w", err)
	}

	// Apply the DACL. PROTECTED_DACL_SECURITY_INFORMATION prevents the
	// parent directory's DACL from being inherited onto this object.
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, // owner (unchanged)
		nil, // group (unchanged)
		acl,
		nil, // sacl (unchanged)
	)
}
