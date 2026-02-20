//go:build windows

package fileutil

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// assertOwnerOnlyWindows verifies the DACL has exactly one ACE granting
// access to the current user, with no other principals allowed.
func assertOwnerOnlyWindows(t *testing.T, path string) {
	t.Helper()

	// Get the current user's SID.
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	ownerSID := user.User.Sid

	// Read the file's DACL.
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(): %v", err)
	}
	if dacl == nil {
		t.Fatalf("DACL is nil (NULL DACL = full access to everyone)")
	}

	// The DACL should have exactly 1 ACE: ALLOW for the current user.
	aceCount := int(dacl.AceCount)
	if aceCount == 0 {
		t.Fatal("DACL has 0 ACEs (empty DACL = deny all)")
	}

	foundOwner := false
	for i := range aceCount {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatalf("GetAce(%d): %v", i, err)
		}

		// The SID starts at the SidStart field of ACCESS_ALLOWED_ACE.
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(ownerSID) {
			foundOwner = true
			continue
		}

		// Any ACE for a principal other than the owner is a security issue.
		sidStr := aceSID.String()
		t.Errorf("unexpected ACE for SID %s (only owner should have access)", sidStr)
	}

	if !foundOwner {
		t.Error("no ACE found for current user")
	}
}

// assertHasInheritedACEs verifies that a file has more than one ACE,
// proving that os.WriteFile with 0600 does NOT restrict access on Windows.
func assertHasInheritedACEs(t *testing.T, path string) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL(): %v", err)
	}
	if dacl == nil {
		t.Fatal("DACL is nil")
	}

	aceCount := int(dacl.AceCount)
	if aceCount <= 1 {
		t.Fatalf("expected >1 ACEs from inherited DACL, got %d (os.WriteFile 0600 unexpectedly restricted access)", aceCount)
	}
	t.Logf("os.WriteFile 0600 produced %d ACEs (inherited, not restricted) — confirms the bug", aceCount)
}
