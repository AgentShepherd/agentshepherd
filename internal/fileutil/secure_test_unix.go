//go:build !windows

package fileutil

import "testing"

// assertOwnerOnlyWindows is a no-op on Unix — permission checks are in the
// shared assertOwnerOnly function using standard mode bits.
func assertOwnerOnlyWindows(t *testing.T, _ string) {
	t.Helper()
}

// assertHasInheritedACEs is a no-op on Unix — this tests Windows ACL behavior.
func assertHasInheritedACEs(t *testing.T, _ string) {
	t.Helper()
}
