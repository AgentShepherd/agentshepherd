//go:build unix

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- ATTACK SURFACE TESTS (shared across unix: Linux, macOS, FreeBSD) ----

// SECURITY: verifyCurrentUserOwnership must reject world-writable files.
func TestVerifyCurrentUserOwnership_RejectsWorldWritable(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o777); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	if err := os.Chmod(fakeBin, 0o777); err != nil {
		t.Fatalf("chmod fake binary: %v", err)
	}

	if verifyCurrentUserOwnership(fakeBin) {
		t.Error("SECURITY: verifyCurrentUserOwnership must reject world-writable files (mode 0777)")
	}
}

// SECURITY: verifyCurrentUserOwnership must reject group-writable files.
// Another user in the same group could substitute the binary.
func TestVerifyCurrentUserOwnership_RejectsGroupWritable(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o775); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	if err := os.Chmod(fakeBin, 0o775); err != nil {
		t.Fatalf("chmod fake binary: %v", err)
	}

	if verifyCurrentUserOwnership(fakeBin) {
		t.Error("SECURITY: verifyCurrentUserOwnership must reject group-writable files (mode 0775)")
	}
}

// SECURITY: verifyCurrentUserOwnership accepts files owned by current user with safe perms.
func TestVerifyCurrentUserOwnership_AcceptsOwnedFile(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	if !verifyCurrentUserOwnership(fakeBin) {
		t.Error("verifyCurrentUserOwnership should accept a file owned by current user with mode 0755")
	}
}

// SECURITY: verifyCurrentUserOwnership rejects nonexistent paths.
func TestVerifyCurrentUserOwnership_RejectsNonexistent(t *testing.T) {
	if verifyCurrentUserOwnership("/nonexistent/path/bakelens-sandbox") {
		t.Error("verifyCurrentUserOwnership must return false for nonexistent paths")
	}
}

// SECURITY: verifyCurrentUserOwnership rejects symlinks.
func TestVerifyCurrentUserOwnership_RejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realBin := filepath.Join(tmpDir, "real-binary")
	linkBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(realBin, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatalf("create real binary: %v", err)
	}
	if err := os.Symlink(realBin, linkBin); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	if verifyCurrentUserOwnership(linkBin) {
		t.Error("SECURITY: verifyCurrentUserOwnership must reject symlinks")
	}
}

// SECURITY: findBakelensSandbox must NOT search in CWD.
// An agent could place a malicious binary in the working directory.
func TestFindBakelensSandbox_DoesNotSearchCWD(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot get CWD")
	}

	fakeBin := filepath.Join(cwd, helperBinaryName)
	if _, err := os.Stat(fakeBin); os.IsNotExist(err) {
		if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o755); err != nil {
			t.Skipf("cannot create fake binary in CWD: %v", err)
		}
		defer os.Remove(fakeBin)

		found, err := findBakelensSandbox()
		if err == nil && found == fakeBin {
			t.Error("SECURITY: findBakelensSandbox must NOT return a binary found in CWD")
		}
	}
}

// SECURITY: sanitizedEnv must not leak dangerous or secret environment variables.
func TestSanitizedEnv_OnlyAllowlisted(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("SECRET_API_KEY", "hunter2")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s3cr3t")
	t.Setenv("HOME", "/home/testuser")

	env := sanitizedEnv()
	envMap := make(map[string]bool)
	for _, e := range env {
		if key, _, ok := strings.Cut(e, "="); ok {
			envMap[key] = true
		}
	}

	for _, dangerous := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "SECRET_API_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if envMap[dangerous] {
			t.Errorf("SECURITY: sanitizedEnv must not include %s", dangerous)
		}
	}

	if !envMap["HOME"] {
		t.Error("sanitizedEnv should include HOME")
	}
}
