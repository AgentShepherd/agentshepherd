//go:build sandbox_e2e

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// setupBakelensSandboxPath finds the bakelens-sandbox helper binary.
// Returns the path to the helper or skips the test.
func setupBakelensSandboxPath(t testing.TB) string {
	// Find project root by looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Walk up to find project root
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod)")
		}
		dir = parent
	}

	// Check for bakelens-sandbox Rust binary
	helperPath := filepath.Join(dir, "cmd", "bakelens-sandbox", "target", "release", "bakelens-sandbox")
	if _, err := os.Stat(helperPath); err != nil {
		t.Skipf("bakelens-sandbox not found at %s. Build it with: make build-sandbox", helperPath)
	}

	// Override helper path so findBakelensSandbox() finds it
	helperPathOverride = helperPath
	t.Cleanup(func() { helperPathOverride = "" })
	return helperPath
}

// suppressOutput temporarily redirects stdout and stderr to discard.
func suppressOutput() func() {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	devNull, _ := os.Open(os.DevNull)
	os.Stdout = devNull
	os.Stderr = devNull
	return func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		devNull.Close()
	}
}
