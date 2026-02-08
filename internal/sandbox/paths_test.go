package sandbox

import (
	"os"
	"testing"
)

func TestDefaultAllowPaths(t *testing.T) {
	paths := DefaultAllowPaths()

	if len(paths) < 12 {
		t.Errorf("DefaultAllowPaths() returned %d paths, expected at least 12", len(paths))
	}

	// Check required system paths
	required := []string{"/bin", "/usr", "/lib", "/lib64", "/tmp", "/var", "/dev", "/etc", "/sys", "/run", "/opt", "/sbin"}
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	for _, r := range required {
		if !pathSet[r] {
			t.Errorf("DefaultAllowPaths() missing required path %q", r)
		}
	}
}

func TestDefaultAllowPaths_IncludesHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	paths := DefaultAllowPaths()
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	if !pathSet[home] {
		t.Errorf("DefaultAllowPaths() should include $HOME (%s)", home)
	}
}

func TestDefaultAllowPaths_IncludesCwd(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil || cwd == "" {
		t.Skip("no working directory available")
	}

	paths := DefaultAllowPaths()
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	if !pathSet[cwd] {
		t.Errorf("DefaultAllowPaths() should include $CWD (%s)", cwd)
	}
}

func TestDefaultAllowPaths_ExcludesProc(t *testing.T) {
	paths := DefaultAllowPaths()
	for _, p := range paths {
		if p == "/proc" {
			t.Error("DefaultAllowPaths() should NOT include /proc")
		}
	}
}
