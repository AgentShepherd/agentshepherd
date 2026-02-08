//go:build linux

package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWrap_EmptyCommand(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)
	s := New(mapper)

	code, err := s.Wrap([]string{})
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(err.Error(), "no command specified") {
		t.Errorf("expected 'no command specified' error, got: %v", err)
	}
}

func TestIsHelperInstalled_ReturnsBoolean(t *testing.T) {
	// Should return true or false without panicking
	result := IsHelperInstalled()
	t.Logf("IsHelperInstalled: %v", result)
}

func TestSandboxMapper(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)
	s := New(mapper)

	if s.mapper != mapper {
		t.Error("sandbox mapper should be the mapper passed to New")
	}
}
