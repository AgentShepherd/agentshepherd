package sandbox

import (
	"strings"
	"testing"
)

func TestWrap_EmptyCommand(t *testing.T) {
	s := New()

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

func TestIsSupported_ReturnsBoolean(t *testing.T) {
	// Should return true or false without panicking
	result := IsSupported()
	t.Logf("IsSupported: %v", result)
}
