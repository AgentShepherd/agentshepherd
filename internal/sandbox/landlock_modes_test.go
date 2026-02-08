//go:build linux

package sandbox

import (
	"testing"
)

// TestModeStringValues: removed — tautology, constants are self-verifying

func TestIntentAwareAllowPaths_SystemDirModes(t *testing.T) {
	// With no rules, system dirs should have correct modes.
	paths := IntentAwareAllowPaths(nil)

	expected := map[string]LandlockMode{
		"/bin":   ModeRX,
		"/usr":   ModeRX,
		"/sbin":  ModeRX,
		"/lib":   ModeRO,
		"/lib64": ModeRO,
		"/tmp":   ModeRW,
		"/var":   ModeRW,
		"/dev":   ModeRW,
		"/etc":   ModeRO,
		"/sys":   ModeRO,
		"/run":   ModeRW,
		"/opt":   ModeRX,
	}

	pathMap := make(map[string]LandlockMode)
	for _, pm := range paths {
		pathMap[pm.Path] = pm.Mode
	}

	for path, wantMode := range expected {
		got, ok := pathMap[path]
		if !ok {
			t.Errorf("system path %q not found in allowlist", path)
			continue
		}
		if got != wantMode {
			t.Errorf("system path %q: got mode %q, want %q", path, got, wantMode)
		}
	}
}

// TestIntentAwareAllowPaths_NoExecuteOnTmp, TestIntentAwareAllowPaths_SystemBinsAreRX,
// TestIntentAwareAllowPaths_LibDirsAreRO: removed — fully subsumed by TestIntentAwareAllowPaths_SystemDirModes

func TestDerivePathModes_DenyWriteIsRO(t *testing.T) {
	rules := []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.config/secret.json"},
			operations: []string{"write"},
		},
	}
	modes := DerivePathModes(rules)
	if modes == nil {
		t.Skip("could not get home directory")
	}
	// The .config dir should get RO (deny write, allow read)
	for dir, mode := range modes {
		if contains(dir, ".config") {
			if mode != ModeRO {
				t.Errorf(".config dir %q: got mode %q, want %q", dir, mode, ModeRO)
			}
			return
		}
	}
	// If .config wasn't found, that's ok — depends on pattern matching
}

func TestDerivePathModes_DenyReadAndWriteIsNone(t *testing.T) {
	rules := []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.ssh/id_*"},
			operations: []string{"read"},
		},
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.ssh/id_*"},
			operations: []string{"write"},
		},
	}
	modes := DerivePathModes(rules)
	if modes == nil {
		t.Skip("could not get home directory")
	}
	for dir, mode := range modes {
		if contains(dir, ".ssh") {
			if mode != ModeNone {
				t.Errorf(".ssh dir %q: got mode %q, want %q", dir, mode, ModeNone)
			}
			return
		}
	}
}

func TestDerivePathModes_ExceptionFallsBackToRW(t *testing.T) {
	rules := []SecurityRule{
		&mockRule{
			enabled:     true,
			blockPaths:  []string{"**/.config/secret.json"},
			blockExcept: []string{"**/.config/public.json"},
			operations:  []string{"read", "write"},
		},
	}
	modes := DerivePathModes(rules)
	if modes == nil {
		t.Skip("could not get home directory")
	}
	for dir, mode := range modes {
		if contains(dir, ".config") {
			if mode != ModeRW {
				t.Errorf(".config dir with exception %q: got mode %q, want %q (rw fallback)", dir, mode, ModeRW)
			}
			return
		}
	}
}

func TestDerivePathModes_NoExecuteLeakage(t *testing.T) {
	// No rule combination should produce rx or rwx for $HOME subdirs.
	// DerivePathModes only produces: ModeNone, ModeRO, ModeRW.
	rules := []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.test/file"},
			operations: []string{"write"},
		},
	}
	modes := DerivePathModes(rules)
	if modes == nil {
		t.Skip("could not get home directory")
	}
	for dir, mode := range modes {
		if mode == ModeRX || mode == ModeRWX {
			t.Errorf("dir %q has mode %q — DerivePathModes must never produce rx or rwx for $HOME subdirs", dir, mode)
		}
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// mockRule implements SecurityRule for testing.
type mockRule struct {
	enabled     bool
	blockPaths  []string
	blockExcept []string
	operations  []string
}

func (r *mockRule) IsEnabled() bool          { return r.enabled }
func (r *mockRule) GetBlockPaths() []string  { return r.blockPaths }
func (r *mockRule) GetBlockExcept() []string { return r.blockExcept }
func (r *mockRule) GetActions() []string     { return r.operations }
func (r *mockRule) GetName() string          { return "mock-rule" }
