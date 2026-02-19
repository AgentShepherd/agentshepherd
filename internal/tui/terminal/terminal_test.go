package terminal

import (
	"testing"
)

// mockEnv builds an EnvFunc from a map of key-value pairs.
func mockEnv(env map[string]string) EnvFunc {
	return func(key string) string {
		return env[key]
	}
}

func TestDetectWith_FullCaps(t *testing.T) {
	// Terminals detected via specific env vars that support all capabilities.
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"WT_SESSION", map[string]string{"WT_SESSION": "guid"}},
		{"KITTY_WINDOW_ID", map[string]string{"KITTY_WINDOW_ID": "1"}},
		{"ALACRITTY_LOG", map[string]string{"ALACRITTY_LOG": "/tmp/log"}},
		{"WEZTERM_EXECUTABLE", map[string]string{"WEZTERM_EXECUTABLE": "/usr/bin/wezterm"}},
		{"TILIX_ID", map[string]string{"TILIX_ID": "id"}},
		{"GNOME_TERMINAL_SCREEN", map[string]string{"GNOME_TERMINAL_SCREEN": "/org/gnome"}},
		{"TERM_PROGRAM_vscode", map[string]string{"TERM_PROGRAM": "vscode"}},
		{"TERM_PROGRAM_iTerm", map[string]string{"TERM_PROGRAM": "iTerm.app"}},
		{"TERM_foot", map[string]string{"TERM": "foot"}},
		{"TERM_foot_extra", map[string]string{"TERM": "foot-extra"}},
		{"VTE_VERSION_only", map[string]string{"VTE_VERSION": "7200"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := DetectWith(mockEnv(tt.env))
			if info.Caps != CapAll {
				t.Errorf("Caps = %d, want CapAll (%d)", info.Caps, CapAll)
			}
		})
	}
}

func TestDetectWith_ReducedCaps(t *testing.T) {
	// KONSOLE_VERSION: all caps except hyperlinks
	info := DetectWith(mockEnv(map[string]string{"KONSOLE_VERSION": "220401"}))
	if info.Caps.Has(CapHyperlinks) {
		t.Error("KONSOLE_VERSION should not have CapHyperlinks")
	}
	if !info.Caps.Has(CapTruecolor) {
		t.Error("KONSOLE_VERSION should have CapTruecolor")
	}
	if !info.Caps.Has(CapItalic | CapFaint | CapStrikethrough | CapWindowTitle) {
		t.Error("KONSOLE_VERSION should have italic, faint, strikethrough, window title")
	}

	// Apple_Terminal: no truecolor, no hyperlinks, no strikethrough
	info = DetectWith(mockEnv(map[string]string{"TERM_PROGRAM": "Apple_Terminal"}))
	if info.Caps.Has(CapTruecolor) {
		t.Error("Apple_Terminal should not have CapTruecolor")
	}
	if info.Caps.Has(CapHyperlinks) {
		t.Error("Apple_Terminal should not have CapHyperlinks")
	}
	if info.Caps.Has(CapStrikethrough) {
		t.Error("Apple_Terminal should not have CapStrikethrough")
	}
	if !info.Caps.Has(CapItalic | CapFaint | CapWindowTitle) {
		t.Error("Apple_Terminal should have italic, faint, window title")
	}
}

func TestDetectWith_Unknown(t *testing.T) {
	info := DetectWith(mockEnv(map[string]string{}))
	if info.Caps != CapNone {
		t.Errorf("Caps = %d, want CapNone", info.Caps)
	}
	if info.Multiplexed {
		t.Error("Multiplexed should be false for empty env")
	}
}

func TestDetectWith_UnknownColorterm(t *testing.T) {
	tests := []struct {
		name      string
		colorterm string
	}{
		{"truecolor", "truecolor"},
		{"24bit", "24bit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := DetectWith(mockEnv(map[string]string{"COLORTERM": tt.colorterm}))
			if !info.Caps.Has(CapTruecolor) {
				t.Error("COLORTERM should grant CapTruecolor")
			}
			if info.Caps.Has(CapHyperlinks) {
				t.Error("COLORTERM alone should not grant CapHyperlinks")
			}
		})
	}
}

func TestDetectWith_Priority(t *testing.T) {
	// When multiple env vars are set, more-specific ones win.
	// We verify by checking the expected capability set.
	tests := []struct {
		name     string
		env      map[string]string
		wantCaps Capability
	}{
		{
			"KITTY_WINDOW_ID over TERM_PROGRAM",
			map[string]string{"KITTY_WINDOW_ID": "1", "TERM_PROGRAM": "iTerm.app"},
			CapAll,
		},
		{
			"WT_SESSION over ALACRITTY_LOG",
			map[string]string{"WT_SESSION": "guid", "ALACRITTY_LOG": "/tmp/log"},
			CapAll,
		},
		{
			"ALACRITTY_LOG over TERM_PROGRAM",
			map[string]string{"ALACRITTY_LOG": "/tmp/log", "TERM_PROGRAM": "vscode"},
			CapAll,
		},
		{
			"TILIX_ID over GNOME_TERMINAL_SCREEN",
			map[string]string{"TILIX_ID": "id", "GNOME_TERMINAL_SCREEN": "/org/gnome"},
			CapAll,
		},
		{
			"KONSOLE_VERSION over TERM_PROGRAM",
			map[string]string{"KONSOLE_VERSION": "220401", "TERM_PROGRAM": "iTerm.app"},
			capsNoLinks, // Konsole caps, not iTerm caps
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := DetectWith(mockEnv(tt.env))
			if info.Caps != tt.wantCaps {
				t.Errorf("Caps = %d, want %d", info.Caps, tt.wantCaps)
			}
		})
	}
}

func TestDetectWith_Multiplexed(t *testing.T) {
	info := DetectWith(mockEnv(map[string]string{
		"TMUX":            "/tmp/tmux-1000/default,12345,0",
		"KITTY_WINDOW_ID": "1",
	}))
	if !info.Multiplexed {
		t.Error("Multiplexed should be true when TMUX is set")
	}
	if !info.Caps.Has(CapAll) {
		t.Error("caps should be CapAll even when multiplexed")
	}
}

func TestDetectWith_Screen(t *testing.T) {
	info := DetectWith(mockEnv(map[string]string{
		"STY":          "12345.pts-0.host",
		"TERM_PROGRAM": "iTerm.app",
	}))
	if !info.Multiplexed {
		t.Error("Multiplexed should be true when STY is set")
	}
	if info.Caps != CapAll {
		t.Errorf("Caps = %d, want CapAll", info.Caps)
	}
}

func TestDetectWith_VTEFallback(t *testing.T) {
	// VTE_VERSION alone (no specific env var) → CapAll
	info := DetectWith(mockEnv(map[string]string{"VTE_VERSION": "7200"}))
	if !info.Caps.Has(CapAll) {
		t.Error("VTE_VERSION should have CapAll")
	}
}

func TestDetectWith_VTENotTilix(t *testing.T) {
	// VTE_VERSION + TILIX_ID → TILIX_ID wins (checked before VTE fallback)
	info := DetectWith(mockEnv(map[string]string{
		"VTE_VERSION": "7200",
		"TILIX_ID":    "some-id",
	}))
	if info.Caps != CapAll {
		t.Errorf("Caps = %d, want CapAll", info.Caps)
	}
}

// --- Capability bitfield tests ---

func TestCapability_Has(t *testing.T) {
	tests := []struct {
		name   string
		caps   Capability
		query  Capability
		expect bool
	}{
		{"CapAll has Truecolor", CapAll, CapTruecolor, true},
		{"CapAll has Hyperlinks", CapAll, CapHyperlinks, true},
		{"CapAll has all", CapAll, CapAll, true},
		{"CapNone has nothing", CapNone, CapTruecolor, false},
		{"CapNone has CapNone", CapNone, CapNone, true},
		{"Single has itself", CapTruecolor, CapTruecolor, true},
		{"Single lacks other", CapTruecolor, CapHyperlinks, false},
		{"Partial lacks combined", CapTruecolor, CapTruecolor | CapHyperlinks, false},
		{"Combined has both", CapTruecolor | CapHyperlinks, CapTruecolor | CapHyperlinks, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caps.Has(tt.query); got != tt.expect {
				t.Errorf("Capability(%d).Has(%d) = %v, want %v", tt.caps, tt.query, got, tt.expect)
			}
		})
	}
}

func TestCapability_WithWithout(t *testing.T) {
	// With adds capability
	c := CapNone.With(CapTruecolor)
	if !c.Has(CapTruecolor) {
		t.Error("With(CapTruecolor) should add CapTruecolor")
	}

	// With is additive
	c = c.With(CapHyperlinks)
	if !c.Has(CapTruecolor) || !c.Has(CapHyperlinks) {
		t.Error("With should be additive")
	}

	// Without removes capability
	c = c.Without(CapTruecolor)
	if c.Has(CapTruecolor) {
		t.Error("Without(CapTruecolor) should remove CapTruecolor")
	}
	if !c.Has(CapHyperlinks) {
		t.Error("Without should not affect other caps")
	}

	// Without on absent cap is no-op
	c = CapNone.Without(CapTruecolor)
	if c != CapNone {
		t.Error("Without on CapNone should return CapNone")
	}

	// CapAll.Without removes
	c = CapAll.Without(CapHyperlinks)
	if c.Has(CapHyperlinks) {
		t.Error("CapAll.Without(CapHyperlinks) should remove hyperlinks")
	}
	if !c.Has(CapTruecolor) || !c.Has(CapItalic) {
		t.Error("CapAll.Without should preserve other caps")
	}
}

// --- Caching test ---

func TestDetect_Caching(t *testing.T) {
	a := Detect()
	b := Detect()
	if a.Caps != b.Caps {
		t.Errorf("Detect() returned different Caps: %d vs %d", a.Caps, b.Caps)
	}
	if a.Multiplexed != b.Multiplexed {
		t.Errorf("Detect() returned different Multiplexed: %v vs %v", a.Multiplexed, b.Multiplexed)
	}
}
