package terminal

import (
	"os"
	"strings"
	"sync"
)

// Capability is a bitfield representing terminal features.
type Capability uint16

const (
	CapTruecolor     Capability = 1 << iota // 24-bit color
	CapHyperlinks                           // OSC 8 clickable links
	CapItalic                               // ANSI italic attribute
	CapFaint                                // ANSI faint/dim attribute
	CapStrikethrough                        // ANSI strikethrough attribute
	CapWindowTitle                          // OSC 0/2 title setting
)

// Composite capability sets.
const (
	CapNone Capability = 0
	CapAll  Capability = CapTruecolor | CapHyperlinks | CapItalic |
		CapFaint | CapStrikethrough | CapWindowTitle
)

// Has reports whether the capability set includes all bits in v.
func (c Capability) Has(v Capability) bool {
	return c&v == v
}

// With returns the set with v added.
func (c Capability) With(v Capability) Capability {
	return c | v
}

// Without returns the set with v removed.
func (c Capability) Without(v Capability) Capability {
	return c &^ v
}

// Info holds detected terminal capabilities.
type Info struct {
	Caps        Capability // detected feature set
	Multiplexed bool       // true if running inside tmux/screen
}

// EnvFunc is the signature for environment variable lookup (matches os.Getenv).
type EnvFunc func(string) string

var (
	cachedInfo Info
	detectOnce sync.Once
)

// Detect identifies terminal capabilities from os.Getenv.
// Result is cached after first call.
func Detect() Info {
	detectOnce.Do(func() {
		cachedInfo = DetectWith(os.Getenv)
	})
	return cachedInfo
}

// Capability profiles for terminals with reduced feature sets.
// Terminals not listed here get CapAll.
var (
	// 256-color only, no OSC 8 hyperlinks, no strikethrough
	capsLimited = CapItalic | CapFaint | CapWindowTitle
	// All features except hyperlinks (disabled by default)
	capsNoLinks = CapAll.Without(CapHyperlinks)
)

// DetectWith identifies terminal capabilities using a custom env lookup.
// Not cached — used for testing.
func DetectWith(getenv EnvFunc) Info {
	info := Info{}

	// Multiplexer detection
	if getenv("TMUX") != "" || getenv("STY") != "" {
		info.Multiplexed = true
	}

	// Map environment variables to capabilities.
	// Order: most-specific env vars first to avoid false matches.
	switch {
	case getenv("WT_SESSION") != "":
		info.Caps = CapAll
	case getenv("KITTY_WINDOW_ID") != "":
		info.Caps = CapAll
	case getenv("ALACRITTY_LOG") != "":
		info.Caps = CapAll
	case getenv("WEZTERM_EXECUTABLE") != "":
		info.Caps = CapAll
	case getenv("TILIX_ID") != "":
		info.Caps = CapAll
	case getenv("KONSOLE_VERSION") != "":
		info.Caps = capsNoLinks
	case getenv("GNOME_TERMINAL_SCREEN") != "":
		info.Caps = CapAll
	default:
		switch getenv("TERM_PROGRAM") {
		case "vscode":
			info.Caps = CapAll
		case "iTerm.app":
			info.Caps = CapAll
		case "Apple_Terminal":
			info.Caps = capsLimited
		default:
			term := getenv("TERM")
			switch {
			case term == "foot" || strings.HasPrefix(term, "foot-"):
				info.Caps = CapAll
			default:
				// VTE-based terminals (GNOME Terminal variants)
				if getenv("VTE_VERSION") != "" {
					info.Caps = CapAll
				}
			}
		}
	}

	// Unrecognized terminal: check COLORTERM for truecolor
	if info.Caps == CapNone {
		ct := getenv("COLORTERM")
		if ct == "truecolor" || ct == "24bit" {
			info.Caps = info.Caps.With(CapTruecolor)
		}
	}

	return info
}
