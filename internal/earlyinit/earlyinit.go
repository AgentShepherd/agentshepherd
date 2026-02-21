// Package earlyinit runs before charmbracelet/bubbletea's init() to prevent
// terminal escape sequence leaks in --foreground mode.
//
// Problem: bubbletea's init() calls lipgloss.HasDarkBackground() which sends
// OSC 11 (background color query) and DSR (cursor position) escape sequences
// to stdout. On a detached TTY (docker run -d -t), these sequences appear as
// garbage in container logs because no terminal emulator processes them.
//
// Solution: This package only imports "os" (stdlib), so Go initializes it
// before bubbletea (which depends on lipgloss → termenv). When --foreground
// is detected in os.Args, TERM is temporarily set to "dumb", which causes
// termenv's termStatusReport() to bail out without sending any escape
// sequences. The original TERM is saved so the caller can restore the color
// profile for styled log output after bubbletea's init() has completed.
//
// Init order guarantee (Go spec): packages are initialized in dependency
// order; ties are broken by lexicographic package path. Since this package
// has fewer dependencies than bubbletea and "BakeLens" < "charmbracelet",
// this init() runs first.
package earlyinit

import "os"

// Foreground is true when --foreground was detected in os.Args.
var Foreground bool

// OrigTERM holds the original TERM value before earlyinit set it to "dumb".
// Used to restore the color profile for styled log output.
var OrigTERM string

// HasForeground reports whether args contains "--foreground" before any "--".
// Exported for testing; init() calls this with os.Args.
func HasForeground(args []string) bool {
	if len(args) < 2 {
		return false
	}
	for _, arg := range args[1:] {
		if arg == "--foreground" {
			return true
		}
		if arg == "--" {
			return false
		}
	}
	return false
}

func init() {
	Foreground = HasForeground(os.Args)
	if !Foreground {
		return
	}

	// Save original TERM, then set to "dumb" to suppress terminal queries.
	// termenv's termStatusReport() checks strings.HasPrefix(term, "dumb")
	// and returns early without sending OSC escape sequences.
	// The caller restores TERM and the color profile after bubbletea's
	// init() has completed safely.
	OrigTERM = os.Getenv("TERM")
	os.Setenv("TERM", "dumb")
}
