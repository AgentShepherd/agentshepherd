// Package earlyinit runs before lipgloss's first render to prevent terminal
// escape sequence leaks in --foreground mode without a real TTY.
//
// Problem: lipgloss lazily calls HasDarkBackground() on first styled render,
// which sends OSC 11 (background color query) via termenv. Without a real TTY
// (e.g., docker run -d), these sequences appear as garbage in container logs
// because no terminal emulator processes them.
//
// Solution: When --foreground is detected and stdout is NOT a terminal, TERM
// is set to "dumb" before any rendering occurs. This causes termenv's
// termStatusReport() to bail out without sending escape sequences. The caller
// then sets explicit color values via SetHasDarkBackground/SetColorProfile,
// pre-empting the lazy query entirely. When a real TTY is present (e.g.,
// docker run -it), TERM is left intact so lipgloss can query the terminal
// and auto-detect the correct background color.
//
// Init order guarantee (Go spec): packages are initialized in dependency
// order; ties are broken by lexicographic package path. This package imports
// only "os" and "golang.org/x/term" (which depends on golang.org/x/sys) —
// strictly fewer dependencies than bubbletea (lipgloss → termenv → many
// packages), and "BakeLens" < "charmbracelet" for lexicographic tie-breaking.
package earlyinit

import (
	"os"

	"golang.org/x/term"
)

// Foreground is true when --foreground was detected in os.Args.
var Foreground bool

// Suppressed is true when TERM was set to "dumb" to prevent terminal queries.
// False when a real TTY is present and bubbletea was allowed to query normally.
var Suppressed bool

// OrigTERM holds the original TERM value before earlyinit may have set it to
// "dumb". Used to restore the color profile for styled log output.
var OrigTERM string

// ShouldSuppress reports whether TERM should be set to "dumb" to prevent
// terminal escape sequence leaks. Returns true when in foreground mode
// without a real TTY on stdout. Exported for testing.
func ShouldSuppress(foreground, isTTY bool) bool {
	return foreground && !isTTY
}

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

	OrigTERM = os.Getenv("TERM")

	// Only suppress terminal queries when stdout is not a real TTY.
	// With a real TTY (e.g., docker run -it), bubbletea can safely query
	// the terminal and get correct responses for background color, etc.
	isTTY := term.IsTerminal(int(os.Stdout.Fd())) //nolint:gosec // Fd() fits int
	if ShouldSuppress(Foreground, isTTY) {
		os.Setenv("TERM", "dumb")
		Suppressed = true
	}
}
