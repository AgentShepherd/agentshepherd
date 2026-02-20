package rules

import (
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
)

// Matcher matches normalized paths against glob patterns
type Matcher struct {
	patterns []glob.Glob
	excepts  []glob.Glob
}

// NewMatcher creates a matcher from glob patterns and exceptions.
// Returns an error if any pattern fails to compile.
func NewMatcher(patterns, excepts []string) (*Matcher, error) {
	m := &Matcher{
		patterns: make([]glob.Glob, 0, len(patterns)),
		excepts:  make([]glob.Glob, 0, len(excepts)),
	}

	// Compile patterns
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, g)
	}

	// Compile excepts
	for _, e := range excepts {
		g, err := glob.Compile(e, '/')
		if err != nil {
			return nil, err
		}
		m.excepts = append(m.excepts, g)
	}

	return m, nil
}

// Match checks if path matches any pattern (and not excluded by except).
// Returns true only if: matches a pattern AND does NOT match any except.
// Empty patterns means nothing matches.
func (m *Matcher) Match(p string) bool {
	if len(m.patterns) == 0 {
		return false
	}

	// Normalize separators: on Windows, convert \ to / so glob patterns using /
	// match paths with either separator. On Unix this is a no-op.
	p = filepath.ToSlash(p)

	// Standard match: check if the path matches any compiled pattern.
	for _, pat := range m.patterns {
		if pat.Match(p) {
			for _, e := range m.excepts {
				if e.Match(p) {
					return false
				}
			}
			return true
		}
	}

	return false
}

// containsGlob returns true if s contains unescaped glob metacharacters.
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// MatchAny checks if any of the paths match, returns the first match.
// Returns (false, "") if no paths match.
func (m *Matcher) MatchAny(paths []string) (matched bool, matchedPath string) {
	for _, path := range paths {
		if m.Match(path) {
			return true, path
		}
	}
	return false, ""
}
