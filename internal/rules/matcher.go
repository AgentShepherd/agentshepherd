package rules

import (
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
func (m *Matcher) Match(path string) bool {
	// Empty patterns means nothing matches
	if len(m.patterns) == 0 {
		return false
	}

	// Check if path matches any pattern
	matched := false
	for _, p := range m.patterns {
		if p.Match(path) {
			matched = true
			break
		}
	}

	if !matched {
		return false
	}

	// Check if path is excluded by any except pattern
	for _, e := range m.excepts {
		if e.Match(path) {
			return false
		}
	}

	return true
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
