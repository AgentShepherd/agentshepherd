package rules

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
)

// Matcher matches normalized paths against glob patterns
type Matcher struct {
	patterns    []glob.Glob
	excepts     []glob.Glob
	rawPatterns []string // original pattern strings for reverse-glob matching
	rawExcepts  []string
}

// NewMatcher creates a matcher from glob patterns and exceptions.
// Returns an error if any pattern fails to compile.
func NewMatcher(patterns, excepts []string) (*Matcher, error) {
	m := &Matcher{
		patterns:    make([]glob.Glob, 0, len(patterns)),
		excepts:     make([]glob.Glob, 0, len(excepts)),
		rawPatterns: make([]string, 0, len(patterns)),
		rawExcepts:  make([]string, 0, len(excepts)),
	}

	// Compile patterns
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, g)
		m.rawPatterns = append(m.rawPatterns, p)
	}

	// Compile excepts
	for _, e := range excepts {
		g, err := glob.Compile(e, '/')
		if err != nil {
			return nil, err
		}
		m.excepts = append(m.excepts, g)
		m.rawExcepts = append(m.rawExcepts, e)
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

	// SECURITY: Reverse-glob match for paths containing glob characters.
	// When a command uses a glob in a file path (e.g., "cat /home/user/.e*"),
	// the shell extractor can't expand it (no filesystem access in dry-run mode).
	// The literal path "/home/user/.e*" won't match rule pattern "**/.env".
	// Fix: check if the path's glob could match any file that the rule protects.
	// We do this by checking if the filename part of a rule's pattern could match
	// the glob part of the extracted path using path.Match (standard glob semantics).
	if containsGlob(p) {
		if m.matchGlobbedPath(p) {
			return true
		}
	}

	return false
}

// containsGlob returns true if s contains unescaped glob metacharacters.
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// matchGlobbedPath checks if a path containing glob characters could match
// any file protected by this matcher's patterns.
//
// Strategy: extract the directory and filename-glob from the path, then check
// if any rule pattern's target filename could be matched by the filename-glob.
// The directory must also be compatible (the rule's directory pattern must be
// a prefix or glob-match of the path's directory).
//
// Example: path="/home/user/.e*", rule="**/.env"
//   - pathDir="/home/user", pathGlob=".e*"
//   - ruleFile=".env"
//   - path.Match(".e*", ".env") → true → blocked
func (m *Matcher) matchGlobbedPath(p string) bool {
	pathDir := path.Dir(p)
	pathFile := path.Base(p)

	// Only proceed if the filename part contains the glob
	if !containsGlob(pathFile) {
		return false
	}

	for i, rawPat := range m.rawPatterns {
		// Extract the filename portion from the rule pattern
		ruleFile := path.Base(rawPat)
		if ruleFile == "" || ruleFile == "." {
			continue
		}

		// Check if the extracted path's filename-glob matches the rule's filename.
		// path.Match handles *, ?, and [...] patterns.
		matched, err := path.Match(pathFile, ruleFile)
		if err != nil || !matched {
			continue
		}

		// Filename matches — now verify the directory is compatible.
		// The rule's directory pattern (e.g., "**" from "**/.env") must match
		// the extracted path's directory. Use the compiled glob for this.
		// Construct a concrete path using the rule's filename to test the compiled pattern.
		testPath := pathDir + "/" + ruleFile
		if m.patterns[i].Match(testPath) {
			// Check exceptions: the concrete path must not be excluded
			excluded := false
			for _, e := range m.excepts {
				if e.Match(testPath) {
					excluded = true
					break
				}
			}
			if !excluded {
				return true
			}
		}
	}
	return false
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
