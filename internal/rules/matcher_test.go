package rules

import (
	"testing"
)

func TestMatcherNew(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		excepts  []string
		wantErr  bool
	}{
		{
			name:     "empty patterns and excepts",
			patterns: []string{},
			excepts:  []string{},
			wantErr:  false,
		},
		{
			name:     "valid patterns",
			patterns: []string{"**/.env", "/etc/**"},
			excepts:  []string{},
			wantErr:  false,
		},
		{
			name:     "valid patterns with excepts",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**"},
			wantErr:  false,
		},
		{
			name:     "invalid pattern",
			patterns: []string{"[invalid"},
			excepts:  []string{},
			wantErr:  true,
		},
		{
			name:     "invalid except",
			patterns: []string{"**/.env"},
			excepts:  []string{"[invalid"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMatcher(tt.patterns, tt.excepts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMatcher() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatcherMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		excepts  []string
		path     string
		want     bool
	}{
		// Empty patterns tests
		{
			name:     "empty patterns returns false",
			patterns: []string{},
			excepts:  []string{},
			path:     "/home/user/.env",
			want:     false,
		},

		// Basic glob matching
		{
			name:     "exact match",
			patterns: []string{"/home/user/.env"},
			excepts:  []string{},
			path:     "/home/user/.env",
			want:     true,
		},
		{
			name:     "exact match - no match",
			patterns: []string{"/home/user/.env"},
			excepts:  []string{},
			path:     "/home/other/.env",
			want:     false,
		},

		// ** recursive patterns
		{
			name:     "** pattern - .env at root",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "/.env",
			want:     true,
		},
		{
			name:     "** pattern - .env one level deep",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "/home/.env",
			want:     true,
		},
		{
			name:     "** pattern - .env deep nested",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "/home/user/projects/app/.env",
			want:     true,
		},
		{
			name:     "** pattern - .env.local",
			patterns: []string{"**/.env.*"},
			excepts:  []string{},
			path:     "/home/user/.env.local",
			want:     true,
		},
		{
			name:     "** pattern - .env.prod",
			patterns: []string{"**/.env.*"},
			excepts:  []string{},
			path:     "/project/.env.prod",
			want:     true,
		},
		{
			name:     "** pattern - SSH key id_rsa",
			patterns: []string{"**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_rsa",
			want:     true,
		},
		{
			name:     "** pattern - SSH key id_ed25519",
			patterns: []string{"**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_ed25519",
			want:     true,
		},
		{
			name:     "** pattern - SSH key no match",
			patterns: []string{"**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/known_hosts",
			want:     false,
		},
		{
			name:     "/etc/** pattern - matches direct child",
			patterns: []string{"/etc/**"},
			excepts:  []string{},
			path:     "/etc/passwd",
			want:     true,
		},
		{
			name:     "/etc/** pattern - matches nested",
			patterns: []string{"/etc/**"},
			excepts:  []string{},
			path:     "/etc/ssh/sshd_config",
			want:     true,
		},
		{
			name:     "/etc/** pattern - no match outside /etc",
			patterns: []string{"/etc/**"},
			excepts:  []string{},
			path:     "/var/etc/config",
			want:     false,
		},

		// * single segment patterns
		{
			name:     "*.txt in current dir",
			patterns: []string{"*.txt"},
			excepts:  []string{},
			path:     "file.txt",
			want:     true,
		},
		{
			name:     "*.txt does not match nested",
			patterns: []string{"*.txt"},
			excepts:  []string{},
			path:     "dir/file.txt",
			want:     false,
		},
		{
			name:     "/**/*.txt matches nested",
			patterns: []string{"/**/*.txt"},
			excepts:  []string{},
			path:     "/dir/file.txt",
			want:     true,
		},

		// Multiple patterns
		{
			name:     "multiple patterns - first matches",
			patterns: []string{"**/.env", "**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/.env",
			want:     true,
		},
		{
			name:     "multiple patterns - second matches",
			patterns: []string{"**/.env", "**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_rsa",
			want:     true,
		},
		{
			name:     "multiple patterns - none match",
			patterns: []string{"**/.env", "**/.ssh/id_*"},
			excepts:  []string{},
			path:     "/home/user/config.yaml",
			want:     false,
		},

		// Except patterns
		{
			name:     "except excludes match",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**"},
			path:     "/project/test/.env",
			want:     false,
		},
		{
			name:     "except does not exclude non-matching",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**"},
			path:     "/project/src/.env",
			want:     true,
		},
		{
			name:     "multiple excepts - first excludes",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**", "**/mock/**"},
			path:     "/project/test/.env",
			want:     false,
		},
		{
			name:     "multiple excepts - second excludes",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**", "**/mock/**"},
			path:     "/project/mock/.env",
			want:     false,
		},
		{
			name:     "multiple excepts - none exclude",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/test/**", "**/mock/**"},
			path:     "/project/src/.env",
			want:     true,
		},

		// Edge cases
		{
			name:     "empty path",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "",
			want:     false,
		},
		{
			name:     "path with trailing slash",
			patterns: []string{"/etc/**"},
			excepts:  []string{},
			path:     "/etc/",
			want:     true,
		},
		{
			name:     "pattern matches exactly",
			patterns: []string{"/etc/passwd"},
			excepts:  []string{},
			path:     "/etc/passwd",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(tt.patterns, tt.excepts)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := m.Match(tt.path)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestMatcherMatchAny(t *testing.T) {
	tests := []struct {
		name            string
		patterns        []string
		excepts         []string
		paths           []string
		wantMatched     bool
		wantMatchedPath string
	}{
		{
			name:            "empty paths",
			patterns:        []string{"**/.env"},
			excepts:         []string{},
			paths:           []string{},
			wantMatched:     false,
			wantMatchedPath: "",
		},
		{
			name:            "no match",
			patterns:        []string{"**/.env"},
			excepts:         []string{},
			paths:           []string{"/home/user/config.yaml", "/etc/passwd"},
			wantMatched:     false,
			wantMatchedPath: "",
		},
		{
			name:            "first path matches",
			patterns:        []string{"**/.env"},
			excepts:         []string{},
			paths:           []string{"/home/user/.env", "/etc/passwd"},
			wantMatched:     true,
			wantMatchedPath: "/home/user/.env",
		},
		{
			name:            "second path matches",
			patterns:        []string{"**/.env"},
			excepts:         []string{},
			paths:           []string{"/etc/passwd", "/home/user/.env"},
			wantMatched:     true,
			wantMatchedPath: "/home/user/.env",
		},
		{
			name:            "multiple matches - returns first",
			patterns:        []string{"**/.env"},
			excepts:         []string{},
			paths:           []string{"/project/.env", "/home/user/.env"},
			wantMatched:     true,
			wantMatchedPath: "/project/.env",
		},
		{
			name:            "match with except - first excluded, second matches",
			patterns:        []string{"**/.env"},
			excepts:         []string{"**/test/**"},
			paths:           []string{"/project/test/.env", "/project/src/.env"},
			wantMatched:     true,
			wantMatchedPath: "/project/src/.env",
		},
		{
			name:            "all paths excluded by except",
			patterns:        []string{"**/.env"},
			excepts:         []string{"**/test/**"},
			paths:           []string{"/project/test/.env", "/app/test/config/.env"},
			wantMatched:     false,
			wantMatchedPath: "",
		},
		{
			name:            "empty patterns - no match",
			patterns:        []string{},
			excepts:         []string{},
			paths:           []string{"/home/user/.env"},
			wantMatched:     false,
			wantMatchedPath: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(tt.patterns, tt.excepts)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			gotMatched, gotMatchedPath := m.MatchAny(tt.paths)
			if gotMatched != tt.wantMatched {
				t.Errorf("MatchAny() matched = %v, want %v", gotMatched, tt.wantMatched)
			}
			if gotMatchedPath != tt.wantMatchedPath {
				t.Errorf("MatchAny() matchedPath = %q, want %q", gotMatchedPath, tt.wantMatchedPath)
			}
		})
	}
}

func TestMatcherEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		excepts  []string
		path     string
		want     bool
	}{
		// Empty excepts means nothing excluded
		{
			name:     "nil excepts",
			patterns: []string{"**/.env"},
			excepts:  nil,
			path:     "/home/user/.env",
			want:     true,
		},

		// Complex patterns
		{
			name:     "complex pattern with multiple wildcards",
			patterns: []string{"**/config/**/*.yaml"},
			excepts:  []string{},
			path:     "/project/config/sub/settings.yaml",
			want:     true,
		},
		{
			name:     "pattern with question mark",
			patterns: []string{"**/.env.?"},
			excepts:  []string{},
			path:     "/project/.env.1",
			want:     true,
		},
		{
			name:     "pattern with character class",
			patterns: []string{"**/id_[re]*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_rsa",
			want:     true,
		},
		{
			name:     "pattern with character class - ed25519",
			patterns: []string{"**/id_[re]*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_ed25519",
			want:     true,
		},
		{
			name:     "pattern with character class - no match",
			patterns: []string{"**/id_[re]*"},
			excepts:  []string{},
			path:     "/home/user/.ssh/id_dsa",
			want:     false,
		},

		// Paths with special characters
		{
			name:     "path with spaces",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "/home/user/my project/.env",
			want:     true,
		},
		{
			name:     "path with dots",
			patterns: []string{"**/.env"},
			excepts:  []string{},
			path:     "/home/user/project.old/.env",
			want:     true,
		},

		// Both except and pattern match same path
		{
			name:     "except takes precedence over pattern",
			patterns: []string{"**/.env"},
			excepts:  []string{"**/.env"},
			path:     "/home/user/.env",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(tt.patterns, tt.excepts)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := m.Match(tt.path)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// TestMatcher_ReverseGlobMatching verifies the reverse-glob matching logic
// that catches paths containing glob characters (e.g., "cat /home/user/.e*").
// When the shell extractor can't expand globs at static analysis time,
// the matcher must detect that the glob could match a protected file.
func TestMatcher_ReverseGlobMatching(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		excepts  []string
		path     string
		want     bool
	}{
		// === Star glob in filename ===
		{
			name:     "star glob matches .env",
			patterns: []string{"**/.env"},
			path:     "/home/user/.e*",
			want:     true,
		},
		{
			name:     "star glob matches .env.local",
			patterns: []string{"**/.env.*"},
			path:     "/home/user/.env.*",
			want:     true,
		},
		{
			name:     "star glob matches SSH key",
			patterns: []string{"**/.ssh/id_*"},
			path:     "/home/user/.ssh/id_*",
			want:     true,
		},
		{
			name:     "star glob too narrow — .x* does not match .env",
			patterns: []string{"**/.env"},
			path:     "/home/user/.x*",
			want:     false,
		},

		// === Question mark glob in filename ===
		{
			name:     "question mark matches .env (4 chars)",
			patterns: []string{"**/.env"},
			path:     "/home/user/.en?",
			want:     true,
		},
		{
			name:     "question mark no match — wrong length",
			patterns: []string{"**/.env"},
			path:     "/home/user/.e?",
			want:     false,
		},

		// === Bracket glob in filename ===
		{
			name:     "bracket glob matches .env",
			patterns: []string{"**/.env"},
			path:     "/home/user/.[e]nv",
			want:     true,
		},
		{
			name:     "bracket glob no match",
			patterns: []string{"**/.env"},
			path:     "/home/user/.[x]nv",
			want:     false,
		},

		// === Directory compatibility ===
		{
			name:     "glob in correct directory",
			patterns: []string{"**/.ssh/id_*"},
			path:     "/home/user/.ssh/id_*",
			want:     true,
		},
		{
			name:     "glob in wrong directory",
			patterns: []string{"**/.ssh/id_*"},
			path:     "/tmp/id_*",
			want:     false,
		},

		// === Except patterns respected ===
		{
			name:     "glob matches but excepted",
			patterns: []string{"**/.env*"},
			excepts:  []string{"**/.env.example"},
			path:     "/home/user/.env.exampl?",
			want:     true, // .env.exampl? could match .env.example, but also .env.examplX — block conservatively
		},
		{
			name:     "glob with except — concrete file excepted",
			patterns: []string{"**/.env"},
			excepts:  []string{"/home/user/.env"},
			path:     "/home/user/.e*",
			want:     false, // the concrete test path /home/user/.env IS excepted
		},

		// === Multiple patterns ===
		{
			name:     "glob matches second pattern",
			patterns: []string{"**/config.yaml", "**/.env"},
			path:     "/app/.e*",
			want:     true,
		},

		// === Non-glob paths unaffected ===
		{
			name:     "normal path still works",
			patterns: []string{"**/.env"},
			path:     "/home/user/.env",
			want:     true,
		},
		{
			name:     "normal path no match",
			patterns: []string{"**/.env"},
			path:     "/home/user/safe.txt",
			want:     false,
		},

		// === Glob only in directory (not filename) ===
		{
			name:     "glob only in directory part — not handled by reverse-glob",
			patterns: []string{"**/.env"},
			path:     "/home/*/.env",
			want:     true, // standard match handles this via compiled glob
		},

		// === Real-world bypass patterns ===
		{
			name:     "cat /home/user/.e* (actual bypass)",
			patterns: []string{"**/.env", "**/.env.*"},
			excepts:  []string{"**/.env.example"},
			path:     "/home/user/.e*",
			want:     true,
		},
		{
			name:     "cat ~/.ssh/id_r* (SSH key glob)",
			patterns: []string{"**/.ssh/id_*"},
			excepts:  []string{"**/.ssh/id_*.pub"},
			path:     "/home/user/.ssh/id_r*",
			want:     true,
		},
		{
			name:     "cat ~/.aws/cred* (AWS creds glob)",
			patterns: []string{"**/.aws/credentials", "**/.aws/config"},
			path:     "/home/user/.aws/cred*",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(tt.patterns, tt.excepts)
			if err != nil {
				t.Fatalf("NewMatcher() error = %v", err)
			}

			got := m.Match(tt.path)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v (patterns=%v, excepts=%v)",
					tt.path, got, tt.want, tt.patterns, tt.excepts)
			}
		})
	}
}

// TestContainsGlob verifies the glob metacharacter detection helper.
func TestContainsGlob(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"/home/user/.env", false},
		{"/home/user/.e*", true},
		{"/home/user/.en?", true},
		{"/home/user/.[e]nv", true},
		{"no-glob-here", false},
		{"*", true},
		{"file?.txt", true},
		{"[abc]", true},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := containsGlob(tt.input); got != tt.want {
				t.Errorf("containsGlob(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestMatcher_ExceptWithMultiplePatterns verifies that the early-return
// Match implementation correctly checks exceptions for all matching patterns.
func TestMatcher_ExceptWithMultiplePatterns(t *testing.T) {
	m, err := NewMatcher(
		[]string{"**/.env", "**/.env.*"},
		[]string{"**/.env.example"},
	)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}

	tests := []struct {
		path string
		want bool
	}{
		{"/home/user/.env", true},
		{"/home/user/.env.production", true},
		{"/home/user/.env.example", false},
		{"/tmp/.env.example", false},
		{"/tmp/safe.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := m.Match(tt.path)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
