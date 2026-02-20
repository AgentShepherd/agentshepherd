package rules

import (
	"os"
	"path/filepath"
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
// TestExpandFileGlobs verifies that filesystem glob expansion resolves
// glob patterns to actual files, replacing heuristic reverse-glob matching.
func TestExpandFileGlobs(t *testing.T) {
	// Create a temp directory with test files
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, ".env"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(home, ".env.local"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(home, ".env.example"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(home, ".bashrc"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(home, ".ssh", "id_rsa.pub"), []byte("x"), 0o600)
	os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
	os.WriteFile(filepath.Join(home, ".aws", "credentials"), []byte("x"), 0o600)

	tests := []struct {
		name       string
		input      []string
		wantEmpty  bool   // true if result should be empty
		wantSubstr string // expected substring in at least one result
	}{
		{
			name:       "non-glob path passes through",
			input:      []string{filepath.Join(home, ".env")},
			wantSubstr: ".env",
		},
		{
			name:       "star glob expands to matching files",
			input:      []string{filepath.Join(home, ".e*")},
			wantSubstr: ".env",
		},
		{
			name:       "question mark glob expands",
			input:      []string{filepath.Join(home, ".en?")},
			wantSubstr: ".env",
		},
		{
			name:       "bracket glob expands",
			input:      []string{filepath.Join(home, ".[e]nv")},
			wantSubstr: ".env",
		},
		{
			name:       "ssh key glob expands",
			input:      []string{filepath.Join(home, ".ssh", "id_r*")},
			wantSubstr: "id_rsa",
		},
		{
			name:       "aws cred glob expands",
			input:      []string{filepath.Join(home, ".aws", "cred*")},
			wantSubstr: "credentials",
		},
		{
			name:      "no-match glob produces empty result",
			input:     []string{filepath.Join(home, ".x*")},
			wantEmpty: true,
		},
		{
			name:      "nonexistent directory glob produces empty",
			input:     []string{filepath.Join(home, "nonexistent", "*.txt")},
			wantEmpty: true,
		},
		{
			name:       "bashrc glob expands (not a false positive)",
			input:      []string{filepath.Join(home, ".b*")},
			wantSubstr: ".bashrc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandFileGlobs(tt.input)
			if tt.wantEmpty {
				if len(result) != 0 {
					t.Errorf("expandFileGlobs(%v) = %v, want empty", tt.input, result)
				}
				return
			}
			if len(result) == 0 {
				t.Errorf("expandFileGlobs(%v) = empty, want results containing %q", tt.input, tt.wantSubstr)
				return
			}
			found := false
			for _, r := range result {
				if filepath.Base(r) == tt.wantSubstr || contains(r, tt.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expandFileGlobs(%v) = %v, none contain %q", tt.input, result, tt.wantSubstr)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && searchSubstr(s, substr)))
}

func searchSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
