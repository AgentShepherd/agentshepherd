package rules

import (
	"testing"
)

func TestLinterBasic(t *testing.T) {
	linter := NewLinter()

	tests := []struct {
		name       string
		rules      []Rule
		wantErrors int
		wantWarns  int
	}{
		{
			name: "valid rule",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{"/etc/passwd"},
					},
				},
			},
			wantErrors: 0,
			wantWarns:  0,
		},
		{
			name: "missing name",
			rules: []Rule{
				{
					Message: "Test message",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{"/etc/passwd"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "missing message",
			rules: []Rule{
				{
					Name:    "test-rule",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{"/etc/passwd"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "missing operations",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Block: Block{
						Paths: []string{"/etc/passwd"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "missing block paths",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Actions: []Operation{OpRead},
				},
			},
			wantErrors: 1,
		},
		{
			name: "invalid operation",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Actions: []Operation{"invalid"},
					Block: Block{
						Paths: []string{"/etc/passwd"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "duplicate names",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{"/path1"},
					},
				},
				{
					Name:    "test-rule",
					Message: "Another message",
					Actions: []Operation{OpWrite},
					Block: Block{
						Paths: []string{"/path2"},
					},
				},
			},
			wantErrors: 1,
		},
		{
			name: "short pattern warning",
			rules: []Rule{
				{
					Name:    "test-rule",
					Message: "Test message",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{"ab"}, // Very short, not starting with / or *
					},
				},
			},
			wantErrors: 0,
			wantWarns:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := linter.LintRules(tt.rules)

			if result.Errors != tt.wantErrors {
				t.Errorf("got %d errors, want %d\nIssues: %s",
					result.Errors, tt.wantErrors, result.FormatIssues(true))
			}

			if tt.wantWarns > 0 && result.Warns < tt.wantWarns {
				t.Errorf("got %d warnings, want at least %d\nIssues: %s",
					result.Warns, tt.wantWarns, result.FormatIssues(true))
			}
		})
	}
}

func TestLinterBuiltinRules(t *testing.T) {
	linter := NewLinter()

	result, err := linter.LintBuiltin()
	if err != nil {
		t.Fatalf("Failed to lint builtin rules: %v", err)
	}

	// Builtin rules should have no errors
	if result.Errors > 0 {
		t.Errorf("Builtin rules have %d errors:\n%s", result.Errors, result.FormatIssues(true))
	}

	// Log warnings for visibility (but don't fail)
	if result.Warns > 0 {
		t.Logf("Builtin rules have %d warnings:\n%s", result.Warns, result.FormatIssues(false))
	}
}

func TestLinterPatternCompilation(t *testing.T) {
	linter := NewLinter()

	tests := []struct {
		name       string
		rules      []Rule
		wantErrors int
	}{
		{
			name: "invalid regex in match.path",
			rules: []Rule{
				{
					Name:    "bad-regex",
					Message: "test",
					Actions: []Operation{OpRead},
					Match:   &Match{Path: "re:(?P<invalid"},
				},
			},
			wantErrors: 1, // compilation error (+ possibly structural)
		},
		{
			name: "invalid glob in block.paths",
			rules: []Rule{
				{
					Name:    "bad-glob",
					Message: "test",
					Actions: []Operation{OpRead},
					Block:   Block{Paths: []string{"[unclosed"}},
				},
			},
			wantErrors: 1,
		},
		{
			name: "null byte in pattern",
			rules: []Rule{
				{
					Name:    "null-byte",
					Message: "test",
					Actions: []Operation{OpRead},
					Block:   Block{Paths: []string{"/path\x00bad"}},
				},
			},
			wantErrors: 1,
		},
		{
			name: "valid regex compiles fine",
			rules: []Rule{
				{
					Name:    "good-regex",
					Message: "test",
					Actions: []Operation{OpRead},
					Match:   &Match{Path: "re:/proc/\\d+/environ"},
				},
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := linter.LintRules(tt.rules)
			if tt.wantErrors > 0 && result.Errors == 0 {
				t.Errorf("expected errors for %q, got none", tt.name)
			}
			if tt.wantErrors == 0 && result.Errors > 0 {
				t.Errorf("expected no errors for %q, got %d:\n%s",
					tt.name, result.Errors, result.FormatIssues(true))
			}
		})
	}
}

func TestLinterSuspiciousPatterns(t *testing.T) {
	linter := NewLinter()

	tests := []struct {
		pattern  string
		hasIssue bool
		message  string
	}{
		// Should warn
		{`**foo`, true, "** without /"},
		// Should not warn
		{`**/foo`, false, "** with /"},
		{`/etc/passwd`, false, "normal absolute path"},
		{`*.yaml`, false, "glob with extension"},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			rules := []Rule{
				{
					Name:    "test",
					Message: "Test message",
					Actions: []Operation{OpRead},
					Block: Block{
						Paths: []string{tt.pattern},
					},
				},
			}

			result := linter.LintRules(rules)
			hasWarning := result.Warns > 0

			if tt.hasIssue && !hasWarning {
				t.Errorf("expected warning for pattern %q (%s), got none", tt.pattern, tt.message)
			}
		})
	}
}
