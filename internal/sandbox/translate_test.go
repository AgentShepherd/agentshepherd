package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

func TestGlobToSandboxRegex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple filename",
			input:    ".env",
			expected: `\.env$`,
		},
		{
			name:     "double star slash at start",
			input:    "**/.env",
			expected: `(.*/)?\.env$`,
		},
		{
			name:     "double star slash in middle",
			input:    "/home/**/.ssh",
			expected: `/home/(.*/)?\.ssh$`,
		},
		{
			name:     "double star at end",
			input:    "/etc/**",
			expected: `/etc/.*`,
		},
		{
			name:     "single star",
			input:    "*.txt",
			expected: `[^/]*\.txt$`,
		},
		{
			name:     "mixed patterns",
			input:    "**/.env.*",
			expected: `(.*/)?\.env\.[^/]*$`,
		},
		{
			name:     "literal path",
			input:    "/etc/passwd",
			expected: `/etc/passwd$`,
		},
		{
			name:     "question mark",
			input:    "file?.txt",
			expected: `file.\.txt$`,
		},
		{
			name:     "hash in path",
			input:    "/path#with#hash",
			expected: `/path\#with\#hash$`,
		},
		{
			name:     "complex pattern",
			input:    "**/credentials*",
			expected: `(.*/)?credentials[^/]*$`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := globToSandboxRegex(tt.input)
			if result != tt.expected {
				t.Errorf("globToSandboxRegex(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExpandHomeDir(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "tilde alone",
			input:    "~",
			expected: home,
		},
		{
			name:     "tilde with path",
			input:    "~/.ssh/id_rsa",
			expected: filepath.Join(home, ".ssh/id_rsa"),
		},
		{
			name:     "no tilde",
			input:    "/etc/passwd",
			expected: "/etc/passwd",
		},
		{
			name:     "tilde in middle",
			input:    "/home/~user",
			expected: "/home/~user",
		},
		{
			name:     "$HOME expansion",
			input:    "$HOME/.config",
			expected: home + "/.config",
		},
		{
			name:     "${HOME} expansion",
			input:    "${HOME}/.config",
			expected: home + "/.config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := expandHomeDir(tt.input)
			if result != tt.expected {
				t.Errorf("expandHomeDir(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestOperationsToSandboxOps(t *testing.T) {
	tests := []struct {
		name     string
		ops      []rules.Operation
		expected []string
	}{
		{
			name:     "read only",
			ops:      []rules.Operation{rules.OpRead},
			expected: []string{"file-read*"},
		},
		{
			name:     "write only",
			ops:      []rules.Operation{rules.OpWrite},
			expected: []string{"file-write*"},
		},
		{
			name:     "delete only",
			ops:      []rules.Operation{rules.OpDelete},
			expected: []string{"file-write-unlink"},
		},
		{
			name:     "copy requires read and write",
			ops:      []rules.Operation{rules.OpCopy},
			expected: []string{"file-read*", "file-write*"},
		},
		{
			name:     "move requires read, write, and unlink",
			ops:      []rules.Operation{rules.OpMove},
			expected: []string{"file-read*", "file-write*", "file-write-unlink"},
		},
		{
			name:     "execute",
			ops:      []rules.Operation{rules.OpExecute},
			expected: []string{"process-exec*"},
		},
		{
			name:     "network",
			ops:      []rules.Operation{rules.OpNetwork},
			expected: []string{"network-outbound"},
		},
		{
			name:     "multiple ops deduplicated",
			ops:      []rules.Operation{rules.OpRead, rules.OpCopy},
			expected: []string{"file-read*", "file-write*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := operationsToSandboxOps(tt.ops)
			if len(result) != len(tt.expected) {
				t.Errorf("operationsToSandboxOps(%v) = %v, expected %v", tt.ops, result, tt.expected)
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("operationsToSandboxOps(%v)[%d] = %q, expected %q", tt.ops, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestDirective_String(t *testing.T) {
	tests := []struct {
		name      string
		directive Directive
		contains  []string
	}{
		{
			name: "regex directive (deny)",
			directive: Directive{
				Action:    "deny",
				Operation: "file-read*",
				Type:      "regex",
				Value:     `\.env$`,
			},
			contains: []string{"(deny file-read*", "(regex #\"", ".env"},
		},
		{
			name: "subpath directive (deny)",
			directive: Directive{
				Action:    "deny",
				Operation: "file-write*",
				Type:      "subpath",
				Value:     "/etc/secrets",
			},
			contains: []string{"(deny file-write*", "(subpath", "/etc/secrets"},
		},
		{
			name: "regex directive (allow - exception)",
			directive: Directive{
				Action:    "allow",
				Operation: "file-read*",
				Type:      "regex",
				Value:     `\.env\.example$`,
			},
			contains: []string{"(allow file-read*", "(regex #\"", "\\.env\\.example"},
		},
		{
			name: "subpath directive (allow - exception)",
			directive: Directive{
				Action:    "allow",
				Operation: "file-write*",
				Type:      "subpath",
				Value:     "/etc/secrets/public",
			},
			contains: []string{"(allow file-write*", "(subpath", "/etc/secrets/public"},
		},
		{
			name: "directive without action defaults to deny",
			directive: Directive{
				Operation: "file-read*",
				Type:      "regex",
				Value:     `/test$`,
			},
			contains: []string{"(deny file-read*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.directive.String()

			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("directive.String() = %q should contain %q", result, substr)
				}
			}
		})
	}
}

func TestDirective_Empty(t *testing.T) {
	directive := Directive{}
	result := directive.String()

	if result != "" {
		t.Errorf("empty directive should return empty string, got %q", result)
	}
}

func TestTranslateRule(t *testing.T) {
	enabled := true
	tests := []struct {
		name         string
		rule         rules.Rule
		minCount     int
		mustContain  []string
		mustNotEmpty bool
	}{
		{
			name: "single path single operation",
			rule: rules.Rule{
				Name:       "test-rule",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"/etc/passwd"}},
				Operations: []rules.Operation{rules.OpRead},
				Message:    "test",
			},
			minCount:    1,
			mustContain: []string{"file-read*", "/etc/passwd"},
		},
		{
			name: "glob pattern",
			rule: rules.Rule{
				Name:       "env-files",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"**/.env"}},
				Operations: []rules.Operation{rules.OpRead, rules.OpWrite},
				Message:    "test",
			},
			minCount:    2,
			mustContain: []string{"file-read*", "file-write*", "(.*/)"},
		},
		{
			name: "multiple paths",
			rule: rules.Rule{
				Name:       "multi-path",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"/etc", "/var"}},
				Operations: []rules.Operation{rules.OpDelete},
				Message:    "test",
			},
			minCount:    2,
			mustContain: []string{"file-write-unlink"},
		},
		{
			name: "rule with exceptions",
			rule: rules.Rule{
				Name:    "env-with-exception",
				Enabled: &enabled,
				Block: rules.Block{
					Paths:  []string{"**/.env"},
					Except: []string{"**/.env.example", "**/.env.sample"},
				},
				Operations: []rules.Operation{rules.OpRead},
				Message:    "test",
			},
			minCount:    3, // 1 deny + 2 allows
			mustContain: []string{"(deny file-read*", "(allow file-read*", "\\.env\\.example", "\\.env\\.sample"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TranslateRule(tt.rule)

			if len(result) < tt.minCount {
				t.Errorf("TranslateRule returned %d directives, expected at least %d", len(result), tt.minCount)
			}

			allDirectives := ""
			for _, d := range result {
				allDirectives += d.String()
			}

			for _, substr := range tt.mustContain {
				if !strings.Contains(allDirectives, substr) {
					t.Errorf("TranslateRule result should contain %q, got %q", substr, allDirectives)
				}
			}
		})
	}
}

func TestTranslateRules(t *testing.T) {
	enabled := true
	disabled := false

	rules := []rules.Rule{
		{
			Name:       "enabled-rule",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"/etc"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
		{
			Name:       "disabled-rule",
			Enabled:    &disabled,
			Block:      rules.Block{Paths: []string{"/var"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
	}

	result := TranslateRules(rules)

	// Should only have directives from the enabled rule
	allDirectives := ""
	for _, d := range result {
		allDirectives += d.String()
	}

	if !strings.Contains(allDirectives, "/etc") {
		t.Error("TranslateRules should include enabled rule's path")
	}
	if strings.Contains(allDirectives, "/var") {
		t.Error("TranslateRules should not include disabled rule's path")
	}
}

func TestGenerateSandboxProfile(t *testing.T) {
	enabled := true
	rules := []rules.Rule{
		{
			Name:       "test-rule",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.env"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
	}

	profile := GenerateSandboxProfile(rules)

	expectedParts := []string{
		"(version 1)",
		"(allow default)",
		"; Rule: test-rule",
		"(deny file-read*",
	}

	for _, part := range expectedParts {
		if !strings.Contains(profile, part) {
			t.Errorf("GenerateSandboxProfile should contain %q", part)
		}
	}
}

func TestGenerateSandboxProfile_WithExceptions(t *testing.T) {
	enabled := true
	rulesList := []rules.Rule{
		{
			Name:    "env-with-exceptions",
			Enabled: &enabled,
			Block: rules.Block{
				Paths:  []string{"**/.env"},
				Except: []string{"**/.env.example"},
			},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
	}

	profile := GenerateSandboxProfile(rulesList)

	// Check that all expected parts are present
	expectedParts := []string{
		"(version 1)",
		"(allow default)",
		"; Rule: env-with-exceptions",
		"; Exceptions:",
		"(allow file-read*",
		"(deny file-read*",
	}

	for _, part := range expectedParts {
		if !strings.Contains(profile, part) {
			t.Errorf("GenerateSandboxProfile should contain %q, got:\n%s", part, profile)
		}
	}

	// Verify that allow (exception) comes BEFORE deny in the profile
	// This is critical for Seatbelt first-match semantics
	allowIndex := strings.Index(profile, "(allow file-read*")
	denyIndex := strings.Index(profile, "(deny file-read*")

	if allowIndex == -1 {
		t.Error("Profile should contain allow directive for exception")
	}
	if denyIndex == -1 {
		t.Error("Profile should contain deny directive")
	}
	if allowIndex > denyIndex {
		t.Errorf("Allow (exception) should come BEFORE deny in profile for first-match semantics. Got allow at %d, deny at %d", allowIndex, denyIndex)
	}
}
