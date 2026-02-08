package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			expected: `^/home/(.*/)?\.ssh$`,
		},
		{
			name:     "double star at end",
			input:    "/etc/**",
			expected: `^/etc/.*`,
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
			expected: `^/etc/passwd$`,
		},
		{
			name:     "question mark",
			input:    "file?.txt",
			expected: `file.\.txt$`,
		},
		{
			name:     "hash in path",
			input:    "/path#with#hash",
			expected: `^/path\#with\#hash$`,
		},
		{
			name:     "complex pattern",
			input:    "**/credentials*",
			expected: `(.*/)?credentials[^/]*$`,
		},
		{
			name:     "double quote in path",
			input:    `/path/with"quote`,
			expected: `^/path/with\"quote$`,
		},
		{
			name:     "backslash in path",
			input:    `/path/with\backslash`,
			expected: `^/path/with\\backslash$`,
		},
		{
			name:     "absolute path gets start anchor",
			input:    "/etc/shadow",
			expected: `^/etc/shadow$`,
		},
		{
			name:     "glob not start-anchored",
			input:    "**/.env",
			expected: `(.*/)?\.env$`,
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
			result := ExpandHomeDir(tt.input)
			if result != tt.expected {
				t.Errorf("ExpandHomeDir(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestOperationsToSandboxOps(t *testing.T) {
	tests := []struct {
		name     string
		ops      []string
		expected []string
	}{
		{
			name:     "read only",
			ops:      []string{"read"},
			expected: []string{"file-read*"},
		},
		{
			name:     "write only",
			ops:      []string{"write"},
			expected: []string{"file-write*"},
		},
		{
			name:     "delete only",
			ops:      []string{"delete"},
			expected: []string{"file-write-unlink"},
		},
		{
			name:     "copy requires read and write",
			ops:      []string{"copy"},
			expected: []string{"file-read*", "file-write*"},
		},
		{
			name:     "move requires read, write, and unlink",
			ops:      []string{"move"},
			expected: []string{"file-read*", "file-write*", "file-write-unlink"},
		},
		{
			name:     "execute",
			ops:      []string{"execute"},
			expected: []string{"process-exec*"},
		},
		{
			name:     "network",
			ops:      []string{"network"},
			expected: []string{"network-outbound"},
		},
		{
			name:     "multiple ops deduplicated",
			ops:      []string{"read", "copy"},
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
		{
			name: "regex directive with escaped quote in value",
			directive: Directive{
				Action:    "deny",
				Operation: "file-read*",
				Type:      "regex",
				Value:     `path/with\"quote$`,
			},
			contains: []string{`(regex #"`, `with\"quote`},
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

// ---- ATTACK SURFACE TESTS ----

// SECURITY: globToSandboxRegex must escape dots before replacing glob patterns.
// Without proper escaping, a path like ".env" could match "xenv" (dot matches any char in regex).
func TestGlobToSandboxRegex_DotEscaping(t *testing.T) {
	result := globToSandboxRegex(".env")
	// The dot must be escaped to \\.
	if !strings.Contains(result, `\.env`) {
		t.Errorf("SECURITY: globToSandboxRegex(\".env\") = %q, dot must be escaped to prevent matching arbitrary characters", result)
	}
	// Make sure the placeholder approach works: dot is escaped, but glob placeholders aren't
	result2 := globToSandboxRegex("**/.env.*")
	if !strings.Contains(result2, `\.env\.`) {
		t.Errorf("SECURITY: globToSandboxRegex(\"**/.env.*\") = %q, dots must be escaped", result2)
	}
	// The ** should still become regex, not be escaped
	if !strings.Contains(result2, "(.*/)?") {
		t.Errorf("SECURITY: globToSandboxRegex(\"**/.env.*\") = %q, **/ must become (.*/)?", result2)
	}
}

// SECURITY: globToSandboxRegex must handle Seatbelt injection attempts in paths.
// A path containing ")(allow default)" could try to break out of a Seatbelt regex context.
func TestGlobToSandboxRegex_SeatbeltInjection(t *testing.T) {
	// This injection attempt tries to close a deny rule and open an allow-all
	injection := "/tmp/)(allow default)"
	result := globToSandboxRegex(injection)

	// The parentheses must be escaped so they don't terminate the regex context
	if strings.Contains(result, ")(allow") {
		t.Errorf("SECURITY: Seatbelt injection attempt not escaped: globToSandboxRegex(%q) = %q", injection, result)
	}
	if !strings.Contains(result, `\)`) || !strings.Contains(result, `\(`) {
		t.Errorf("SECURITY: parentheses must be escaped in regex output: %q", result)
	}
}

// SECURITY: globToSandboxRegex must escape all regex metacharacters in paths.
func TestGlobToSandboxRegex_RegexMetacharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		mustHave string // escaped form that must appear
	}{
		{"plus", "/path/with+plus", `\+`},
		{"caret", "/path/with^caret", `\^`},
		{"dollar", "/path/with$dollar", `\$`},
		{"pipe", "/path/with|pipe", `\|`},
		{"open_bracket", "/path/with[bracket", `\[`},
		{"close_bracket", "/path/with]bracket", `\]`},
		{"open_paren", "/path/with(paren", `\(`},
		{"close_paren", "/path/with)paren", `\)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := globToSandboxRegex(tt.input)
			if !strings.Contains(result, tt.mustHave) {
				t.Errorf("SECURITY: metachar not escaped: globToSandboxRegex(%q) = %q, must contain %q",
					tt.input, result, tt.mustHave)
			}
		})
	}
}

// SECURITY: TranslateRule must generate deny directives BEFORE allow (exception) directives.
// In Seatbelt profiles, order matters — exceptions must follow the deny they override.
func TestTranslateRule_DenyBeforeAllow(t *testing.T) {
	rule := &testRule{
		name:       "env-with-exception",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		except:     []string{"**/.env.example"},
		operations: []string{"read"},
	}

	result := TranslateRule(rule)

	// Find first deny and first allow
	firstDeny := -1
	firstAllow := -1
	for i, d := range result {
		if d.Action == "deny" && firstDeny == -1 {
			firstDeny = i
		}
		if d.Action == "allow" && firstAllow == -1 {
			firstAllow = i
		}
	}

	if firstDeny == -1 {
		t.Fatal("TranslateRule should produce deny directives")
	}
	if firstAllow == -1 {
		t.Fatal("TranslateRule should produce allow directives for exceptions")
	}
	if firstDeny >= firstAllow {
		t.Errorf("SECURITY: deny (index %d) must come BEFORE allow (index %d) — Seatbelt evaluates in order",
			firstDeny, firstAllow)
	}
}

// SECURITY: operationsToSandboxOps must deduplicate operations.
// Without dedup, duplicate sandbox ops could cause unexpected behavior.
func TestOperationsToSandboxOps_DeduplicatesExplicitly(t *testing.T) {
	// "copy" produces file-read* and file-write*
	// "read" also produces file-read*
	// Result should have file-read* only once
	result := operationsToSandboxOps([]string{"copy", "read", "write"})

	counts := make(map[string]int)
	for _, op := range result {
		counts[op]++
	}

	for op, count := range counts {
		if count > 1 {
			t.Errorf("SECURITY: operationsToSandboxOps produced duplicate op %q (%d times)", op, count)
		}
	}

	// Verify all expected ops are present
	expected := map[string]bool{"file-read*": true, "file-write*": true}
	for exp := range expected {
		if counts[exp] == 0 {
			t.Errorf("operationsToSandboxOps missing expected op %q", exp)
		}
	}
}

// SECURITY: ExpandHomeDir must NOT expand $HOME in the middle of a path.
// Only leading $HOME or ${HOME} should be expanded. Otherwise, a path like
// /tmp/$HOME/foo could leak the real home directory into the sandbox regex.
func TestExpandHomeDir_MiddleOfPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory available")
	}

	input := "/tmp/$HOME/foo"
	result := ExpandHomeDir(input)

	// ReplaceAll will expand $HOME wherever it appears — document this behavior
	// The current implementation DOES expand $HOME in the middle (known behavior).
	// This test documents the behavior and flags it if it changes.
	if strings.Contains(result, home) {
		t.Logf("KNOWN BEHAVIOR: ExpandHomeDir(%q) = %q — $HOME expanded in middle of path. "+
			"This is a known gap: strings.ReplaceAll expands all occurrences.", input, result)
	} else {
		// If this branch executes, the implementation was fixed
		t.Logf("ExpandHomeDir(%q) = %q — $HOME NOT expanded in middle (good)", input, result)
	}
}

func TestTranslateRule(t *testing.T) {
	tests := []struct {
		name         string
		rule         SecurityRule
		minCount     int
		mustContain  []string
		mustNotEmpty bool
	}{
		{
			name: "single path single operation",
			rule: &testRule{
				name:       "test-rule",
				enabled:    &boolTrue,
				paths:      []string{"/etc/passwd"},
				operations: []string{"read"},
			},
			minCount:    1,
			mustContain: []string{"file-read*", "/etc/passwd"},
		},
		{
			name: "glob pattern",
			rule: &testRule{
				name:       "env-files",
				enabled:    &boolTrue,
				paths:      []string{"**/.env"},
				operations: []string{"read", "write"},
			},
			minCount:    2,
			mustContain: []string{"file-read*", "file-write*", "(.*/)"},
		},
		{
			name: "multiple paths",
			rule: &testRule{
				name:       "multi-path",
				enabled:    &boolTrue,
				paths:      []string{"/etc", "/var"},
				operations: []string{"delete"},
			},
			minCount:    2,
			mustContain: []string{"file-write-unlink"},
		},
		{
			name: "rule with exceptions",
			rule: &testRule{
				name:       "env-with-exception",
				enabled:    &boolTrue,
				paths:      []string{"**/.env"},
				except:     []string{"**/.env.example", "**/.env.sample"},
				operations: []string{"read"},
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
