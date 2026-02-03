//go:build go1.18

package sandbox

import (
	"testing"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

// FuzzGlobToSandboxRegex tests glob → sandbox regex conversion for panics/crashes.
func FuzzGlobToSandboxRegex(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"**/.env",
		"**/.ssh/*",
		"**/credentials*",
		"/etc/**",
		"*.txt",
		"",
		"***",
		"?????",
		"#####",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, pattern string) {
		// Should not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("globToSandboxRegex panicked on: %q", pattern)
			}
		}()

		_ = globToSandboxRegex(pattern)
	})
}

// FuzzExpandHomeDir tests home directory expansion for panics.
func FuzzExpandHomeDir(f *testing.F) {
	seeds := []string{
		"~",
		"~/path",
		"~/.ssh/id_rsa",
		"/etc/passwd",
		"$HOME/test",
		"${HOME}/test",
		"",
		"~~~",
		"$HOME$HOME$HOME",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, path string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("expandHomeDir panicked on: %q", path)
			}
		}()

		_ = expandHomeDir(path)
	})
}

// FuzzDirectiveString tests directive formatting.
func FuzzDirectiveString(f *testing.F) {
	f.Add("file-read*", "regex", `\.env$`)
	f.Add("file-write*", "subpath", "/etc")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, operation, dtype, value string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Directive.String panicked: op=%q type=%q val=%q", operation, dtype, value)
			}
		}()

		d := Directive{
			Operation: operation,
			Type:      dtype,
			Value:     value,
		}

		_ = d.String()
	})
}

// FuzzMapperAddRule tests adding path-based rules to the mapper.
func FuzzMapperAddRule(f *testing.F) {
	f.Add("test-rule", "**/.env", true)
	f.Add("", "**/test", false)
	f.Add("rule", "", true)

	f.Fuzz(func(t *testing.T, name, path string, enabled bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AddRule panicked: name=%q path=%q enabled=%v", name, path, enabled)
			}
		}()

		mapper := NewMapper(t.TempDir() + "/test.sb")

		enabledPtr := &enabled
		rule := rules.Rule{
			Name:       name,
			Enabled:    enabledPtr,
			Block:      rules.Block{Paths: []string{path}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		}

		_ = mapper.AddRule(rule)
	})
}

// FuzzParseRuleSections tests profile parsing.
func FuzzParseRuleSections(f *testing.F) {
	seeds := []string{
		`(version 1)
(allow default)
; --- RULE: test ---
(deny file-read*)
; --- END RULE: test ---`,
		``,
		`; --- RULE: broken`,
		`(deny file-read* (regex #"\.env$"))`,
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, profile string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("parseRuleSections panicked on profile length %d", len(profile))
			}
		}()

		mapper := NewMapper(t.TempDir() + "/test.sb")
		_ = mapper.parseRuleSections(profile)
	})
}

// FuzzTranslateRule tests rule translation.
func FuzzTranslateRule(f *testing.F) {
	f.Add("test-rule", "**/.env", "read")
	f.Add("rule", "/etc/*", "write")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, name, path, op string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("TranslateRule panicked: name=%q path=%q op=%q", name, path, op)
			}
		}()

		enabled := true
		rule := rules.Rule{
			Name:       name,
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{path}},
			Operations: []rules.Operation{rules.Operation(op)},
			Message:    "test",
		}

		_ = TranslateRule(rule)
	})
}
