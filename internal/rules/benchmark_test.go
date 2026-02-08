package rules

import (
	"encoding/json"
	"testing"
)

// BenchmarkRuleMatching benchmarks rule evaluation speed.
func BenchmarkRuleMatching(b *testing.B) {
	b.ReportAllocs()
	cfg := EngineConfig{
		DisableBuiltin: false,
		UserRulesDir:   b.TempDir(),
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// Test cases representing different scenarios
	testCases := []struct {
		name string
		call ToolCall
	}{
		{
			name: "simple_allowed",
			call: ToolCall{
				Name:      "Bash",
				Arguments: json.RawMessage(`{"command": "ls -la"}`),
			},
		},
		{
			name: "blocked_rm_rf",
			call: ToolCall{
				Name:      "Bash",
				Arguments: json.RawMessage(`{"command": "rm -rf /etc"}`),
			},
		},
		{
			name: "blocked_env_file",
			call: ToolCall{
				Name:      "Read",
				Arguments: json.RawMessage(`{"path": "/home/user/.env"}`),
			},
		},
		{
			name: "blocked_ssh_key",
			call: ToolCall{
				Name:      "Read",
				Arguments: json.RawMessage(`{"path": "/home/user/.ssh/id_rsa"}`),
			},
		},
		{
			name: "allowed_normal_file",
			call: ToolCall{
				Name:      "Read",
				Arguments: json.RawMessage(`{"path": "/home/user/project/main.go"}`),
			},
		},
		{
			name: "complex_command",
			call: ToolCall{
				Name:      "Bash",
				Arguments: json.RawMessage(`{"command": "find /var/log -name '*.log' -exec grep -l 'error' {} \\;"}`),
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = engine.Evaluate(tc.call)
			}
		})
	}
}

// BenchmarkRuleMatchingParallel benchmarks concurrent rule evaluation.
func BenchmarkRuleMatchingParallel(b *testing.B) {
	b.ReportAllocs()
	cfg := EngineConfig{
		DisableBuiltin: false,
		UserRulesDir:   b.TempDir(),
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	call := ToolCall{
		Name:      "Bash",
		Arguments: json.RawMessage(`{"command": "echo hello"}`),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = engine.Evaluate(call)
		}
	})
}

// BenchmarkRegexMatching benchmarks regex pattern matching.
func BenchmarkRegexMatching(b *testing.B) {
	b.ReportAllocs()
	cfg := EngineConfig{
		DisableBuiltin: false,
		UserRulesDir:   b.TempDir(),
	}
	engine, err := NewEngine(cfg)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// Get compiled rules
	rules := engine.GetRules()
	b.Logf("Testing with %d rules", len(rules))

	commands := []string{
		"ls -la",
		"rm -rf /",
		"cat /etc/passwd",
		"echo hello world",
		"find . -name '*.go'",
	}

	for _, cmd := range commands {
		b.Run(cmd[:min(20, len(cmd))], func(b *testing.B) {
			b.ReportAllocs()
			call := ToolCall{
				Name:      "Bash",
				Arguments: json.RawMessage(`{"command": "` + cmd + `"}`),
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = engine.Evaluate(call)
			}
		})
	}
}

// BenchmarkEngineCreation benchmarks engine initialization.
func BenchmarkEngineCreation(b *testing.B) {
	b.ReportAllocs()
	b.Run("with_builtin", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cfg := EngineConfig{
				DisableBuiltin: false,
				UserRulesDir:   b.TempDir(),
			}
			_, _ = NewEngine(cfg)
		}
	})

	b.Run("without_builtin", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cfg := EngineConfig{
				DisableBuiltin: true,
				UserRulesDir:   b.TempDir(),
			}
			_, _ = NewEngine(cfg)
		}
	})
}

// BenchmarkNormalizePathsInCommand benchmarks path normalization.
func BenchmarkNormalizePathsInCommand(b *testing.B) {
	b.ReportAllocs()
	sanitizer := GetSanitizer()

	commands := []struct {
		name string
		cmd  string
	}{
		{"simple", "ls -la /tmp"},
		{"multiple_paths", "cp /etc/passwd /tmp/backup"},
		{"path_traversal", "cat /etc/../etc/./passwd"},
		{"shell_var", "cat /proc/$PID/cmdline"},
		{"command_sub", "cat /proc/$(pgrep node)/environ"},
		{"complex", "for f in /proc/*/cmdline; do cat $f; done"},
		{"no_path", "echo hello world"},
		{"long_path", "cat /very/long/path/to/some/deeply/nested/file.txt"},
	}

	for _, tc := range commands {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = sanitizer.SanitizeCommand(tc.cmd)
			}
		})
	}
}

// =============================================================================
// Extractor Benchmarks
// =============================================================================

// BenchmarkExtractor_Bash_Simple benchmarks extracting from a simple bash command.
func BenchmarkExtractor_Bash_Simple(b *testing.B) {
	b.ReportAllocs()
	extractor := NewExtractor()
	args := json.RawMessage(`{"command": "ls -la"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract("Bash", args)
	}
}

// BenchmarkExtractor_Bash_Complex benchmarks extracting from a complex bash command.
func BenchmarkExtractor_Bash_Complex(b *testing.B) {
	b.ReportAllocs()
	extractor := NewExtractor()
	// Complex command with pipes, redirects, and multiple arguments
	args := json.RawMessage(`{"command": "cat /etc/passwd | grep root > /tmp/output.txt 2>&1 && echo done"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractor.Extract("Bash", args)
	}
}

// =============================================================================
// Normalizer Benchmarks
// =============================================================================

// BenchmarkNormalizer_NoOp benchmarks normalizing an already normalized path.
func BenchmarkNormalizer_NoOp(b *testing.B) {
	b.ReportAllocs()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", map[string]string{
		"HOME": "/home/user",
	})
	path := "/home/user/project/main.go"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizer.Normalize(path)
	}
}

// BenchmarkNormalizer_TildeExpansion benchmarks tilde expansion.
func BenchmarkNormalizer_TildeExpansion(b *testing.B) {
	b.ReportAllocs()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", map[string]string{
		"HOME": "/home/user",
	})
	path := "~/foo/bar/file.txt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizer.Normalize(path)
	}
}

// BenchmarkNormalizer_EnvVar benchmarks environment variable expansion.
func BenchmarkNormalizer_EnvVar(b *testing.B) {
	b.ReportAllocs()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", map[string]string{
		"HOME": "/home/user",
	})
	path := "$HOME/.env"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizer.Normalize(path)
	}
}

// BenchmarkNormalizer_Combined benchmarks all normalizer transformations.
func BenchmarkNormalizer_Combined(b *testing.B) {
	b.ReportAllocs()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", map[string]string{
		"HOME":    "/home/user",
		"PROJECT": "myproject",
	})
	// Path with tilde, env var, path traversal, and relative component
	path := "~/${PROJECT}/../other/./file.txt"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizer.Normalize(path)
	}
}

// BenchmarkNormalizer_Pattern benchmarks NormalizePattern (glob-safe normalization for sandbox).
func BenchmarkNormalizer_Pattern(b *testing.B) {
	b.ReportAllocs()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", map[string]string{
		"HOME":   "/home/user",
		"TMPDIR": "/tmp/user-tmp",
	})

	patterns := []struct {
		name    string
		pattern string
	}{
		{"glob_simple", "**/.env"},
		{"glob_with_tilde", "~/.ssh/id_*"},
		{"glob_with_envvar", "$TMPDIR/cache/**"},
		{"glob_recursive", "**/.aws/credentials"},
		{"absolute", "/etc/shadow"},
	}

	for _, tc := range patterns {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = normalizer.NormalizePattern(tc.pattern)
			}
		})
	}
}
