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

// BenchmarkJSONParsing benchmarks JSON argument extraction.
func BenchmarkJSONParsing(b *testing.B) {
	b.ReportAllocs()
	testCases := []struct {
		name string
		json string
		path string
	}{
		{"simple", `{"command": "ls"}`, "command"},
		{"nested", `{"options": {"path": "/etc"}}`, "options.path"},
		{"large", `{"command": "very long command with lots of text and arguments that might slow things down"}`, "command"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			data := json.RawMessage(tc.json)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = extractJSONField(data, tc.path)
			}
		})
	}
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

// BenchmarkContainsRegex benchmarks regex detection.
func BenchmarkContainsRegex(b *testing.B) {
	b.ReportAllocs()
	patterns := []string{
		"simple",
		`\.env$`,
		`[a-zA-Z0-9]+`,
		`^/proc/[0-9]+/cmdline$`,
		"no-metacharacters-here",
	}

	for _, p := range patterns {
		b.Run(p[:min(15, len(p))], func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = containsRegex(p)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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

// BenchmarkNormalizePathsRegexOnly benchmarks regex-only approach for comparison.
func BenchmarkNormalizePathsRegexOnly(b *testing.B) {
	b.ReportAllocs()
	commands := []struct {
		name string
		cmd  string
	}{
		{"simple", "ls -la /tmp"},
		{"multiple_paths", "cp /etc/passwd /tmp/backup"},
		{"path_traversal", "cat /etc/../etc/./passwd"},
		{"no_path", "echo hello world"},
	}

	for _, tc := range commands {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = normalizePathsRegex(tc.cmd)
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

// =============================================================================
// Matcher Benchmarks
// =============================================================================

// BenchmarkMatcher_ExactPath benchmarks exact path matching.
func BenchmarkMatcher_ExactPath(b *testing.B) {
	b.ReportAllocs()
	pattern := "/home/user/.env"
	paths := []string{"/home/user/.env"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}

// BenchmarkMatcher_SimpleGlob benchmarks simple glob pattern matching.
func BenchmarkMatcher_SimpleGlob(b *testing.B) {
	b.ReportAllocs()
	pattern := "**/.env"
	paths := []string{"/home/user/project/.env"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}

// BenchmarkMatcher_RecursiveGlob benchmarks recursive glob matching.
func BenchmarkMatcher_RecursiveGlob(b *testing.B) {
	b.ReportAllocs()
	pattern := "/home/**/.ssh/id_*"
	paths := []string{"/home/user/.ssh/id_rsa"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}

// BenchmarkMatcher_Regex benchmarks regex pattern matching.
func BenchmarkMatcher_Regex(b *testing.B) {
	b.ReportAllocs()
	pattern := `re:^/proc/[0-9]+/cmdline$`
	paths := []string{"/proc/12345/cmdline"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}

// BenchmarkMatcher_NoMatch benchmarks when pattern doesn't match.
func BenchmarkMatcher_NoMatch(b *testing.B) {
	b.ReportAllocs()
	pattern := "**/.env"
	paths := []string{"/home/user/project/main.go", "/tmp/data.txt"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}

// BenchmarkMatcher_ManyPaths benchmarks matching against many paths.
func BenchmarkMatcher_ManyPaths(b *testing.B) {
	b.ReportAllocs()
	pattern := "**/.env*"
	paths := []string{
		"/home/user/project/main.go",
		"/home/user/project/README.md",
		"/tmp/data.txt",
		"/var/log/syslog",
		"/etc/passwd",
		"/home/user/.bashrc",
		"/home/user/project/.env.local", // match
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchPath(pattern, paths)
	}
}
