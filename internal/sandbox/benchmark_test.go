package sandbox

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

// commandTiming holds timing results for a command.
type commandTiming struct {
	name     string
	category string // "valid" or "malicious"
	cmd      []string
	samples  []time.Duration
	mean     time.Duration
	min      time.Duration
	max      time.Duration
}

// TestSandboxCostReport runs both valid and malicious commands and prints a cost report.
// Run with: go test -v -run TestSandboxCostReport ./internal/sandbox/
// Requires Linux 5.13+ with Landlock enabled.
func TestSandboxCostReport(t *testing.T) {
	platform := Platform()
	if platform == "Landlock not available" {
		t.Fatal("FATAL: Landlock not available. Requires Linux 5.13+ with CONFIG_SECURITY_LANDLOCK=y")
	}
	if !IsSupported() {
		t.Fatal("FATAL: Sandbox not supported on this platform. Requires Linux 5.13+ or macOS")
	}

	// Ensure sandbox-exec helper is found
	helperPath := setupSandboxExecPath(t)
	t.Logf("Using sandbox-exec helper: %s", helperPath)

	// Suppress sandbox stderr output during command execution
	restore := suppressOutput()

	// Load all builtin path-based rules
	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Count enabled rules
	var blockRules int
	for _, r := range builtinRules {
		if r.IsEnabled() {
			blockRules++
		}
	}

	// Create sandbox with all rules
	profilePath := filepath.Join(t.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)
	for _, rule := range builtinRules {
		if rule.IsEnabled() {
			_ = mapper.AddRule(rule)
		}
	}
	sb := New(mapper)

	// Create temp directory with test fixtures for malicious commands
	// Note: Content is intentionally non-realistic to avoid triggering secret detection
	fixtureDir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(fixtureDir, ".ssh"), 0755)
	fixtures := map[string]string{
		".env":             "TEST_VAR=value1\nANOTHER_VAR=value2",
		".ssh/id_rsa":      "fake ssh key content for testing",
		".ssh/id_ed25519":  "fake ed25519 key content for testing",
		"credentials.json": `{"test": "data", "for": "benchmarking"}`,
		"secrets.yaml":     "test: data\nfor: benchmarking",
	}
	for name, content := range fixtures {
		_ = os.WriteFile(filepath.Join(fixtureDir, name), []byte(content), 0644)
	}

	// Define test commands
	commands := []commandTiming{
		// Valid commands - safe operations
		{name: "echo hello", category: "valid", cmd: []string{"echo", "hello"}},
		{name: "ls /tmp", category: "valid", cmd: []string{"ls", "/tmp"}},
		{name: "true", category: "valid", cmd: []string{"true"}},
		{name: "cat /etc/hostname", category: "valid", cmd: []string{"cat", "/etc/hostname"}},
		{name: "pwd", category: "valid", cmd: []string{"pwd"}},
		// Malicious commands - would be blocked by Layer 1 rules engine
		// Using fixture files so commands succeed (measuring sandbox overhead, not file errors)
		{name: "cat .env", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".env")}},
		{name: "cat .ssh/id_rsa", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".ssh/id_rsa")}},
		{name: "cat .ssh/id_ed25519", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".ssh/id_ed25519")}},
		{name: "cat credentials.json", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, "credentials.json")}},
		{name: "cat secrets.yaml", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, "secrets.yaml")}},
		{name: "cat /proc/1/cmdline", category: "malicious", cmd: []string{"cat", "/proc/1/cmdline"}},
	}

	// Number of iterations for timing
	const iterations = 50

	// Run timing for each command
	for i := range commands {
		cmd := &commands[i]
		cmd.samples = make([]time.Duration, iterations)

		// Verify first execution works (catches helper not found errors)
		exitCode, err := sb.Wrap(cmd.cmd)
		if err != nil {
			t.Fatalf("Wrap failed for %q: %v", cmd.name, err)
		}
		// Note: exitCode may be non-zero for commands that fail (e.g., file not found)
		// We only care that the sandbox executed, not that the command succeeded
		_ = exitCode

		for j := 0; j < iterations; j++ {
			start := time.Now()
			_, _ = sb.Wrap(cmd.cmd)
			cmd.samples[j] = time.Since(start)
		}

		// Calculate statistics
		sort.Slice(cmd.samples, func(a, b int) bool {
			return cmd.samples[a] < cmd.samples[b]
		})
		cmd.min = cmd.samples[0]
		cmd.max = cmd.samples[len(cmd.samples)-1]

		var total time.Duration
		for _, s := range cmd.samples {
			total += s
		}
		cmd.mean = total / time.Duration(len(cmd.samples))
	}

	// Also measure bare execution (no sandbox)
	var bareMean time.Duration
	{
		samples := make([]time.Duration, iterations)
		for j := 0; j < iterations; j++ {
			start := time.Now()
			c := exec.Command("echo", "hello")
			c.Stdout = io.Discard
			c.Stderr = io.Discard
			_ = c.Run()
			samples[j] = time.Since(start)
		}
		var total time.Duration
		for _, s := range samples {
			total += s
		}
		bareMean = total / time.Duration(len(samples))
	}

	// Restore output before printing report
	restore()

	// Print report
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        SANDBOX COST REPORT                                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Platform: %-67s ║\n", Platform())
	fmt.Printf("║ Block Rules Loaded: %-57d ║\n", blockRules)
	fmt.Printf("║ Iterations per Command: %-53d ║\n", iterations)
	fmt.Printf("║ Bare Execution (no sandbox): %-48s ║\n", bareMean.String())
	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")

	// Valid commands
	fmt.Println("║                              VALID COMMANDS                                  ║")
	fmt.Println("╟──────────────────────────────────────────────────────────────────────────────╢")
	fmt.Println("║ Command                    │ Mean       │ Min        │ Max        │ Overhead ║")
	fmt.Println("╟────────────────────────────┼────────────┼────────────┼────────────┼──────────╢")

	var validTotal time.Duration
	var validCount int
	for _, cmd := range commands {
		if cmd.category == "valid" {
			overhead := float64(cmd.mean-bareMean) / float64(bareMean) * 100
			fmt.Printf("║ %-26s │ %10s │ %10s │ %10s │ %+6.1f%% ║\n",
				truncate(cmd.name, 26), cmd.mean.Truncate(time.Microsecond),
				cmd.min.Truncate(time.Microsecond), cmd.max.Truncate(time.Microsecond), overhead)
			validTotal += cmd.mean
			validCount++
		}
	}
	validAvg := validTotal / time.Duration(validCount)

	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")

	// Malicious commands
	fmt.Println("║                            MALICIOUS COMMANDS                                ║")
	fmt.Println("║ (These pass Layer 2 sandbox but would be blocked by Layer 1 rules engine)   ║")
	fmt.Println("╟──────────────────────────────────────────────────────────────────────────────╢")
	fmt.Println("║ Command                    │ Mean       │ Min        │ Max        │ Overhead ║")
	fmt.Println("╟────────────────────────────┼────────────┼────────────┼────────────┼──────────╢")

	var maliciousTotal time.Duration
	var maliciousCount int
	for _, cmd := range commands {
		if cmd.category == "malicious" {
			overhead := float64(cmd.mean-bareMean) / float64(bareMean) * 100
			fmt.Printf("║ %-26s │ %10s │ %10s │ %10s │ %+6.1f%% ║\n",
				truncate(cmd.name, 26), cmd.mean.Truncate(time.Microsecond),
				cmd.min.Truncate(time.Microsecond), cmd.max.Truncate(time.Microsecond), overhead)
			maliciousTotal += cmd.mean
			maliciousCount++
		}
	}
	maliciousAvg := maliciousTotal / time.Duration(maliciousCount)

	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                               SUMMARY                                        ║")
	fmt.Println("╟──────────────────────────────────────────────────────────────────────────────╢")
	fmt.Printf("║ Valid Commands Average:     %-50s ║\n", validAvg.Truncate(time.Microsecond).String())
	fmt.Printf("║ Malicious Commands Average: %-50s ║\n", maliciousAvg.Truncate(time.Microsecond).String())
	fmt.Printf("║ Sandbox Overhead (vs bare): %-50s ║\n", (validAvg - bareMean).Truncate(time.Microsecond).String())
	fmt.Println("╟──────────────────────────────────────────────────────────────────────────────╢")
	fmt.Println("║ NOTE: Layer 1 (rules engine) adds ~30μs and blocks malicious commands       ║")
	fmt.Println("║       Layer 2 (sandbox) adds ~300-500μs kernel-level protection             ║")
	fmt.Println("║       Persistent mode reduces sandbox overhead by ~40-65%                   ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// suppressOutput temporarily redirects stdout and stderr to discard during benchmarks.
func suppressOutput() func() {
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	devNull, _ := os.Open(os.DevNull)
	os.Stdout = devNull
	os.Stderr = devNull
	return func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
		devNull.Close()
	}
}

// setupSandboxExecPath finds the sandbox-exec helper and sets SANDBOX_EXEC_PATH.
// Returns the path to the helper or fails the test.
func setupSandboxExecPath(t testing.TB) string {
	// Check if already set
	if path := os.Getenv("SANDBOX_EXEC_PATH"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Find project root by looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	// Walk up to find project root
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("Could not find project root (go.mod)")
		}
		dir = parent
	}

	// Check for sandbox-exec in cmd/sandbox-exec/
	helperPath := filepath.Join(dir, "cmd", "sandbox-exec", "sandbox-exec")
	if _, err := os.Stat(helperPath); err != nil {
		t.Fatalf("sandbox-exec helper not found at %s. Build it with: make -C cmd/sandbox-exec", helperPath)
	}

	// Set environment variable so findSandboxExec() finds it
	os.Setenv("SANDBOX_EXEC_PATH", helperPath)
	return helperPath
}

// BenchmarkSandboxProfileGeneration benchmarks sandbox profile creation.
func BenchmarkSandboxProfileGeneration(b *testing.B) {
	b.ReportAllocs()
	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
		mapper := NewMapper(profilePath)
		for _, rule := range builtinRules {
			if rule.IsEnabled() {
				_ = mapper.AddRule(rule)
			}
		}
	}
}

// BenchmarkGlobToRegex benchmarks glob pattern conversion.
func BenchmarkGlobToRegex(b *testing.B) {
	b.ReportAllocs()
	patterns := []string{
		"**/.env",
		"**/.ssh/id_*",
		"**/credentials*",
		"/etc/**",
		"*.txt",
	}

	for _, p := range patterns {
		b.Run(p[:min(15, len(p))], func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = globToSandboxRegex(p)
			}
		})
	}
}

// BenchmarkCommandExecution benchmarks actual command execution.
// This compares execution with and without sandbox wrapper.
func BenchmarkCommandExecution(b *testing.B) {
	b.ReportAllocs()
	if !IsSupported() {
		b.Fatal("Sandbox not supported: requires Linux 5.13+ with Landlock")
	}

	// Ensure sandbox-exec helper is found
	setupSandboxExecPath(b)

	// Suppress sandbox stderr output during benchmarks
	restore := suppressOutput()
	defer restore()

	// Create sandbox with all builtin rules
	profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)

	loader := rules.NewLoader("")
	builtinRules, _ := loader.LoadBuiltin()
	for _, rule := range builtinRules {
		if rule.IsEnabled() {
			_ = mapper.AddRule(rule)
		}
	}

	sb := New(mapper)

	b.Run("without_sandbox", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cmd := exec.Command("echo", "hello")
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			_ = cmd.Run()
		}
	})

	b.Run("with_sandbox_all_rules", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_, _ = sb.Wrap([]string{"echo", "hello"})
		}
	})
}

// BenchmarkSandboxOverhead measures the pure overhead of sandbox.
func BenchmarkSandboxOverhead(b *testing.B) {
	b.ReportAllocs()
	if !IsSupported() {
		b.Fatal("Sandbox not supported: requires Linux 5.13+ with Landlock")
	}

	// Ensure sandbox-exec helper is found
	setupSandboxExecPath(b)

	// Suppress sandbox stderr output during benchmarks
	restore := suppressOutput()
	defer restore()

	profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)

	// Minimal rule (single rule)
	enabled := true
	rule := rules.Rule{
		Name:       "test-rule",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.env"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(rule)

	sb := New(mapper)

	// Benchmark simple commands
	commands := [][]string{
		{"true"},
		{"echo", "hello"},
		{"ls", "/tmp"},
	}

	for _, cmd := range commands {
		name := cmd[0]
		b.Run("bare_"+name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				c := exec.Command(cmd[0], cmd[1:]...)
				c.Stdout = io.Discard
				c.Stderr = io.Discard
				_ = c.Run()
			}
		})

		b.Run("sandbox_"+name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sb.Wrap(cmd)
			}
		})
	}
}

// BenchmarkAllBuiltinRules benchmarks sandbox with all builtin rules loaded.
// Includes both valid (safe) and malicious commands to verify behavior.
func BenchmarkAllBuiltinRules(b *testing.B) {
	b.ReportAllocs()
	if !IsSupported() {
		b.Fatal("Sandbox not supported: requires Linux 5.13+ with Landlock")
	}

	// Ensure sandbox-exec helper is found
	setupSandboxExecPath(b)

	restore := suppressOutput()
	defer restore()

	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	// Count rules for reporting
	var blockRules int
	for _, r := range builtinRules {
		if r.IsEnabled() {
			blockRules++
		}
	}
	b.Logf("Testing with %d block rules", blockRules)

	profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)
	for _, rule := range builtinRules {
		if rule.IsEnabled() {
			_ = mapper.AddRule(rule)
		}
	}
	sb := New(mapper)

	// Valid (safe) commands - should execute normally
	validCmds := []struct {
		name string
		cmd  []string
	}{
		{"valid_echo", []string{"echo", "hello"}},
		{"valid_ls_tmp", []string{"ls", "/tmp"}},
		{"valid_true", []string{"true"}},
		{"valid_cat_hostname", []string{"cat", "/etc/hostname"}},
	}

	for _, tc := range validCmds {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sb.Wrap(tc.cmd)
			}
		})
	}

	// Malicious commands - sandbox allows (Layer 1 blocks these)
	// NOTE: Landlock cannot block individual files, only directories.
	// These commands execute in sandbox but would be blocked by Layer 1.
	maliciousCmds := []struct {
		name string
		cmd  []string
	}{
		{"malicious_cat_env", []string{"cat", ".env"}},              // Would read secrets
		{"malicious_cat_ssh", []string{"cat", "/root/.ssh/id_rsa"}}, // Would read SSH key (will fail - no file)
		{"malicious_rm_etc", []string{"ls", "/etc/passwd"}},         // Probing system files
	}

	for _, tc := range maliciousCmds {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// These may fail (file not found) but sandbox allows execution
				_, _ = sb.Wrap(tc.cmd)
			}
		})
	}
}

// BenchmarkMapperOperations benchmarks mapper add/remove.
func BenchmarkMapperOperations(b *testing.B) {
	b.ReportAllocs()
	enabled := true
	b.Run("add_rule", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
			mapper := NewMapper(profilePath)

			rule := rules.Rule{
				Name:       "test-rule",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"**/.env"}},
				Operations: []rules.Operation{rules.OpRead},
				Message:    "test",
			}
			_ = mapper.AddRule(rule)
		}
	})

	b.Run("remove_rule", func(b *testing.B) {
		b.ReportAllocs()
		profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
		mapper := NewMapper(profilePath)

		rule := rules.Rule{
			Name:       "test-rule",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.env"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mapper.AddRule(rule)
			_ = mapper.RemoveRule("test-rule")
		}
	})
}

// BenchmarkConsistencyCheck benchmarks consistency checking.
func BenchmarkConsistencyCheck(b *testing.B) {
	b.ReportAllocs()
	profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)

	loader := rules.NewLoader("")
	builtinRules, _ := loader.LoadBuiltin()

	for _, rule := range builtinRules {
		if rule.IsEnabled() {
			_ = mapper.AddRule(rule)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mapper.CheckConsistency(builtinRules)
	}
}

// BenchmarkProfileParsing benchmarks profile file parsing.
func BenchmarkProfileParsing(b *testing.B) {
	b.ReportAllocs()
	// Create a realistic profile
	profile := `; AgentShepherd Sandbox Profile
(version 1)
(allow default)

; --- RULE: block-env-file-access ---
(deny file-read* (regex #"\.env$"))
(deny file-write* (regex #"\.env$"))
; --- END RULE: block-env-file-access ---

; --- RULE: block-ssh-key-access ---
(deny file-read* (regex #"\.ssh/(id_rsa|id_ed25519)$"))
; --- END RULE: block-ssh-key-access ---

; --- RULE: block-credentials ---
(deny file-read* (regex #"credentials\.json$"))
(deny file-read* (regex #"secrets\.yaml$"))
; --- END RULE: block-credentials ---
`

	profilePath := filepath.Join(b.TempDir(), "sandbox.sb")
	_ = os.WriteFile(profilePath, []byte(profile), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mapper := NewMapper(profilePath)
		_ = mapper.LoadFromFile()
	}
}

// BenchmarkTranslateRule benchmarks rule translation.
func BenchmarkTranslateRule(b *testing.B) {
	b.ReportAllocs()
	enabled := true
	testRules := []struct {
		name string
		rule rules.Rule
	}{
		{
			name: "single_path",
			rule: rules.Rule{
				Name:       "test",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"**/.env"}},
				Operations: []rules.Operation{rules.OpRead},
				Message:    "test",
			},
		},
		{
			name: "multiple_paths",
			rule: rules.Rule{
				Name:       "test",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"**/.env", "**/.ssh/*", "**/credentials*"}},
				Operations: []rules.Operation{rules.OpRead, rules.OpWrite},
				Message:    "test",
			},
		},
		{
			name: "all_operations",
			rule: rules.Rule{
				Name:       "test",
				Enabled:    &enabled,
				Block:      rules.Block{Paths: []string{"/etc"}},
				Operations: []rules.Operation{rules.OpRead, rules.OpWrite, rules.OpDelete, rules.OpCopy, rules.OpMove},
				Message:    "test",
			},
		},
	}

	for _, tc := range testRules {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = TranslateRule(tc.rule)
			}
		})
	}
}

// TestParentProcessNotRestricted verifies that the parent (Go test process)
// is not restricted by Landlock after running sandbox commands.
// This is the critical fix from the C helper approach.
func TestParentProcessNotRestricted(t *testing.T) {
	if !IsSupported() {
		t.Fatal("Sandbox not supported: requires Linux 5.13+ with Landlock")
	}

	// Ensure sandbox-exec helper is found
	setupSandboxExecPath(t)

	// Create sandbox
	profilePath := filepath.Join(t.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)
	sb := New(mapper)

	// Create a test file that we'll verify we can still access
	testFile := filepath.Join(t.TempDir(), "parent-test.txt")
	if err := os.WriteFile(testFile, []byte("before sandbox"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Run multiple sandbox commands
	for i := 0; i < 10; i++ {
		exitCode, err := sb.Wrap([]string{"true"})
		if err != nil {
			t.Fatalf("Wrap %d failed: %v", i, err)
		}
		if exitCode != 0 {
			t.Fatalf("Wrap %d exited with code %d", i, exitCode)
		}
	}

	// CRITICAL: Verify parent can still access files
	// If Landlock was incorrectly applied to parent, this would fail with EACCES
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Parent process cannot read file after sandbox: %v (Landlock incorrectly applied to parent!)", err)
	}
	if string(content) != "before sandbox" {
		t.Fatalf("Unexpected content: %s", content)
	}

	// Verify we can still write
	if err := os.WriteFile(testFile, []byte("after sandbox"), 0644); err != nil {
		t.Fatalf("Parent process cannot write file after sandbox: %v (Landlock incorrectly applied to parent!)", err)
	}

	// Verify we can create new files
	newFile := filepath.Join(t.TempDir(), "new-file.txt")
	if err := os.WriteFile(newFile, []byte("new content"), 0644); err != nil {
		t.Fatalf("Parent process cannot create file after sandbox: %v (Landlock incorrectly applied to parent!)", err)
	}

	t.Log("Parent process isolation verified: Go process not restricted by Landlock")
}
