//go:build sandbox_e2e

package sandbox

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

// ==================== Go → Rust Integration Contract Tests ====================
//
// These tests verify the Go→Rust IPC contract: policy JSON serialization,
// exit code propagation, environment sanitization, and error handling.
// They do NOT test Rust enforcement (Landlock, Seatbelt, etc.) — that is
// covered by the Rust test suite.
//
// Run with: task test-e2e
// Requires: bakelens-sandbox binary (build with: task build)

// --- Policy JSON contract ---

// TestE2E_PolicyAcceptedByRust verifies Rust parses the policy JSON that Go produces.
// This catches JSON schema mismatches between Go's PolicyJSON and Rust's InputPolicy.
func TestE2E_PolicyAcceptedByRust(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules([]SecurityRule{
		&testRule{
			name:       "test-rule",
			paths:      []string{"**/.env", "**/.env.*"},
			except:     []string{"**/.env.example"},
			operations: []string{"read", "write"},
		},
	})
	defer SetRules(nil)

	sb := New()
	exitCode, err := sb.Wrap([]string{"true"})
	if err != nil {
		t.Fatalf("Wrap() failed: %v (Rust may have rejected Go's policy JSON)", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0 (Rust may have rejected policy)", exitCode)
	}
}

// TestE2E_PolicyWithHostsAccepted verifies Rust accepts rules with host entries.
func TestE2E_PolicyWithHostsAccepted(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules([]SecurityRule{
		&testRule{
			name:       "block-ip",
			paths:      []string{"**/.env"},
			operations: []string{"read"},
			hosts:      []string{"127.0.0.1"},
		},
	})
	defer SetRules(nil)

	sb := New()
	exitCode, err := sb.Wrap([]string{"true"})
	if err != nil {
		t.Fatalf("Wrap() with host entries failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

// TestE2E_EmptyRulesAccepted verifies Rust accepts a policy with zero deny rules.
func TestE2E_EmptyRulesAccepted(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)

	sb := New()
	exitCode, err := sb.Wrap([]string{"true"})
	if err != nil {
		t.Fatalf("Wrap() with empty rules failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

// TestE2E_MultipleRulesAccepted verifies Rust accepts a policy with many rules.
func TestE2E_MultipleRulesAccepted(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	rules := make([]SecurityRule, 20)
	for i := range rules {
		rules[i] = &testRule{
			name:       "rule-" + strings.Repeat("x", 5) + string(rune('a'+i)),
			paths:      []string{"**/pattern-" + string(rune('a'+i))},
			operations: []string{"read", "write", "delete"},
		}
	}
	SetRules(rules)
	defer SetRules(nil)

	sb := New()
	exitCode, err := sb.Wrap([]string{"true"})
	if err != nil {
		t.Fatalf("Wrap() with 20 rules failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

// --- Exit code propagation ---

// TestE2E_ExitCodeZero verifies exit code 0 is propagated from Rust.
func TestE2E_ExitCodeZero(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	exitCode, err := sb.Wrap([]string{"true"})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
}

// TestE2E_ExitCodeNonZero verifies non-zero exit codes are propagated from Rust.
func TestE2E_ExitCodeNonZero(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	exitCode, err := sb.Wrap([]string{"false"})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 1 {
		t.Errorf("exit code = %d, want 1", exitCode)
	}
}

// TestE2E_ExitCodeFromShell verifies specific exit codes pass through.
func TestE2E_ExitCodeFromShell(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	exitCode, err := sb.Wrap([]string{"sh", "-c", "exit 42"})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("exit code = %d, want 42", exitCode)
	}
}

// --- Command argument passing ---

// TestE2E_CommandArgsPreserved verifies arguments pass through Go→Rust→exec correctly.
func TestE2E_CommandArgsPreserved(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	// Write a marker via the sandboxed command, read it back
	tmpFile := t.TempDir() + "/args-test.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "echo hello world > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read marker file: %v", err)
	}
	if got := strings.TrimSpace(string(content)); got != "hello world" {
		t.Errorf("marker content = %q, want %q", got, "hello world")
	}
}

// TestE2E_CommandWithSpacesInArgs verifies arguments with spaces are preserved.
func TestE2E_CommandWithSpacesInArgs(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	tmpFile := t.TempDir() + "/spaces-test.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "echo 'arg with spaces' > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read marker file: %v", err)
	}
	if got := strings.TrimSpace(string(content)); got != "arg with spaces" {
		t.Errorf("marker content = %q, want %q", got, "arg with spaces")
	}
}

// --- Environment sanitization pipeline ---

// TestE2E_EnvSanitization verifies dangerous env vars do NOT reach the sandboxed process.
func TestE2E_EnvSanitization(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	// Set dangerous env vars that must NOT leak into the sandbox
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib")
	t.Setenv("SECRET_API_KEY", "hunter2")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s3cr3t")

	SetRules(nil)
	sb := New()

	tmpFile := t.TempDir() + "/env-test.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "env > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	env := string(content)
	for _, dangerous := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "SECRET_API_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(env, dangerous+"=") {
			t.Errorf("SECURITY: sandboxed process must not see %s", dangerous)
		}
	}
}

// TestE2E_EnvSafeVarsPresent verifies allowlisted env vars ARE passed through.
func TestE2E_EnvSafeVarsPresent(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	t.Setenv("HOME", "/home/testuser")
	t.Setenv("PATH", "/usr/bin:/bin")

	SetRules(nil)
	sb := New()

	tmpFile := t.TempDir() + "/env-safe.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "env > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	env := string(content)
	if !strings.Contains(env, "HOME=") {
		t.Error("sandboxed process should see HOME")
	}
	if !strings.Contains(env, "PATH=") {
		t.Error("sandboxed process should see PATH")
	}
}

// TestE2E_ProxyURLInjection verifies proxy URL env vars are injected when set.
func TestE2E_ProxyURLInjection(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetProxyURL("http://127.0.0.1:9876")
	defer SetProxyURL("")

	SetRules(nil)
	sb := New()

	tmpFile := t.TempDir() + "/proxy-env.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "env > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	env := string(content)
	if !strings.Contains(env, "ANTHROPIC_BASE_URL=http://127.0.0.1:9876") {
		t.Error("ANTHROPIC_BASE_URL not injected into sandboxed process")
	}
	if !strings.Contains(env, "OPENAI_BASE_URL=http://127.0.0.1:9876/v1") {
		t.Error("OPENAI_BASE_URL not injected into sandboxed process")
	}
}

// TestE2E_NoProxyURLWhenUnset verifies proxy vars are NOT injected when proxy is not set.
func TestE2E_NoProxyURLWhenUnset(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetProxyURL("")

	SetRules(nil)
	sb := New()

	tmpFile := t.TempDir() + "/no-proxy-env.txt"
	exitCode, err := sb.Wrap([]string{"sh", "-c", "env > " + tmpFile})
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	env := string(content)
	if strings.Contains(env, "ANTHROPIC_BASE_URL=") {
		t.Error("ANTHROPIC_BASE_URL should not be present when proxy is unset")
	}
	if strings.Contains(env, "OPENAI_BASE_URL=") {
		t.Error("OPENAI_BASE_URL should not be present when proxy is unset")
	}
}

// --- Error handling ---

// TestE2E_NonexistentCommand verifies the pipeline handles a nonexistent command.
func TestE2E_NonexistentCommand(t *testing.T) {
	setupBakelensSandboxPath(t)
	restore := suppressOutput()
	defer restore()

	SetRules(nil)
	sb := New()

	exitCode, err := sb.Wrap([]string{"/nonexistent/command/that/does/not/exist"})
	// Rust should attempt to exec and fail — Go should get a non-zero exit code.
	// The exact behavior depends on Rust: it may return exit code 127 or an error.
	if err == nil && exitCode == 0 {
		t.Error("expected failure for nonexistent command, got exit code 0 with no error")
	}
}

// --- Policy JSON structure (pure Go, no Rust needed) ---

// TestE2E_PolicyJSONStructure verifies the serialized policy matches the Rust schema.
func TestE2E_PolicyJSONStructure(t *testing.T) {
	SetRules([]SecurityRule{
		&testRule{
			name:       "test-fs",
			paths:      []string{"**/.env"},
			except:     []string{"**/.env.example"},
			operations: []string{"read", "write"},
		},
		&testRule{
			name:       "test-net",
			hosts:      []string{"127.0.0.1"},
			operations: []string{"network"},
		},
	})
	defer SetRules(nil)

	policyJSON, err := buildPolicy([]string{"echo", "hello"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	// Verify it round-trips through JSON correctly
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(policyJSON, &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// Must have exactly: version, command, rules (no extra fields — Rust uses deny_unknown_fields)
	allowedKeys := map[string]bool{"version": true, "command": true, "rules": true}
	for key := range raw {
		if !allowedKeys[key] {
			t.Errorf("SECURITY: unexpected top-level key %q in policy JSON (Rust uses deny_unknown_fields)", key)
		}
	}
	for key := range allowedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing required key %q in policy JSON", key)
		}
	}

	// Verify version is 1
	var version int
	if err := json.Unmarshal(raw["version"], &version); err != nil {
		t.Fatalf("unmarshal version: %v", err)
	}
	if version != 1 {
		t.Errorf("version = %d, want 1", version)
	}

	// Verify command is preserved
	var command []string
	if err := json.Unmarshal(raw["command"], &command); err != nil {
		t.Fatalf("unmarshal command: %v", err)
	}
	if len(command) != 2 || command[0] != "echo" || command[1] != "hello" {
		t.Errorf("command = %v, want [echo hello]", command)
	}

	// Verify rule structure
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(raw["rules"], &rules); err != nil {
		t.Fatalf("unmarshal rules: %v", err)
	}

	// First rule: filesystem rule
	allowedRuleKeys := map[string]bool{
		"name": true, "patterns": true, "except": true,
		"operations": true, "hosts": true,
	}
	for _, rule := range rules {
		for key := range rule {
			if !allowedRuleKeys[key] {
				t.Errorf("SECURITY: unexpected key %q in deny rule (Rust uses deny_unknown_fields)", key)
			}
		}
	}
}

// ==================== Sandbox Overhead Benchmarks (require Rust binary) ====================

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

// truncate truncates a string to maxLen characters.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// TestSandboxCostReport runs both valid and malicious commands and prints a cost report.
// Measures Rust sandbox overhead per command type.
// Run with: go test -v -tags=sandbox_e2e -run TestSandboxCostReport ./internal/sandbox/
func TestSandboxCostReport(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported: bakelens-sandbox binary not found")
	}

	helperPath := setupBakelensSandboxPath(t)
	t.Logf("Using bakelens-sandbox helper: %s", helperPath)

	restore := suppressOutput()

	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	var blockRules int
	for _, r := range builtinRules {
		if r.IsEnabled() {
			blockRules++
		}
	}

	var secRules []SecurityRule
	for i := range builtinRules {
		if builtinRules[i].IsEnabled() {
			secRules = append(secRules, &builtinRules[i])
		}
	}
	SetRules(secRules)
	sb := New()

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

	commands := []commandTiming{
		{name: "echo hello", category: "valid", cmd: []string{"echo", "hello"}},
		{name: "ls /tmp", category: "valid", cmd: []string{"ls", "/tmp"}},
		{name: "true", category: "valid", cmd: []string{"true"}},
		{name: "cat /etc/hostname", category: "valid", cmd: []string{"cat", "/etc/hostname"}},
		{name: "pwd", category: "valid", cmd: []string{"pwd"}},
		{name: "cat .env", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".env")}},
		{name: "cat .ssh/id_rsa", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".ssh/id_rsa")}},
		{name: "cat .ssh/id_ed25519", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, ".ssh/id_ed25519")}},
		{name: "cat credentials.json", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, "credentials.json")}},
		{name: "cat secrets.yaml", category: "malicious", cmd: []string{"cat", filepath.Join(fixtureDir, "secrets.yaml")}},
		{name: "cat /proc/1/cmdline", category: "malicious", cmd: []string{"cat", "/proc/1/cmdline"}},
	}

	const iterations = 50

	for i := range commands {
		cmd := &commands[i]
		cmd.samples = make([]time.Duration, iterations)

		exitCode, err := sb.Wrap(cmd.cmd)
		if err != nil {
			t.Fatalf("Wrap failed for %q: %v", cmd.name, err)
		}
		_ = exitCode

		for j := range iterations {
			start := time.Now()
			_, _ = sb.Wrap(cmd.cmd)
			cmd.samples[j] = time.Since(start)
		}

		slices.Sort(cmd.samples)
		cmd.min = cmd.samples[0]
		cmd.max = cmd.samples[len(cmd.samples)-1]

		var total time.Duration
		for _, s := range cmd.samples {
			total += s
		}
		cmd.mean = total / time.Duration(len(cmd.samples))
	}

	var bareMean time.Duration
	{
		samples := make([]time.Duration, iterations)
		for j := range iterations {
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

	restore()

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                        SANDBOX COST REPORT                                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Platform: %-67s ║\n", Platform())
	fmt.Printf("║ Block Rules Loaded: %-57d ║\n", blockRules)
	fmt.Printf("║ Iterations per Command: %-53d ║\n", iterations)
	fmt.Printf("║ Bare Execution (no sandbox): %-48s ║\n", bareMean.String())
	fmt.Println("╠══════════════════════════════════════════════════════════════════════════════╣")

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
	fmt.Println("╚══════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// BenchmarkCommandExecution benchmarks actual command execution.
// Compares execution with and without sandbox wrapper to measure Rust overhead.
func BenchmarkCommandExecution(b *testing.B) {
	b.ReportAllocs()
	if !IsSupported() {
		b.Skip("Sandbox not supported: bakelens-sandbox binary not found")
	}

	setupBakelensSandboxPath(b)

	restore := suppressOutput()
	defer restore()

	loader := rules.NewLoader("")
	builtinRules, _ := loader.LoadBuiltin()
	var secRules []SecurityRule
	for i := range builtinRules {
		if builtinRules[i].IsEnabled() {
			secRules = append(secRules, &builtinRules[i])
		}
	}
	SetRules(secRules)

	sb := New()

	b.Run("without_sandbox", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			cmd := exec.Command("echo", "hello")
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			_ = cmd.Run()
		}
	})

	b.Run("with_sandbox_all_rules", func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			_, _ = sb.Wrap([]string{"echo", "hello"})
		}
	})
}

// BenchmarkAllBuiltinRules benchmarks sandbox with all builtin rules loaded.
// Measures Rust overhead for both valid and malicious commands.
func BenchmarkAllBuiltinRules(b *testing.B) {
	b.ReportAllocs()
	if !IsSupported() {
		b.Skip("Sandbox not supported: bakelens-sandbox binary not found")
	}

	setupBakelensSandboxPath(b)

	restore := suppressOutput()
	defer restore()

	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	var secRules []SecurityRule
	for i := range builtinRules {
		if builtinRules[i].IsEnabled() {
			secRules = append(secRules, &builtinRules[i])
		}
	}
	SetRules(secRules)
	sb := New()

	validCmds := []struct {
		name string
		cmd  []string
	}{
		{"valid_echo", []string{"echo", "hello"}},
		{"valid_ls_tmp", []string{"ls", "/tmp"}},
		{"valid_true", []string{"true"}},
	}

	for _, tc := range validCmds {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_, _ = sb.Wrap(tc.cmd)
			}
		})
	}

	maliciousCmds := []struct {
		name string
		cmd  []string
	}{
		{"malicious_cat_env", []string{"cat", ".env"}},
		{"malicious_cat_ssh", []string{"cat", "/root/.ssh/id_rsa"}},
		{"malicious_ls_passwd", []string{"ls", "/etc/passwd"}},
	}

	for _, tc := range maliciousCmds {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_, _ = sb.Wrap(tc.cmd)
			}
		})
	}
}
