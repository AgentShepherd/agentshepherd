package sandbox

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestContainsGlob(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{".env", false},
		{"id_*", true},
		{"file?.txt", true},
		{"[abc]", true},
		{"credentials", false},
		{"**", true},
		{"", false},
		{"normal.file.name", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := containsGlob(tt.input)
			if got != tt.want {
				t.Errorf("containsGlob(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// SECURITY: Policy JSON has deny_unknown_fields protection via version validation.
// The Rust side uses #[serde(deny_unknown_fields)] and validates version == 1.
func TestBuildPolicy_VersionFieldValidation(t *testing.T) {
	origRules := getRules()
	defer func() { SetRules(origRules) }()
	SetRules(nil)

	policyJSON, err := buildPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	var policy PolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if policy.Version != 1 {
		t.Errorf("SECURITY: policy version must be 1 (Rust side uses deny_unknown_fields + version check), got %d", policy.Version)
	}
}

// Test that buildPolicy includes deny rules from SecurityRules.
func TestBuildPolicy_IncludesDenyRules(t *testing.T) {
	origRules := getRules()
	defer func() { SetRules(origRules) }()

	SetRules([]SecurityRule{
		&testRule{
			name:       "block-env",
			paths:      []string{"**/.env*"},
			except:     []string{"**/.env.example"},
			operations: []string{"read", "write"},
		},
	})

	policyJSON, err := buildPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	var policy PolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 deny rule, got %d", len(policy.Rules))
	}
	dr := policy.Rules[0]
	if dr.Name != "block-env" {
		t.Errorf("deny rule name = %q, want %q", dr.Name, "block-env")
	}
	if len(dr.Patterns) != 1 || dr.Patterns[0] != "**/.env*" {
		t.Errorf("deny rule patterns = %v, want [**/.env*]", dr.Patterns)
	}
	if len(dr.Except) != 1 || dr.Except[0] != "**/.env.example" {
		t.Errorf("deny rule except = %v, want [**/.env.example]", dr.Except)
	}
	if len(dr.Operations) != 2 {
		t.Errorf("deny rule operations = %v, want [read write]", dr.Operations)
	}
}

// Test that buildPolicy includes host entries inline in rules.
func TestBuildPolicy_IncludesHostEntries(t *testing.T) {
	origRules := getRules()
	defer func() { SetRules(origRules) }()

	SetRules([]SecurityRule{
		&testRule{
			name:  "block-ip",
			paths: []string{"**/.env"},
			hosts: []string{"127.0.0.1"},
		},
	})

	policyJSON, err := buildPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	var policy PolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(policy.Rules))
	}
	if len(policy.Rules[0].Hosts) != 1 {
		t.Fatalf("expected 1 host entry in rule, got %d", len(policy.Rules[0].Hosts))
	}
	he := policy.Rules[0].Hosts[0]
	if he.Name != "127.0.0.1" {
		t.Errorf("host name = %q, want %q", he.Name, "127.0.0.1")
	}
	if len(he.ResolvedIPs) != 1 || he.ResolvedIPs[0] != "127.0.0.1" {
		t.Errorf("resolved IPs = %v, want [127.0.0.1]", he.ResolvedIPs)
	}
}

// SECURITY: Policy JSON must not contain a "mode" field — Rust uses deny_unknown_fields.
func TestBuildPolicy_NoModeField(t *testing.T) {
	origRules := getRules()
	defer func() { SetRules(origRules) }()
	SetRules(nil)

	policyJSON, err := buildPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	if strings.Contains(string(policyJSON), `"mode"`) {
		t.Errorf("SECURITY: policy JSON must not contain mode field (Rust deny_unknown_fields), got: %s", policyJSON)
	}
}

// Rust requires "rules" to be present even when empty.
func TestBuildPolicy_EmptyRulesPresent(t *testing.T) {
	origRules := getRules()
	defer func() { SetRules(origRules) }()
	SetRules(nil)

	policyJSON, err := buildPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildPolicy() error: %v", err)
	}

	if !strings.Contains(string(policyJSON), `"rules":[]`) {
		t.Errorf("policy must contain \"rules\":[] when no rules are set, got: %s", policyJSON)
	}
}

// No-op rules (no filesystem ops and no network hosts) are skipped.
func TestBuildDenyRulesFrom_SkipsNoOpRules(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name: "no-paths-no-hosts",
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 rules (no-op), got %d", len(result))
	}
}

// Network-only rules (hosts without patterns) are valid.
func TestBuildDenyRulesFrom_NetworkOnlyRule(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:  "block-ip",
			hosts: []string{"127.0.0.1"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rule (network-only), got %d", len(result))
	}
	dr := result[0]
	if len(dr.Patterns) != 0 {
		t.Errorf("network-only rule should have no patterns, got %v", dr.Patterns)
	}
	if len(dr.Operations) != 0 {
		t.Errorf("network-only rule should have empty operations, got %v", dr.Operations)
	}
	if len(dr.Hosts) != 1 {
		t.Fatalf("expected 1 host entry, got %d", len(dr.Hosts))
	}
}

// Network-only rules with only "network" op should emit empty operations.
func TestBuildDenyRulesFrom_NetworkOpOnlyWithHosts(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:       "net-deny",
			operations: []string{"network"},
			hosts:      []string{"127.0.0.1"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if len(result[0].Operations) != 0 {
		t.Errorf("operations should be empty after filtering 'network', got %v", result[0].Operations)
	}
}

// Disabled rules must not appear in policy output.
func TestBuildDenyRulesFrom_SkipsDisabledRules(t *testing.T) {
	disabled := false
	rules := []SecurityRule{
		&testRule{
			name:    "disabled-rule",
			enabled: &disabled,
			paths:   []string{"**/.env"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 rules (disabled should be skipped), got %d", len(result))
	}
}

// Empty operations must be expanded to all filesystem operations (no "network").
func TestBuildDenyRulesFrom_DefaultsToAllFileOps(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:  "no-ops",
			paths: []string{"**/.env"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if len(result[0].Operations) != 6 {
		t.Errorf("expected 6 filesystem operations (no network), got %d: %v", len(result[0].Operations), result[0].Operations)
	}
	for _, op := range result[0].Operations {
		if op == "network" {
			t.Errorf("operations must not contain 'network', got %v", result[0].Operations)
		}
	}
}

// "network" in explicit operations must be filtered out before sending to Rust.
func TestBuildDenyRulesFrom_FiltersNetworkOp(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:       "mixed-ops",
			paths:      []string{"**/.env"},
			operations: []string{"read", "network", "write"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if len(result[0].Operations) != 2 {
		t.Errorf("expected 2 operations (read, write), got %d: %v", len(result[0].Operations), result[0].Operations)
	}
	for _, op := range result[0].Operations {
		if op == "network" {
			t.Errorf("operations must not contain 'network', got %v", result[0].Operations)
		}
	}
}

// Duplicate operations must be deduplicated.
func TestBuildDenyRulesFrom_DedupsOperations(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:       "dup-ops",
			paths:      []string{"**/.env"},
			operations: []string{"read", "write", "read"},
		},
	}

	result, err := buildDenyRulesFrom(rules)
	if err != nil {
		t.Fatalf("buildDenyRulesFrom() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}
	if len(result[0].Operations) != 2 {
		t.Errorf("expected 2 operations after dedup, got %d: %v", len(result[0].Operations), result[0].Operations)
	}
}

// Schema: name maxLength 128.
func TestBuildDenyRulesFrom_RejectsLongName(t *testing.T) {
	longName := strings.Repeat("x", 129)
	rules := []SecurityRule{
		&testRule{name: longName, paths: []string{"**/.env"}, operations: []string{"read"}},
	}
	_, err := buildDenyRulesFrom(rules)
	if err == nil {
		t.Fatal("expected error for name > 128 chars")
	}
}

// Schema: patterns maxItems 64.
func TestBuildDenyRulesFrom_RejectsTooManyPatterns(t *testing.T) {
	patterns := make([]string, 65)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("pattern-%d", i)
	}
	rules := []SecurityRule{
		&testRule{name: "many-patterns", paths: patterns, operations: []string{"read"}},
	}
	_, err := buildDenyRulesFrom(rules)
	if err == nil {
		t.Fatal("expected error for > 64 patterns")
	}
}

// Schema: pattern maxLength 512.
func TestBuildDenyRulesFrom_RejectsLongPattern(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:       "long-pattern",
			paths:      []string{strings.Repeat("a", 513)},
			operations: []string{"read"},
		},
	}
	_, err := buildDenyRulesFrom(rules)
	if err == nil {
		t.Fatal("expected error for pattern > 512 chars")
	}
}

// Duplicate rule names must be rejected.
func TestBuildDenyRulesFrom_RejectsDuplicateNames(t *testing.T) {
	rules := []SecurityRule{
		&testRule{
			name:       "same-name",
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
		&testRule{
			name:       "same-name",
			paths:      []string{"**/.ssh/id_*"},
			operations: []string{"read"},
		},
	}

	_, err := buildDenyRulesFrom(rules)
	if err == nil {
		t.Fatal("expected error for duplicate rule names, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention 'duplicate', got: %v", err)
	}
}
