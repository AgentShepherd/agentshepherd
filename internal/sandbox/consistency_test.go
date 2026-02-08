package sandbox

import (
	"strings"
	"testing"
)

func TestCheckConsistency_AllMapped(t *testing.T) {
	mapper := newTestMapper(t)

	allRules := []SecurityRule{
		&testRule{
			name:       "rule-one",
			enabled:    &boolTrue,
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
		&testRule{
			name:       "rule-two",
			enabled:    &boolTrue,
			paths:      []string{"**/.ssh/*"},
			operations: []string{"read"},
		},
	}

	for _, rule := range allRules {
		_ = mapper.AddRule(rule)
	}

	err := mapper.CheckConsistency(allRules)
	if err != nil {
		t.Errorf("expected no consistency error, got: %v", err)
	}
}

func TestCheckConsistency_MissingMappings(t *testing.T) {
	mapper := newTestMapper(t)

	rule1 := &testRule{
		name:       "rule-one",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule1)

	allRules := []SecurityRule{
		rule1,
		&testRule{
			name:       "rule-two",
			enabled:    &boolTrue,
			paths:      []string{"**/.ssh/*"},
			operations: []string{"read"},
		},
	}

	err := mapper.CheckConsistency(allRules)
	if err == nil {
		t.Fatal("expected consistency error for missing mapping")
	}

	if len(err.MissingInSandbox) != 1 {
		t.Errorf("expected 1 missing, got %d", len(err.MissingInSandbox))
	}
	if err.MissingInSandbox[0] != "rule-two" {
		t.Errorf("expected rule-two missing, got %s", err.MissingInSandbox[0])
	}
}

func TestCheckConsistency_OrphanedMappings(t *testing.T) {
	mapper := newTestMapper(t)

	rule1 := &testRule{
		name:       "rule-one",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	rule2 := &testRule{
		name:       "rule-two",
		enabled:    &boolTrue,
		paths:      []string{"**/.ssh/*"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule1)
	_ = mapper.AddRule(rule2)

	// But only claim one rule exists
	allRules := []SecurityRule{rule1}

	err := mapper.CheckConsistency(allRules)
	if err == nil {
		t.Fatal("expected consistency error for orphaned mapping")
	}

	if len(err.OrphanedMappings) != 1 {
		t.Errorf("expected 1 orphaned, got %d", len(err.OrphanedMappings))
	}
	if err.OrphanedMappings[0] != "rule-two" {
		t.Errorf("expected rule-two orphaned, got %s", err.OrphanedMappings[0])
	}
}

func TestCheckConsistency_IgnoresDisabledRules(t *testing.T) {
	mapper := newTestMapper(t)

	rule1 := &testRule{
		name:       "enabled-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule1)

	allRules := []SecurityRule{
		rule1,
		&testRule{
			name:       "disabled-rule",
			enabled:    &boolFalse,
			paths:      []string{"**/.secret"},
			operations: []string{"read"},
		},
	}

	err := mapper.CheckConsistency(allRules)
	if err != nil {
		t.Errorf("disabled rules should be ignored: %v", err)
	}
}

func TestRepair(t *testing.T) {
	mapper := newTestMapper(t)

	orphanRule := &testRule{
		name:       "orphan-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.old"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(orphanRule)

	allRules := []SecurityRule{
		&testRule{
			name:       "rule-one",
			enabled:    &boolTrue,
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
		&testRule{
			name:       "rule-two",
			enabled:    &boolTrue,
			paths:      []string{"**/.ssh/*"},
			operations: []string{"read"},
		},
	}

	err := mapper.Repair(allRules)
	if err != nil {
		t.Fatalf("Repair failed: %v", err)
	}

	if mapper.HasRule("orphan-rule") {
		t.Error("orphan-rule should be removed after repair")
	}

	if !mapper.HasRule("rule-one") {
		t.Error("rule-one should be present after repair")
	}
	if !mapper.HasRule("rule-two") {
		t.Error("rule-two should be present after repair")
	}

	consistErr := mapper.CheckConsistency(allRules)
	if consistErr != nil {
		t.Errorf("should be consistent after repair: %v", consistErr)
	}
}

func TestRepair_EmptyRules(t *testing.T) {
	mapper := newTestMapper(t)

	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule)

	err := mapper.Repair([]SecurityRule{})
	if err != nil {
		t.Fatalf("Repair with empty rules failed: %v", err)
	}

	if mapper.RuleCount() != 0 {
		t.Errorf("expected 0 rules after repair with empty set, got %d", mapper.RuleCount())
	}
}

func TestSync(t *testing.T) {
	mapper := newTestMapper(t)

	allRules := []SecurityRule{
		&testRule{
			name:       "rule-one",
			enabled:    &boolTrue,
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
	}

	err := mapper.Sync(allRules)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if !mapper.HasRule("rule-one") {
		t.Error("rule-one should be present after sync")
	}
}

func TestSync_AlreadyConsistent(t *testing.T) {
	mapper := newTestMapper(t)

	allRules := []SecurityRule{
		&testRule{
			name:       "rule-one",
			enabled:    &boolTrue,
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
	}

	// Add rules first so mapper is consistent
	for _, r := range allRules {
		_ = mapper.AddRule(r)
	}

	// Sync on already-consistent state should return nil without calling Repair
	err := mapper.Sync(allRules)
	if err != nil {
		t.Errorf("Sync on consistent state should return nil, got: %v", err)
	}
}

func TestRepair_DisabledRules(t *testing.T) {
	mapper := newTestMapper(t)

	allRules := []SecurityRule{
		&testRule{
			name:       "enabled-rule",
			enabled:    &boolTrue,
			paths:      []string{"**/.env"},
			operations: []string{"read"},
		},
		&testRule{
			name:       "disabled-rule",
			enabled:    &boolFalse,
			paths:      []string{"**/.secret"},
			operations: []string{"read"},
		},
	}

	err := mapper.Repair(allRules)
	if err != nil {
		t.Fatalf("Repair failed: %v", err)
	}

	if !mapper.HasRule("enabled-rule") {
		t.Error("enabled-rule should be present after repair")
	}
	if mapper.HasRule("disabled-rule") {
		t.Error("disabled-rule should be skipped during repair")
	}
}

func TestConsistencyError_Error(t *testing.T) {
	err := &ConsistencyError{
		MissingInSandbox: []string{"rule-a", "rule-b"},
		OrphanedMappings: []string{"rule-c"},
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "missing mappings") {
		t.Error("error should mention missing mappings")
	}
	if !strings.Contains(errStr, "orphaned mappings") {
		t.Error("error should mention orphaned mappings")
	}
	if !strings.Contains(errStr, "rule-a") {
		t.Error("error should contain rule names")
	}
}

func TestConsistencyError_HasErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConsistencyError
		expected bool
	}{
		{
			name:     "no errors",
			err:      &ConsistencyError{},
			expected: false,
		},
		{
			name: "has missing",
			err: &ConsistencyError{
				MissingInSandbox: []string{"rule-a"},
			},
			expected: true,
		},
		{
			name: "has orphaned",
			err: &ConsistencyError{
				OrphanedMappings: []string{"rule-b"},
			},
			expected: true,
		},
		{
			name: "has both",
			err: &ConsistencyError{
				MissingInSandbox: []string{"rule-a"},
				OrphanedMappings: []string{"rule-b"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.HasErrors() != tt.expected {
				t.Errorf("HasErrors() = %v, expected %v", tt.err.HasErrors(), tt.expected)
			}
		})
	}
}
