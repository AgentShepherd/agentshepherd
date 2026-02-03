package sandbox

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

func TestCheckConsistency_AllMapped(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	allRules := []rules.Rule{
		{
			Name:       "rule-one",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.env"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
		{
			Name:       "rule-two",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.ssh/*"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
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
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	rule1 := rules.Rule{
		Name:       "rule-one",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.env"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(rule1)

	allRules := []rules.Rule{
		rule1,
		{
			Name:       "rule-two",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.ssh/*"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
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
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	rule1 := rules.Rule{
		Name:       "rule-one",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.env"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	rule2 := rules.Rule{
		Name:       "rule-two",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.ssh/*"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(rule1)
	_ = mapper.AddRule(rule2)

	// But only claim one rule exists
	allRules := []rules.Rule{rule1}

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
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	disabled := false
	rule1 := rules.Rule{
		Name:       "enabled-rule",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.env"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(rule1)

	allRules := []rules.Rule{
		rule1,
		{
			Name:       "disabled-rule",
			Enabled:    &disabled,
			Block:      rules.Block{Paths: []string{"**/.secret"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
	}

	err := mapper.CheckConsistency(allRules)
	if err != nil {
		t.Errorf("disabled rules should be ignored: %v", err)
	}
}

func TestRepair(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	orphanRule := rules.Rule{
		Name:       "orphan-rule",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.old"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(orphanRule)

	allRules := []rules.Rule{
		{
			Name:       "rule-one",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.env"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
		},
		{
			Name:       "rule-two",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.ssh/*"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
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
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	rule := rules.Rule{
		Name:       "test-rule",
		Enabled:    &enabled,
		Block:      rules.Block{Paths: []string{"**/.env"}},
		Operations: []rules.Operation{rules.OpRead},
		Message:    "test",
	}
	_ = mapper.AddRule(rule)

	err := mapper.Repair([]rules.Rule{})
	if err != nil {
		t.Fatalf("Repair with empty rules failed: %v", err)
	}

	if mapper.RuleCount() != 0 {
		t.Errorf("expected 0 rules after repair with empty set, got %d", mapper.RuleCount())
	}
}

func TestSync(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	enabled := true
	allRules := []rules.Rule{
		{
			Name:       "rule-one",
			Enabled:    &enabled,
			Block:      rules.Block{Paths: []string{"**/.env"}},
			Operations: []rules.Operation{rules.OpRead},
			Message:    "test",
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
