package sandbox

import (
	"fmt"
	"strings"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

// ConsistencyError represents a rule-mapping inconsistency.
type ConsistencyError struct {
	MissingInSandbox []string // Rules without sandbox mapping
	OrphanedMappings []string // Sandbox entries without rules
}

func (e *ConsistencyError) Error() string {
	var parts []string
	if len(e.MissingInSandbox) > 0 {
		parts = append(parts, fmt.Sprintf("missing mappings: %v", e.MissingInSandbox))
	}
	if len(e.OrphanedMappings) > 0 {
		parts = append(parts, fmt.Sprintf("orphaned mappings: %v", e.OrphanedMappings))
	}
	return strings.Join(parts, "; ")
}

// HasErrors returns true if there are any consistency errors.
func (e *ConsistencyError) HasErrors() bool {
	return len(e.MissingInSandbox) > 0 || len(e.OrphanedMappings) > 0
}

// CheckConsistency verifies path-based rules and sandbox profile are in sync.
func (m *Mapper) CheckConsistency(pbRules []rules.Rule) *ConsistencyError {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Build set of rule names that should have mappings
	expectedRules := make(map[string]bool)
	for _, rule := range pbRules {
		if rule.IsEnabled() && len(rule.Block.Paths) > 0 {
			expectedRules[rule.Name] = true
		}
	}

	// Check for missing mappings
	var missing []string
	for name := range expectedRules {
		if _, ok := m.mappings[name]; !ok {
			missing = append(missing, name)
		}
	}

	// Check for orphaned mappings
	var orphaned []string
	for name := range m.mappings {
		if !expectedRules[name] {
			orphaned = append(orphaned, name)
		}
	}

	if len(missing) > 0 || len(orphaned) > 0 {
		return &ConsistencyError{
			MissingInSandbox: missing,
			OrphanedMappings: orphaned,
		}
	}

	return nil
}

// Repair fixes inconsistencies by regenerating from path-based rules.
func (m *Mapper) Repair(pbRules []rules.Rule) error {
	m.mu.Lock()

	// Clear existing mappings
	m.mappings = make(map[string]string)

	// Regenerate from rules
	for _, rule := range pbRules {
		if !rule.IsEnabled() {
			continue
		}

		directives := TranslateRule(rule)
		if len(directives) > 0 {
			var buf strings.Builder
			for _, d := range directives {
				buf.WriteString(d.String())
				buf.WriteString("\n")
			}
			m.mappings[rule.Name] = buf.String()
		}
	}

	m.mu.Unlock()

	return m.writeProfile()
}

// Sync synchronizes the sandbox profile with path-based rules.
func (m *Mapper) Sync(pbRules []rules.Rule) error {
	if err := m.CheckConsistency(pbRules); err != nil {
		return m.Repair(pbRules)
	}
	return nil
}

// RuleCount returns the number of rules currently mapped.
func (m *Mapper) RuleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.mappings)
}

// HasRule checks if a rule is currently mapped.
func (m *Mapper) HasRule(ruleName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.mappings[ruleName]
	return ok
}

// GetRuleDirectives returns the sandbox directives for a specific rule.
func (m *Mapper) GetRuleDirectives(ruleName string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	directives, ok := m.mappings[ruleName]
	return directives, ok
}
