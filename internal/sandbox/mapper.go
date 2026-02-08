package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	profileHeader = `; Crust Sandbox Profile
; Auto-generated - do not edit manually
(version 1)
(allow default)

`
	ruleStartMarker = "; --- RULE: %s ---"
	ruleEndMarker   = "; --- END RULE: %s ---"
)

// Mapper maintains the dynamic mapping between rules and sandbox directives.
type Mapper struct {
	profilePath string
	mu          sync.RWMutex
	mappings    map[string]string // ruleName → sandbox directives
}

// NewMapper creates a new Mapper.
func NewMapper(profilePath string) *Mapper {
	return &Mapper{
		profilePath: profilePath,
		mappings:    make(map[string]string),
	}
}

// DefaultProfilePath returns the default sandbox profile path.
func DefaultProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp" // Fallback if home dir unavailable
	}
	return filepath.Join(home, ".crust", "sandbox.sb")
}

// ProfilePath returns the path to the sandbox profile.
func (m *Mapper) ProfilePath() string {
	return m.profilePath
}

// AddRule adds or updates a path-based rule mapping.
func (m *Mapper) AddRule(rule SecurityRule) error {
	if !rule.IsEnabled() {
		return nil
	}

	directives := TranslateRule(rule)
	if len(directives) == 0 {
		return nil
	}

	var buf strings.Builder
	for _, d := range directives {
		buf.WriteString(d.String())
		buf.WriteString("\n")
	}

	m.mu.Lock()
	m.mappings[rule.GetName()] = buf.String()
	m.mu.Unlock()

	return m.writeProfile()
}

// RemoveRule removes a rule mapping.
func (m *Mapper) RemoveRule(ruleName string) error {
	m.mu.Lock()
	delete(m.mappings, ruleName)
	m.mu.Unlock()

	return m.writeProfile()
}

// GetMappings returns a copy of current mappings.
func (m *Mapper) GetMappings() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]string, len(m.mappings))
	for k, v := range m.mappings {
		result[k] = v
	}
	return result
}

// writeProfile writes the complete sandbox profile to disk atomically.
func (m *Mapper) writeProfile() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Ensure directory exists
	dir := filepath.Dir(m.profilePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(profileHeader)

	// Write each rule section with markers
	for ruleName, directives := range m.mappings {
		safeName := sanitizeRuleName(ruleName)
		buf.WriteString(fmt.Sprintf(ruleStartMarker, safeName))
		buf.WriteString("\n")
		buf.WriteString(directives)
		buf.WriteString(fmt.Sprintf(ruleEndMarker, safeName))
		buf.WriteString("\n\n")
	}

	// Atomic write: write to temp file, then rename
	tempPath := m.profilePath + ".tmp"
	if err := os.WriteFile(tempPath, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write temp profile: %w", err)
	}

	if err := os.Rename(tempPath, m.profilePath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename profile: %w", err)
	}

	return nil
}

// LoadFromFile loads existing mappings from the profile file.
func (m *Mapper) LoadFromFile() error {
	data, err := os.ReadFile(m.profilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return m.parseRuleSections(string(data))
}

// parseRuleSections parses rule sections from a profile string.
func (m *Mapper) parseRuleSections(profile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.mappings = make(map[string]string)

	startPattern := regexp.MustCompile(`; --- RULE: ([^\s]+) ---`)
	lines := strings.Split(profile, "\n")

	var currentRule string
	var currentDirectives strings.Builder

	for _, line := range lines {
		if matches := startPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentRule = matches[1]
			currentDirectives.Reset()
		} else if strings.HasPrefix(line, "; --- END RULE:") {
			if currentRule != "" {
				m.mappings[currentRule] = currentDirectives.String()
			}
			currentRule = ""
		} else if currentRule != "" && strings.HasPrefix(line, "(deny ") {
			currentDirectives.WriteString(line)
			currentDirectives.WriteString("\n")
		}
	}

	return nil
}

// GetProfile returns the current profile content.
func (m *Mapper) GetProfile() ([]byte, error) {
	return os.ReadFile(m.profilePath)
}

// GenerateProfileContent generates the profile content without writing to disk.
func (m *Mapper) GenerateProfileContent() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var buf bytes.Buffer
	buf.WriteString(profileHeader)

	for ruleName, directives := range m.mappings {
		safeName := sanitizeRuleName(ruleName)
		buf.WriteString(fmt.Sprintf(ruleStartMarker, safeName))
		buf.WriteString("\n")
		buf.WriteString(directives)
		buf.WriteString(fmt.Sprintf(ruleEndMarker, safeName))
		buf.WriteString("\n\n")
	}

	return buf.String()
}

// sanitizeRuleName strips characters that could inject Seatbelt profile directives.
func sanitizeRuleName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == '\n', r == '\r', r == ';', r == '(', r == ')', r == '"', r == '#':
			continue
		case r == utf8.RuneError:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

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
func (m *Mapper) CheckConsistency(pbRules []SecurityRule) *ConsistencyError {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Build set of rule names that should have mappings
	expectedRules := make(map[string]bool)
	for _, rule := range pbRules {
		if rule.IsEnabled() && len(rule.GetBlockPaths()) > 0 {
			expectedRules[rule.GetName()] = true
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
func (m *Mapper) Repair(pbRules []SecurityRule) error {
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
			m.mappings[rule.GetName()] = buf.String()
		}
	}

	m.mu.Unlock()

	return m.writeProfile()
}

// Sync synchronizes the sandbox profile with path-based rules.
func (m *Mapper) Sync(pbRules []SecurityRule) error {
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
