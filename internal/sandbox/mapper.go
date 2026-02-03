package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

const (
	profileHeader = `; AgentShepherd Sandbox Profile
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
	return filepath.Join(home, ".agentshepherd", "sandbox.sb")
}

// ProfilePath returns the path to the sandbox profile.
func (m *Mapper) ProfilePath() string {
	return m.profilePath
}

// AddRule adds or updates a path-based rule mapping.
func (m *Mapper) AddRule(rule rules.Rule) error {
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
	m.mappings[rule.Name] = buf.String()
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
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create profile directory: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteString(profileHeader)

	// Write each rule section with markers
	for ruleName, directives := range m.mappings {
		buf.WriteString(fmt.Sprintf(ruleStartMarker, ruleName))
		buf.WriteString("\n")
		buf.WriteString(directives)
		buf.WriteString(fmt.Sprintf(ruleEndMarker, ruleName))
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
		buf.WriteString(fmt.Sprintf(ruleStartMarker, ruleName))
		buf.WriteString("\n")
		buf.WriteString(directives)
		buf.WriteString(fmt.Sprintf(ruleEndMarker, ruleName))
		buf.WriteString("\n\n")
	}

	return buf.String()
}

// ProfileTemplate is for advanced profile generation.
var ProfileTemplate = template.Must(template.New("sandbox").Parse(`
; AgentShepherd Sandbox Profile
; Generated for: {{ .Platform }}
(version 1)
(allow default)

{{- range .Rules }}
; --- RULE: {{ .Name }} ---
{{ .Directives }}
; --- END RULE: {{ .Name }} ---
{{- end }}
`))
