package rules

import (
	"errors"
	"fmt"
)

// Rule types for path-based security rules

// RuleSet represents a collection of rules from a YAML file
type RuleSet struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// Rule represents a security rule with path/host blocking
type Rule struct {
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     *bool       `yaml:"enabled,omitempty" json:"enabled,omitempty"`   // default true
	Priority    int         `yaml:"priority,omitempty" json:"priority,omitempty"` // lower = higher priority, default 50
	Block       Block       `yaml:"block" json:"block"`
	Operations  []Operation `yaml:"operations" json:"operations"`
	Message     string      `yaml:"message" json:"message"`
	Severity    string      `yaml:"severity,omitempty" json:"severity,omitempty"`

	// Advanced match (Level 4)
	Match *Match `yaml:"-" json:"match,omitempty"`

	// Composite conditions (Level 5)
	AllConditions []Match `yaml:"-" json:"all_conditions,omitempty"` // AND
	AnyConditions []Match `yaml:"-" json:"any_conditions,omitempty"` // OR

	// Runtime fields
	Source   string `yaml:"-" json:"source,omitempty"`
	FilePath string `yaml:"-" json:"file_path,omitempty"`
	HitCount int64  `yaml:"-" json:"hit_count,omitempty"` // number of times this rule matched
}

// Match represents a single match condition for advanced rules
type Match struct {
	Path    string   `json:"path,omitempty"`
	Command string   `json:"command,omitempty"`
	Host    string   `json:"host,omitempty"`
	Content string   `json:"content,omitempty"` // Pattern to match in Write/Edit content
	Tools   []string `json:"tools,omitempty"`
}

// Block defines what paths/hosts to block
type Block struct {
	Paths  []string `yaml:"paths,omitempty" json:"paths,omitempty"`   // glob patterns
	Except []string `yaml:"except,omitempty" json:"except,omitempty"` // exclusions
	Hosts  []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`   // for network ops
}

// Operation represents the type of file/network operation
type Operation string

const (
	OpRead    Operation = "read"
	OpWrite   Operation = "write"
	OpDelete  Operation = "delete"
	OpCopy    Operation = "copy"
	OpMove    Operation = "move"
	OpExecute Operation = "execute"
	OpNetwork Operation = "network"
)

// ValidOperations is the set of all valid operations
var ValidOperations = map[Operation]bool{
	OpRead:    true,
	OpWrite:   true,
	OpDelete:  true,
	OpCopy:    true,
	OpMove:    true,
	OpExecute: true,
	OpNetwork: true,
}

// Default values for rules
const (
	DefaultRulePriority = 50
	DefaultRuleSeverity = "critical"
)

// IsEnabled returns whether the rule is enabled (default true)
func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// GetPriority returns the rule priority (default 50)
func (r *Rule) GetPriority() int {
	if r.Priority == 0 {
		return DefaultRulePriority
	}
	return r.Priority
}

// GetSeverity returns the rule severity (default critical)
func (r *Rule) GetSeverity() string {
	if r.Severity == "" {
		return DefaultRuleSeverity
	}
	return r.Severity
}

// Validate checks if the rule is well-formed
func (r *Rule) Validate() error {
	if r.Name == "" {
		return errors.New("rule name is required")
	}

	if r.Message == "" {
		return errors.New("rule message is required")
	}

	if len(r.Operations) == 0 {
		return errors.New("at least one operation is required")
	}

	for _, op := range r.Operations {
		if !ValidOperations[op] {
			return fmt.Errorf("invalid operation: %s", op)
		}
	}

	// Check if rule has any matching criteria (simple block, advanced match, or composite)
	hasBlockPaths := len(r.Block.Paths) > 0
	hasBlockHosts := len(r.Block.Hosts) > 0
	hasMatch := r.Match != nil
	hasAllConditions := len(r.AllConditions) > 0
	hasAnyConditions := len(r.AnyConditions) > 0

	if !hasBlockPaths && !hasBlockHosts && !hasMatch && !hasAllConditions && !hasAnyConditions {
		return errors.New("block.paths, block.hosts, match, all, or any is required")
	}

	// Validate that hosts are only used with network operation (for simple block format)
	if hasBlockHosts {
		hasNetwork := false
		for _, op := range r.Operations {
			if op == OpNetwork {
				hasNetwork = true
				break
			}
		}
		if !hasNetwork {
			return errors.New("block.hosts requires 'network' operation")
		}
	}

	// Validate advanced match
	if hasMatch {
		if err := r.Match.Validate(); err != nil {
			return fmt.Errorf("match: %w", err)
		}
	}

	// Validate composite conditions
	for i, cond := range r.AllConditions {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("all[%d]: %w", i, err)
		}
	}
	for i, cond := range r.AnyConditions {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("any[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate checks if a Match condition has at least one field
func (m *Match) Validate() error {
	if m.Path == "" && m.Command == "" && m.Host == "" && m.Content == "" && len(m.Tools) == 0 {
		return errors.New("match must have at least one field (path, command, host, content, tools)")
	}
	return nil
}

// ValidateRuleSet validates all rules in a ruleset
func ValidateRuleSet(rs *RuleSet) error {
	if rs.Version != 1 {
		return fmt.Errorf("unsupported version: %d (expected 1)", rs.Version)
	}

	names := make(map[string]bool)
	for i, rule := range rs.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, rule.Name, err)
		}
		if names[rule.Name] {
			return fmt.Errorf("duplicate rule name: %s", rule.Name)
		}
		names[rule.Name] = true
	}

	return nil
}

// HasOperation checks if the rule applies to the given operation
func (r *Rule) HasOperation(op Operation) bool {
	for _, o := range r.Operations {
		if o == op {
			return true
		}
	}
	return false
}

// IsContentOnly returns true if this rule only matches on content (raw JSON)
// Content-only rules are evaluated for ALL tool calls regardless of operation
func (r *Rule) IsContentOnly() bool {
	// Must have Match with Content set
	if r.Match == nil || r.Match.Content == "" {
		return false
	}
	// Must not have other match conditions
	if r.Match.Path != "" || r.Match.Command != "" || r.Match.Host != "" || len(r.Match.Tools) > 0 {
		return false
	}
	// Must not have block paths/hosts
	if len(r.Block.Paths) > 0 || len(r.Block.Hosts) > 0 {
		return false
	}
	// Must not have composite conditions
	if len(r.AllConditions) > 0 || len(r.AnyConditions) > 0 {
		return false
	}
	return true
}
