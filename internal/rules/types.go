package rules

import (
	"encoding/json"
)

// MatchResult represents the result of evaluating a rule
type MatchResult struct {
	Matched      bool     `json:"matched"`
	RuleName     string   `json:"rule_name,omitempty"`
	Severity     Severity `json:"severity,omitempty"`
	Action       Action   `json:"action,omitempty"` // block, log, alert
	Message      string   `json:"message,omitempty"`
	AlertWebhook string   `json:"alert_webhook,omitempty"`
}

// ToolCall represents a tool call to be evaluated
type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Severity represents a rule severity level.
type Severity string

// Severity levels
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

// ValidSeverities is the set of all valid severity levels.
var ValidSeverities = map[Severity]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityWarning:  true,
	SeverityInfo:     true,
}

// Action represents a rule action type.
type Action string

// Action types
const (
	ActionBlock Action = "block"
	ActionLog   Action = "log"
	ActionAlert Action = "alert"
)

// Source represents the origin of a rule.
type Source string

// Rule sources
const (
	SourceBuiltin Source = "builtin"
	SourceUser    Source = "user"
	SourceCLI     Source = "cli"
)
