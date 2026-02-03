package rules

import (
	"encoding/json"
)

// MatchResult represents the result of evaluating a rule
type MatchResult struct {
	Matched      bool   `json:"matched"`
	RuleName     string `json:"rule_name,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Action       string `json:"action,omitempty"` // block, log, alert
	Message      string `json:"message,omitempty"`
	AlertWebhook string `json:"alert_webhook,omitempty"`
}

// ToolCall represents a tool call to be evaluated
type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// Severity levels
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Action types
const (
	ActionBlock = "block"
	ActionLog   = "log"
	ActionAlert = "alert"
)

// Rule sources
const (
	SourceBuiltin = "builtin"
	SourceUser    = "user"
	SourceCLI     = "cli"
)
