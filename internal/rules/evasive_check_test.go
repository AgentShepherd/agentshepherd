package rules

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestEvasiveMarkingOnSecondaryFields(t *testing.T) {
	ext := NewExtractor()

	cases := []struct {
		name        string
		toolName    string
		args        map[string]any
		wantEvasive bool
	}{
		{
			name:        "safe command + broken script (unclosed quote)",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo safe", "script": "this has an unclosed 'quote"},
			wantEvasive: false, // expectation: should NOT be evasive if at least one field parses
		},
		{
			name:        "safe command only",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo hello"},
			wantEvasive: false,
		},
		{
			name:        "natural language in script field",
			toolName:    "build_tool",
			args:        map[string]any{"script": "Build the project using make install"},
			wantEvasive: false, // permissive parser treats this as valid commands
		},
		{
			name:        "text starting with shell keyword if",
			toolName:    "helper",
			args:        map[string]any{"script": "if you want to delete, use rm"},
			wantEvasive: true, // incomplete if/then block fails parser — expected
		},
		{
			name:        "safe command + text starting with if keyword",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo safe", "script": "if you want to delete, use rm"},
			wantEvasive: false, // should NOT be evasive — first field parsed successfully
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argsJSON, _ := json.Marshal(tc.args)
			info := ext.Extract(tc.toolName, argsJSON)
			fmt.Printf("  %s: Evasive=%v Reason=%q Op=%v\n", tc.name, info.Evasive, info.EvasiveReason, info.Operation)
			if info.Evasive != tc.wantEvasive {
				t.Errorf("Evasive = %v, want %v (reason: %s)", info.Evasive, tc.wantEvasive, info.EvasiveReason)
			}
		})
	}
}
