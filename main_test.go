package main

import (
	"encoding/json"
	"testing"
)

func TestRuleInfoUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantName string
		wantOps  int
		wantErr  bool
	}{
		{
			name: "simple rule",
			jsonData: `{
				"name": "protect-env-files",
				"message": "Cannot access .env files",
				"operations": ["read", "write"],
				"block": {"paths": ["**/.env"]}
			}`,
			wantName: "protect-env-files",
			wantOps:  2,
			wantErr:  false,
		},
		{
			name: "rule with exceptions",
			jsonData: `{
				"name": "protect-ssh-keys",
				"message": "Cannot access SSH keys",
				"operations": ["read"],
				"block": {
					"paths": ["**/.ssh/id_*"],
					"except": ["**/.ssh/id_*.pub"]
				}
			}`,
			wantName: "protect-ssh-keys",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with match",
			jsonData: `{
				"name": "block-crontab",
				"message": "Cannot edit crontab",
				"operations": ["execute"],
				"block": {},
				"match": {
					"command": "re:crontab\\s+-e"
				}
			}`,
			wantName: "block-crontab",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with content match",
			jsonData: `{
				"name": "detect-private-key",
				"message": "Private key detected",
				"operations": ["write"],
				"block": {},
				"match": {
					"content": "re:-----BEGIN.*PRIVATE KEY-----"
				}
			}`,
			wantName: "detect-private-key",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with all conditions",
			jsonData: `{
				"name": "composite-rule",
				"message": "Blocked",
				"operations": ["execute"],
				"block": {},
				"all_conditions": [
					{"path": "/etc/**"},
					{"command": "re:ln\\s+-s"}
				]
			}`,
			wantName: "composite-rule",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with enabled pointer nil",
			jsonData: `{
				"name": "enabled-default",
				"message": "Test",
				"operations": ["read"],
				"block": {"paths": ["/test"]}
			}`,
			wantName: "enabled-default",
			wantOps:  1,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ri ruleInfo
			err := json.Unmarshal([]byte(tt.jsonData), &ri)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if ri.Name != tt.wantName {
				t.Errorf("name = %q, want %q", ri.Name, tt.wantName)
			}

			if len(ri.Operations) != tt.wantOps {
				t.Errorf("operations count = %d, want %d", len(ri.Operations), tt.wantOps)
			}
		})
	}
}

func TestRuleInfoEnabled(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		wantEnabled bool
	}{
		{
			name:        "enabled nil (default true)",
			jsonData:    `{"name": "test", "operations": ["read"], "block": {}}`,
			wantEnabled: true,
		},
		{
			name:        "enabled true",
			jsonData:    `{"name": "test", "enabled": true, "operations": ["read"], "block": {}}`,
			wantEnabled: true,
		},
		{
			name:        "enabled false",
			jsonData:    `{"name": "test", "enabled": false, "operations": ["read"], "block": {}}`,
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ri ruleInfo
			if err := json.Unmarshal([]byte(tt.jsonData), &ri); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			// Check enabled status (nil means true)
			enabled := ri.Enabled == nil || *ri.Enabled
			if enabled != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, tt.wantEnabled)
			}
		})
	}
}

func TestRuleBlockFields(t *testing.T) {
	jsonData := `{
		"name": "test-rule",
		"message": "Test",
		"operations": ["read", "write", "delete"],
		"block": {
			"paths": ["/path/one", "/path/two"],
			"except": ["/path/one/allowed"],
			"hosts": ["example.com"]
		}
	}`

	var ri ruleInfo
	if err := json.Unmarshal([]byte(jsonData), &ri); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(ri.Block.Paths) != 2 {
		t.Errorf("paths count = %d, want 2", len(ri.Block.Paths))
	}

	if len(ri.Block.Except) != 1 {
		t.Errorf("except count = %d, want 1", len(ri.Block.Except))
	}

	if len(ri.Block.Hosts) != 1 {
		t.Errorf("hosts count = %d, want 1", len(ri.Block.Hosts))
	}
}

func TestRuleMatchFields(t *testing.T) {
	jsonData := `{
		"name": "test-match",
		"message": "Test",
		"operations": ["execute"],
		"block": {},
		"match": {
			"path": "/etc/**",
			"command": "re:rm\\s+-rf",
			"host": "evil.com",
			"content": "re:password",
			"tools": ["bash", "write"]
		}
	}`

	var ri ruleInfo
	if err := json.Unmarshal([]byte(jsonData), &ri); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if ri.Match == nil {
		t.Fatal("match is nil")
	}

	if ri.Match.Path != "/etc/**" {
		t.Errorf("match.path = %q, want %q", ri.Match.Path, "/etc/**")
	}

	if ri.Match.Command != "re:rm\\s+-rf" {
		t.Errorf("match.command = %q, want %q", ri.Match.Command, "re:rm\\s+-rf")
	}

	if ri.Match.Host != "evil.com" {
		t.Errorf("match.host = %q, want %q", ri.Match.Host, "evil.com")
	}

	if ri.Match.Content != "re:password" {
		t.Errorf("match.content = %q, want %q", ri.Match.Content, "re:password")
	}

	if len(ri.Match.Tools) != 2 {
		t.Errorf("match.tools count = %d, want 2", len(ri.Match.Tools))
	}
}

func TestRuleCompositeConditions(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantAll  int
		wantAny  int
	}{
		{
			name: "all conditions",
			jsonData: `{
				"name": "test",
				"message": "Test",
				"operations": ["execute"],
				"block": {},
				"all_conditions": [
					{"path": "/etc/**"},
					{"command": "re:ln"}
				]
			}`,
			wantAll: 2,
			wantAny: 0,
		},
		{
			name: "any conditions",
			jsonData: `{
				"name": "test",
				"message": "Test",
				"operations": ["execute"],
				"block": {},
				"any_conditions": [
					{"command": "re:curl.*-T"},
					{"command": "re:curl.*--upload"}
				]
			}`,
			wantAll: 0,
			wantAny: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ri ruleInfo
			if err := json.Unmarshal([]byte(tt.jsonData), &ri); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if len(ri.AllConditions) != tt.wantAll {
				t.Errorf("all_conditions count = %d, want %d", len(ri.AllConditions), tt.wantAll)
			}

			if len(ri.AnyConditions) != tt.wantAny {
				t.Errorf("any_conditions count = %d, want %d", len(ri.AnyConditions), tt.wantAny)
			}
		})
	}
}

func TestRulesResponseUnmarshal(t *testing.T) {
	jsonData := `{
		"total": 2,
		"rules": [
			{
				"name": "rule-one",
				"message": "Rule one",
				"operations": ["read"],
				"block": {"paths": ["/one"]}
			},
			{
				"name": "rule-two",
				"message": "Rule two",
				"operations": ["write"],
				"block": {"paths": ["/two"]}
			}
		]
	}`

	var resp rulesResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Total != 2 {
		t.Errorf("total = %d, want 2", resp.Total)
	}

	if len(resp.Rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(resp.Rules))
	}

	if resp.Rules[0].Name != "rule-one" {
		t.Errorf("rules[0].name = %q, want %q", resp.Rules[0].Name, "rule-one")
	}
}
