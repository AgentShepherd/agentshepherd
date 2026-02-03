package rules

import (
	"testing"
)

// TestBuiltinRulesLoad verifies builtin security rules can be loaded.
// Tests rule: protect-env-files
// Tests rule: protect-ssh-keys
// Tests rule: protect-agentshepherd
// Tests rule: protect-shell-history
// Tests rule: protect-cloud-credentials
// Tests rule: protect-gpg-keys
// Tests rule: protect-browser-data
// Tests rule: protect-git-credentials
// Tests rule: protect-package-tokens
// Tests rule: protect-shell-rc
// Tests rule: protect-ssh-authorized-keys
// Tests rule: detect-private-key-write
func TestBuiltinRulesLoad(t *testing.T) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	if len(rules) == 0 {
		t.Error("Expected at least one builtin rule")
	}

	// Check for critical security rules for personal users
	expectedRules := []string{
		"protect-env-files",
		"protect-ssh-keys",
		"protect-agentshepherd",
		"protect-shell-history",
		"protect-cloud-credentials",
		"protect-gpg-keys",
		"protect-browser-data",
		"protect-git-credentials",
		"protect-package-tokens",
		"protect-shell-rc",
		"protect-ssh-authorized-keys",
		"detect-private-key-write",
	}

	ruleNames := make(map[string]bool)
	for _, r := range rules {
		ruleNames[r.Name] = true
	}

	for _, name := range expectedRules {
		if !ruleNames[name] {
			t.Errorf("Missing expected builtin rule: %s", name)
		}
	}

	t.Logf("Loaded %d builtin rules", len(rules))
}
