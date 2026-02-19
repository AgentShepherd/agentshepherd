package sandbox

import (
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// BenchmarkSandboxPolicyGeneration benchmarks sandbox policy creation via buildDenyRulesFrom.
func BenchmarkSandboxPolicyGeneration(b *testing.B) {
	b.ReportAllocs()
	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		b.Fatalf("Failed to load rules: %v", err)
	}

	var secRules []SecurityRule
	for i := range builtinRules {
		if builtinRules[i].IsEnabled() {
			secRules = append(secRules, &builtinRules[i])
		}
	}

	for b.Loop() {
		_, _ = buildDenyRulesFrom(secRules)
	}
}

// BenchmarkBuildDenyRules benchmarks converting SecurityRules to DenyRuleJSON.
func BenchmarkBuildDenyRules(b *testing.B) {
	b.ReportAllocs()
	allRules := []SecurityRule{
		&testRule{
			name:       "env-files",
			paths:      []string{"**/.env", "**/.env.*"},
			except:     []string{"**/.env.example"},
			operations: []string{"read"},
		},
		&testRule{
			name:       "ssh-keys",
			paths:      []string{"~/.ssh/id_*", "~/.ssh/authorized_keys"},
			operations: []string{"read", "write"},
		},
		&testRule{
			name:       "system-files",
			paths:      []string{"/etc/shadow", "/etc/passwd"},
			operations: []string{"read", "write", "delete"},
		},
	}

	for b.Loop() {
		_, _ = buildDenyRulesFrom(allRules)
	}
}
