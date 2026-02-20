package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ==================== Policy types (Go → Rust IPC) ====================
// Go sends a rules-mode policy to bakelens-sandbox via stdin.
// Rust builds the full platform-specific enforcement policy internally.

// PolicyJSON is the rules-mode policy sent to bakelens-sandbox via stdin.
// Go sends rules (with hosts); Rust builds the full enforcement policy.
// Fields must match Rust's InputPolicy exactly (deny_unknown_fields).
type PolicyJSON struct {
	Version int            `json:"version"`
	Command []string       `json:"command"`
	Rules   []DenyRuleJSON `json:"rules"`
}

// HostEntryJSON is a pre-resolved host entry for network deny rules.
// DNS resolution is done in Go; Rust only receives IP addresses.
type HostEntryJSON struct {
	Name        string   `json:"name"`
	ResolvedIPs []string `json:"resolved_ips"`
}

// DenyRuleJSON is a named deny rule with glob patterns, exceptions, and hosts.
// Filesystem deny is controlled by operations + patterns. Network deny is
// controlled by hosts. These are independent — a rule can have one or both.
type DenyRuleJSON struct {
	Name       string          `json:"name"`
	Patterns   []string        `json:"patterns,omitempty"`
	Except     []string        `json:"except,omitempty"`
	Operations []string        `json:"operations"`
	Hosts      []HostEntryJSON `json:"hosts,omitempty"`
}

// ==================== Rule storage (cross-platform) ====================

var (
	currentRulesMu sync.RWMutex
	currentRules   []SecurityRule
)

// SetRules stores rules for policy generation.
// Called from main.go after the rule engine is initialized and on reload.
func SetRules(allRules []SecurityRule) {
	currentRulesMu.Lock()
	currentRules = allRules
	currentRulesMu.Unlock()
}

// getRules returns a snapshot of the current rules.
func getRules() []SecurityRule {
	currentRulesMu.RLock()
	defer currentRulesMu.RUnlock()
	return currentRules
}

// ==================== Schema limits (must match docs/schema.json) ====================

const (
	maxDenyRules       = 256
	maxRuleNameLen     = 128
	maxPatternsPerRule = 64
	maxPatternLen      = 512
	maxExceptPerRule   = 64
	maxHostsPerRule    = 256
	maxIPsPerHost      = 64
)

// ==================== Policy builder ====================

// buildPolicy builds a rules-mode JSON policy for bakelens-sandbox.
// The same function is used on all platforms. Rust handles platform dispatch.
func buildPolicy(command []string) ([]byte, error) {
	denyRules, err := buildDenyRulesFrom(getRules())
	if err != nil {
		return nil, err
	}
	policy := PolicyJSON{
		Version: 1,
		Command: command,
		Rules:   denyRules,
	}
	return json.Marshal(policy)
}

// allFileOps returns all filesystem operation names.
// Network deny is structural (via the hosts field), not an operation.
func allFileOps() []string {
	return []string{
		string(OpRead), string(OpWrite), string(OpDelete),
		string(OpCopy), string(OpMove), string(OpExecute),
	}
}

// filterOps removes "network" and deduplicates an operations list.
// "network" is not a valid sandbox operation — network deny is controlled
// structurally by the hosts field on DenyRule. Duplicates are also removed.
func filterOps(ops []string) []string {
	seen := make(map[string]bool, len(ops))
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if op == string(OpNetwork) || seen[op] {
			continue
		}
		seen[op] = true
		out = append(out, op)
	}
	return out
}

// buildDenyRulesFrom converts the given SecurityRules into DenyRuleJSON entries.
// Each rule is self-contained: filesystem patterns + network hosts are inline.
// Match-only rules (content, command) are enforced at Layer 1, not here.
// Validates output against the sandbox input schema (docs/schema.json).
func buildDenyRulesFrom(rules []SecurityRule) ([]DenyRuleJSON, error) {
	result := make([]DenyRuleJSON, 0, len(rules))
	seenNames := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}
		paths := rule.GetBlockPaths()
		hosts := resolveHostsForRule(rule)

		// Filter "network" (not a sandbox operation) and deduplicate.
		ops := filterOps(rule.GetActions())
		if len(ops) == 0 && len(paths) > 0 {
			// Filesystem patterns without explicit ops: default to all file ops.
			ops = allFileOps()
		}

		// Skip rules that have nothing enforceable at the sandbox level.
		// Content-only rules (no paths, no hosts) are Layer 0/1 only.
		if len(paths) == 0 && len(hosts) == 0 {
			continue
		}
		if len(ops) == 0 && len(hosts) == 0 {
			continue
		}

		name := rule.GetName()
		if err := validateDenyRule(name, paths, rule.GetBlockExcept(), hosts, seenNames); err != nil {
			return nil, err
		}
		seenNames[name] = true

		dr := DenyRuleJSON{
			Name:       name,
			Patterns:   paths,
			Except:     rule.GetBlockExcept(),
			Operations: ops,
			Hosts:      hosts,
		}
		result = append(result, dr)
	}

	if len(result) > maxDenyRules {
		return nil, fmt.Errorf("too many deny rules (%d, max %d)", len(result), maxDenyRules)
	}

	return result, nil
}

// validateDenyRule checks a single rule against the sandbox input schema limits.
func validateDenyRule(name string, patterns, except []string, hosts []HostEntryJSON, seenNames map[string]bool) error {
	if len(name) == 0 {
		return errors.New("deny rule name must not be empty")
	}
	if len(name) > maxRuleNameLen {
		return fmt.Errorf("deny rule name %q too long (%d chars, max %d)", name, len(name), maxRuleNameLen)
	}
	if seenNames[name] {
		return fmt.Errorf("duplicate deny rule name %q: rule names must be unique", name)
	}
	if len(patterns) > maxPatternsPerRule {
		return fmt.Errorf("deny rule %q: too many patterns (%d, max %d)", name, len(patterns), maxPatternsPerRule)
	}
	for _, p := range patterns {
		if len(p) == 0 {
			return fmt.Errorf("deny rule %q: pattern must not be empty", name)
		}
		if len(p) > maxPatternLen {
			return fmt.Errorf("deny rule %q: pattern too long (%d chars, max %d)", name, len(p), maxPatternLen)
		}
	}
	if len(except) > maxExceptPerRule {
		return fmt.Errorf("deny rule %q: too many except patterns (%d, max %d)", name, len(except), maxExceptPerRule)
	}
	for _, e := range except {
		if len(e) == 0 {
			return fmt.Errorf("deny rule %q: except pattern must not be empty", name)
		}
		if len(e) > maxPatternLen {
			return fmt.Errorf("deny rule %q: except pattern too long (%d chars, max %d)", name, len(e), maxPatternLen)
		}
	}
	if len(hosts) > maxHostsPerRule {
		return fmt.Errorf("deny rule %q: too many hosts (%d, max %d)", name, len(hosts), maxHostsPerRule)
	}
	for _, h := range hosts {
		if len(h.Name) == 0 {
			return fmt.Errorf("deny rule %q: host name must not be empty", name)
		}
		if len(h.ResolvedIPs) == 0 {
			return fmt.Errorf("deny rule %q: host %q must have at least one resolved IP", name, h.Name)
		}
		if len(h.ResolvedIPs) > maxIPsPerHost {
			return fmt.Errorf("deny rule %q: host %q has too many IPs (%d, max %d)", name, h.Name, len(h.ResolvedIPs), maxIPsPerHost)
		}
	}
	return nil
}

// resolveHostsForRule resolves a single rule's block hosts to HostEntryJSON entries.
// DNS resolution is done here in Go — Rust only receives IP addresses.
func resolveHostsForRule(rule SecurityRule) []HostEntryJSON {
	blockHosts := rule.GetBlockHosts()
	if len(blockHosts) == 0 {
		return nil
	}

	var entries []HostEntryJSON
	for _, host := range blockHosts {
		resolved := resolveHostToIPs(host)
		if len(resolved) == 0 {
			continue
		}
		entries = append(entries, HostEntryJSON{
			Name:        host,
			ResolvedIPs: resolved,
		})
	}
	return entries
}

// resolveHostToIPs resolves a single host string to IP addresses.
// Returns nil for globs, regex, and CIDRs.
func resolveHostToIPs(host string) []string {
	// Skip glob patterns and regex
	if containsGlob(host) || strings.HasPrefix(host, "re:") {
		return nil
	}

	// Try parsing as IP literal
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}

	// Skip CIDRs
	if _, _, err := net.ParseCIDR(host); err == nil {
		return nil
	}

	// DNS resolution for domain names
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}

	var ips []string
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil {
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// containsGlob returns true if the string contains glob metacharacters.
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}
