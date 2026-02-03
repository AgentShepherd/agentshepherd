package rules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/AgentShepherd/agentshepherd/internal/logger"
	"github.com/gobwas/glob"
)

var log = logger.New("rules")

// Engine is the path-based rule engine
type Engine struct {
	mu sync.RWMutex

	// Immutable after init (unless --disable-builtin)
	builtin []CompiledRule

	// Can be hot-reloaded
	user []CompiledRule

	// Merged and sorted by priority (rebuilt on reload)
	merged []CompiledRule

	// Core components
	extractor  *Extractor
	normalizer *Normalizer
	loader     *Loader

	// Configuration
	config EngineConfig

	// Stats
	hitCounts map[string]*int64

	// Callbacks for reload notifications (e.g., sandbox mapper)
	onReloadCallbacks []ReloadCallback
}

// CompiledRule is a rule with pre-compiled matchers
type CompiledRule struct {
	Rule        Rule
	PathMatcher *Matcher
	HostMatcher *Matcher
}

// EngineConfig holds engine configuration
type EngineConfig struct {
	UserRulesDir   string
	DisableBuiltin bool
	APIPort        int // Management API port (for dynamic protection rules)
}

// ReloadCallback is called after rules are reloaded
type ReloadCallback func(rules []Rule)

// SECURITY FIX: Use mutex to prevent race conditions on global engine access
var (
	globalEngine   *Engine
	globalEngineMu sync.RWMutex
)

// SetGlobalEngine sets the global rule engine instance
func SetGlobalEngine(e *Engine) {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()
	globalEngine = e
}

// GetGlobalEngine returns the global rule engine instance
func GetGlobalEngine() *Engine {
	globalEngineMu.RLock()
	defer globalEngineMu.RUnlock()
	return globalEngine
}

// NewEngine creates a new path-based rule engine
func NewEngine(cfg EngineConfig) (*Engine, error) {
	loader := NewLoader(cfg.UserRulesDir)

	e := &Engine{
		extractor:  NewExtractor(),
		normalizer: NewNormalizer(),
		loader:     loader,
		config:     cfg,
		hitCounts:  make(map[string]*int64),
	}

	// Load builtin rules (unless disabled)
	if !cfg.DisableBuiltin {
		builtinRules, err := loader.LoadBuiltin()
		if err != nil {
			return nil, err
		}

		// Add dynamic protection rules based on config
		dynamicRules := generateProtectionRules(cfg)
		builtinRules = append(dynamicRules, builtinRules...)

		compiled, err := e.compileRules(builtinRules)
		if err != nil {
			return nil, err
		}
		e.builtin = compiled
		log.Info("Loaded %d builtin rules (%d dynamic)", len(compiled), len(dynamicRules))
	} else {
		log.Warn("Builtin rules disabled")
	}

	// Load user rules
	if err := e.ReloadUserRules(); err != nil {
		log.Warn("Failed to load user rules: %v", err)
	}

	return e, nil
}

// NewEngineWithNormalizer creates a new engine with a custom normalizer.
// This is useful for testing with a controlled environment.
func NewEngineWithNormalizer(cfg EngineConfig, normalizer *Normalizer) (*Engine, error) {
	engine, err := NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	engine.normalizer = normalizer
	return engine, nil
}

// NewTestEngine creates a new engine from a list of rules.
// This is a convenience function for testing that bypasses loading from files.
func NewTestEngine(rules []Rule) (*Engine, error) {
	e := &Engine{
		extractor:  NewExtractor(),
		normalizer: NewNormalizer(),
		loader:     NewLoader(""),
		config:     EngineConfig{DisableBuiltin: true},
		hitCounts:  make(map[string]*int64),
	}

	compiled, err := e.compileRules(rules)
	if err != nil {
		return nil, err
	}
	e.builtin = compiled
	e.rebuildMergedLocked()

	return e, nil
}

// NewTestEngineWithNormalizer creates a new engine with a custom normalizer.
// This is useful for testing with controlled environment variables.
func NewTestEngineWithNormalizer(rules []Rule, normalizer *Normalizer) (*Engine, error) {
	engine, err := NewTestEngine(rules)
	if err != nil {
		return nil, err
	}
	engine.normalizer = normalizer
	return engine, nil
}

// generateProtectionRules creates dynamic rules to protect AgentShepherd itself
func generateProtectionRules(cfg EngineConfig) []Rule {
	rules := []Rule{}

	// Rule 1: Block deletion of AgentShepherd rules directory
	rules = append(rules, Rule{
		Name:        "block-agentshepherd-rules-dir-delete",
		Description: "Block deletion of AgentShepherd rules directory",
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/**"},
		},
		Operations: []Operation{OpDelete},
		Message:    "BLOCKED: Cannot delete AgentShepherd rules directory",
		Severity:   SeverityCritical,
		Source:     SourceBuiltin,
	})

	// Rule 2: Block writing to rules directory (except through API)
	rules = append(rules, Rule{
		Name:        "block-agentshepherd-rule-file-write",
		Description: "Block direct modification of rule files",
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/*.yaml"},
		},
		Operations: []Operation{OpWrite},
		Message:    "BLOCKED: Cannot modify AgentShepherd rule files directly",
		Severity:   SeverityCritical,
		Source:     SourceBuiltin,
	})

	return rules
}

// ReloadUserRules reloads rules from user directory
func (e *Engine) ReloadUserRules() error {
	userRules, err := e.loader.LoadUser()
	if err != nil {
		return err
	}

	compiled, err := e.compileRules(userRules)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.user = compiled
	e.rebuildMergedLocked()
	e.mu.Unlock()

	log.Info("Loaded %d user rules, total %d active rules", len(compiled), len(e.merged))

	// Notify reload callbacks (e.g., sandbox mapper)
	e.notifyReload()

	return nil
}

// AddRulesFromFile adds rules from a file and reloads
func (e *Engine) AddRulesFromFile(path string) (string, error) {
	destPath, err := e.loader.AddRuleFile(path)
	if err != nil {
		return "", err
	}

	if err := e.ReloadUserRules(); err != nil {
		return destPath, err
	}

	return destPath, nil
}

// Evaluate evaluates a tool call against path-based rules
// Returns MatchResult (same as pattern-based for compatibility)
func (e *Engine) Evaluate(call ToolCall) MatchResult {
	// Step 1: Extract paths and operation from the tool call
	info := e.extractor.Extract(call.Name, call.Arguments)

	e.mu.RLock()
	rules := e.merged
	e.mu.RUnlock()

	// Step 2: Normalize extracted paths
	normalizedPaths := e.normalizer.NormalizeAll(info.Paths)

	// Step 3: Evaluate operation-based rules (for known tools)
	if info.Operation != "" {
		if result := e.evaluateOperationRules(rules, info, normalizedPaths, call.Name); result.Matched {
			return result
		}
	}

	// Step 4: Fallback rules (content-only) - matches raw JSON of ANY tool including MCP
	for _, compiled := range rules {
		if !compiled.Rule.IsEnabled() {
			continue
		}
		if compiled.Rule.IsContentOnly() && info.Content != "" {
			if matchContent(compiled.Rule.Match.Content, info.Content) {
				e.incrementHitCount(compiled.Rule.Name)
				return MatchResult{
					Matched:  true,
					RuleName: compiled.Rule.Name,
					Severity: compiled.Rule.GetSeverity(),
					Action:   ActionBlock,
					Message:  compiled.Rule.Message,
				}
			}
		}
	}

	return MatchResult{Matched: false}
}

// evaluateOperationRules evaluates operation-based rules (path, command, host matching)
func (e *Engine) evaluateOperationRules(rules []CompiledRule, info ExtractedInfo, normalizedPaths []string, toolName string) MatchResult {
	// Evaluate against rules (sorted by priority)
	for _, compiled := range rules {
		// Skip disabled rules
		if !compiled.Rule.IsEnabled() {
			continue
		}

		// Skip if rule doesn't apply to this operation
		if !compiled.Rule.HasOperation(info.Operation) {
			continue
		}

		// Check path matching for non-network operations (or network ops that also have paths)
		if compiled.PathMatcher != nil && len(normalizedPaths) > 0 {
			matched, matchedPath := compiled.PathMatcher.MatchAny(normalizedPaths)
			if matched {
				// Increment hit count
				e.incrementHitCount(compiled.Rule.Name)

				return MatchResult{
					Matched:  true,
					RuleName: compiled.Rule.Name,
					Severity: compiled.Rule.GetSeverity(),
					Action:   ActionBlock,
					Message:  formatMessage(compiled.Rule.Message, matchedPath),
				}
			}
		}

		// Check host matching for network operations
		if info.Operation == OpNetwork && compiled.HostMatcher != nil && len(info.Hosts) > 0 {
			matched, matchedHost := compiled.HostMatcher.MatchAny(info.Hosts)
			if matched {
				// Increment hit count
				e.incrementHitCount(compiled.Rule.Name)

				return MatchResult{
					Matched:  true,
					RuleName: compiled.Rule.Name,
					Severity: compiled.Rule.GetSeverity(),
					Action:   ActionBlock,
					Message:  formatMessage(compiled.Rule.Message, matchedHost),
				}
			}
		}

		// Evaluate advanced match conditions (progressive disclosure Level 4+)
		if compiled.Rule.Match != nil {
			if e.evaluateMatch(*compiled.Rule.Match, info, normalizedPaths, toolName) {
				e.incrementHitCount(compiled.Rule.Name)
				return MatchResult{
					Matched:  true,
					RuleName: compiled.Rule.Name,
					Severity: compiled.Rule.GetSeverity(),
					Action:   ActionBlock,
					Message:  compiled.Rule.Message,
				}
			}
		}

		// Evaluate AllConditions (AND logic - all conditions must match)
		if len(compiled.Rule.AllConditions) > 0 {
			allMatched := true
			for _, match := range compiled.Rule.AllConditions {
				if !e.evaluateMatch(match, info, normalizedPaths, toolName) {
					allMatched = false
					break
				}
			}
			if allMatched {
				e.incrementHitCount(compiled.Rule.Name)
				return MatchResult{
					Matched:  true,
					RuleName: compiled.Rule.Name,
					Severity: compiled.Rule.GetSeverity(),
					Action:   ActionBlock,
					Message:  compiled.Rule.Message,
				}
			}
		}

		// Evaluate AnyConditions (OR logic - any condition matches)
		if len(compiled.Rule.AnyConditions) > 0 {
			for _, match := range compiled.Rule.AnyConditions {
				if e.evaluateMatch(match, info, normalizedPaths, toolName) {
					e.incrementHitCount(compiled.Rule.Name)
					return MatchResult{
						Matched:  true,
						RuleName: compiled.Rule.Name,
						Severity: compiled.Rule.GetSeverity(),
						Action:   ActionBlock,
						Message:  compiled.Rule.Message,
					}
				}
			}
		}
	}

	// No operation-based rule matched
	return MatchResult{Matched: false}
}

// evaluateMatch evaluates a single Match condition against the extracted info.
// Returns true only if ALL non-empty conditions in the Match are satisfied (AND within a single Match).
func (e *Engine) evaluateMatch(match Match, info ExtractedInfo, normalizedPaths []string, toolName string) bool {
	// If match.Path is set, check if any normalized path matches
	if match.Path != "" {
		if !matchPath(match.Path, normalizedPaths) {
			return false
		}
	}

	// If match.Command is set, check if command matches (regex)
	if match.Command != "" {
		if !matchCommand(match.Command, info.Command) {
			return false
		}
	}

	// If match.Host is set, check if any host matches
	if match.Host != "" {
		if !matchHost(match.Host, info.Hosts) {
			return false
		}
	}

	// If match.Content is set, check if content matches (for Write/Edit tools)
	if match.Content != "" {
		if !matchContent(match.Content, info.Content) {
			return false
		}
	}

	// If match.Tools is set, check if toolName is in the list
	if len(match.Tools) > 0 {
		if !matchTools(match.Tools, toolName) {
			return false
		}
	}

	// All non-empty conditions matched (or no conditions were set)
	return true
}

// matchPath checks if any path matches the pattern (glob or regex with re: prefix)
func matchPath(pattern string, paths []string) bool {
	if len(paths) == 0 {
		return false
	}

	// Check for regex pattern (re: prefix)
	if len(pattern) > 3 && pattern[:3] == "re:" {
		re, err := regexp.Compile(pattern[3:])
		if err != nil {
			return false
		}
		for _, path := range paths {
			if re.MatchString(path) {
				return true
			}
		}
		return false
	}

	// Glob pattern
	g, err := glob.Compile(pattern, '/')
	if err != nil {
		return false
	}
	for _, path := range paths {
		if g.Match(path) {
			return true
		}
	}
	return false
}

// matchCommand checks if command matches the pattern (regex with re: prefix, or literal)
func matchCommand(pattern string, command string) bool {
	if command == "" {
		return false
	}

	// Check for regex pattern (re: prefix)
	if len(pattern) > 3 && pattern[:3] == "re:" {
		re, err := regexp.Compile(pattern[3:])
		if err != nil {
			return false
		}
		return re.MatchString(command)
	}

	// Literal match (case-insensitive substring)
	return containsIgnoreCase(command, pattern)
}

// matchContent checks if content matches the pattern (regex with re: prefix, or literal)
func matchContent(pattern string, content string) bool {
	if content == "" {
		return false
	}

	// Check for regex pattern (re: prefix)
	if len(pattern) > 3 && pattern[:3] == "re:" {
		re, err := regexp.Compile(pattern[3:])
		if err != nil {
			return false
		}
		return re.MatchString(content)
	}

	// Literal match (case-insensitive substring)
	return containsIgnoreCase(content, pattern)
}

// matchHost checks if any host matches the pattern (glob, regex with re: prefix, or literal)
func matchHost(pattern string, hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}

	// Check for regex pattern (re: prefix)
	if len(pattern) > 3 && pattern[:3] == "re:" {
		re, err := regexp.Compile(pattern[3:])
		if err != nil {
			return false
		}
		for _, host := range hosts {
			if re.MatchString(host) {
				return true
			}
		}
		return false
	}

	// Simple glob matching for hosts
	g, err := glob.Compile(pattern, '.')
	if err != nil {
		// If glob fails, try literal match
		for _, host := range hosts {
			if host == pattern {
				return true
			}
		}
		return false
	}

	for _, host := range hosts {
		if g.Match(host) {
			return true
		}
	}
	return false
}

// matchTools checks if toolName (lowercase) is in the list of allowed tools
func matchTools(tools []string, toolName string) bool {
	toolLower := toLower(toolName)
	for _, t := range tools {
		if t == toolLower {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	substrLower := toLower(substr)
	return len(sLower) >= len(substrLower) && findSubstring(sLower, substrLower)
}

// findSubstring checks if s contains substr
func findSubstring(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// EvaluateJSON is a convenience method that accepts JSON arguments
func (e *Engine) EvaluateJSON(toolName string, argsJSON string) MatchResult {
	return e.Evaluate(ToolCall{
		Name:      toolName,
		Arguments: json.RawMessage(argsJSON),
	})
}

// formatMessage formats a rule message, optionally including the matched path/host
func formatMessage(template string, matchedValue string) string {
	// For now, just return the template as-is
	// Future: could support placeholders like {path} or {host}
	return template
}

// GetRules returns all active rules
func (e *Engine) GetRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.merged))
	for i, cr := range e.merged {
		rule := cr.Rule
		// Update hit count from stats
		if count := e.hitCounts[rule.Name]; count != nil {
			rule.HitCount = atomic.LoadInt64(count)
		}
		rules[i] = rule
	}
	return rules
}

// GetBuiltinRules returns only builtin rules
func (e *Engine) GetBuiltinRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.builtin))
	for i, cr := range e.builtin {
		rules[i] = cr.Rule
	}
	return rules
}

// GetUserRules returns only user rules
func (e *Engine) GetUserRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, len(e.user))
	for i, cr := range e.user {
		rules[i] = cr.Rule
	}
	return rules
}

// RuleCount returns total number of active rules
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.merged)
}

// GetLoader returns the rule loader
func (e *Engine) GetLoader() *Loader {
	return e.loader
}

// GetAllRules returns all rules (builtin + user) as a flat slice.
// Useful for sandbox profile generation and consistency checking.
func (e *Engine) GetAllRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]Rule, 0, len(e.builtin)+len(e.user))
	for _, cr := range e.builtin {
		rules = append(rules, cr.Rule)
	}
	for _, cr := range e.user {
		rules = append(rules, cr.Rule)
	}
	return rules
}

// GetCompiledRules returns all compiled rules (for inspection/debugging)
func (e *Engine) GetCompiledRules() []CompiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.merged
}

// OnReload registers a callback to be called after rules are reloaded.
// The callback receives the complete list of all rules (builtin + user).
func (e *Engine) OnReload(callback ReloadCallback) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onReloadCallbacks = append(e.onReloadCallbacks, callback)
}

// notifyReload calls all registered reload callbacks.
func (e *Engine) notifyReload() {
	rules := e.GetAllRules()
	for _, cb := range e.onReloadCallbacks {
		go cb(rules) // Non-blocking
	}
}

// compileRules compiles path/host patterns in rules
func (e *Engine) compileRules(rules []Rule) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rules))

	for _, rule := range rules {
		// Skip disabled rules
		if !rule.IsEnabled() {
			continue
		}

		// Compile path matcher
		var pathMatcher *Matcher
		if len(rule.Block.Paths) > 0 {
			var err error
			pathMatcher, err = NewMatcher(rule.Block.Paths, rule.Block.Except)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.Name, err)
			}
		}

		// Compile host matcher
		var hostMatcher *Matcher
		if len(rule.Block.Hosts) > 0 {
			var err error
			hostMatcher, err = NewMatcher(rule.Block.Hosts, nil)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", rule.Name, err)
			}
		}

		compiled = append(compiled, CompiledRule{
			Rule:        rule,
			PathMatcher: pathMatcher,
			HostMatcher: hostMatcher,
		})
	}

	return compiled, nil
}

// rebuildMergedLocked rebuilds the merged rule list (must hold write lock)
func (e *Engine) rebuildMergedLocked() {
	// Combine builtin and user rules
	all := make([]CompiledRule, 0, len(e.builtin)+len(e.user))
	all = append(all, e.builtin...)
	all = append(all, e.user...)

	// Sort by priority (lower = higher priority)
	sort.Slice(all, func(i, j int) bool {
		return all[i].Rule.GetPriority() < all[j].Rule.GetPriority()
	})

	e.merged = all

	// Initialize hit counts for new rules
	for _, cr := range all {
		if _, exists := e.hitCounts[cr.Rule.Name]; !exists {
			var count int64
			e.hitCounts[cr.Rule.Name] = &count
		}
	}
}

// incrementHitCount increments the hit count for a rule
func (e *Engine) incrementHitCount(name string) {
	if count := e.hitCounts[name]; count != nil {
		atomic.AddInt64(count, 1)
	}
}

// extractJSONField extracts a string value from JSON at a dot-notation path
// SECURITY: Uses case-insensitive key matching to prevent bypasses
func extractJSONField(data json.RawMessage, path string) string {
	var parsed interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return ""
	}

	parts := splitPath(path)
	current := parsed

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = getMapValueCaseInsensitive(v, part)
		default:
			return ""
		}
	}

	switch v := current.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%g", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// splitPath splits a dot-notation path into parts
func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

// getMapValueCaseInsensitive finds a map value using case-insensitive key matching.
func getMapValueCaseInsensitive(m map[string]interface{}, key string) interface{} {
	// Try exact match first (most common case)
	if v, ok := m[key]; ok {
		return v
	}

	// Try case-insensitive match
	lowerKey := toLower(key)
	for k, v := range m {
		if toLower(k) == lowerKey {
			return v
		}
	}

	return nil
}

// toLower is a simple lowercase conversion
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		result[i] = c
	}
	return string(result)
}

// containsRegex checks if a string contains regex metacharacters
func containsRegex(s string) bool {
	metacharacters := `\^$.|?*+()[]{}`
	for _, c := range metacharacters {
		for _, r := range s {
			if r == c {
				return true
			}
		}
	}
	return false
}
