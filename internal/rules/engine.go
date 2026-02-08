package rules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/gobwas/glob"
)

var log = logger.New("rules")

// selfProtectAPIRegex is a hardcoded, tamper-proof check for management API access.
// Compiled once at init — cannot be altered by YAML rule changes or hot-reload.
var selfProtectAPIRegex = regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0|0x7f000001|2130706433)[:/].*crust`)

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

// CompiledMatch holds pre-compiled patterns from a Match condition.
// All regex/glob patterns are validated and compiled at rule insert time,
// so evaluation never needs to re-compile or handle invalid patterns.
type CompiledMatch struct {
	Match        Match          // original for error messages/display
	PathRegex    *regexp.Regexp // non-nil if Match.Path starts with "re:"
	PathGlob     glob.Glob      // non-nil if Match.Path is a glob pattern
	CommandRegex *regexp.Regexp // non-nil if Match.Command starts with "re:"
	HostRegex    *regexp.Regexp // non-nil if Match.Host starts with "re:"
	HostGlob     glob.Glob      // non-nil if Match.Host is a glob pattern
	ContentRegex *regexp.Regexp // non-nil if Match.Content starts with "re:"
}

// CompiledRule is a rule with pre-compiled matchers
type CompiledRule struct {
	Rule        Rule
	PathMatcher *Matcher // pre-compiled Block.Paths/Except
	HostMatcher *Matcher // pre-compiled Block.Hosts

	// Pre-compiled Match patterns (Level 4+ rules)
	MatchCompiled      *CompiledMatch
	AllCompiledMatches []CompiledMatch
	AnyCompiledMatches []CompiledMatch
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

		compiled, err := e.compileRules(builtinRules, true)
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

	compiled, err := e.compileRules(rules, true)
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

// generateProtectionRules creates dynamic rules to protect Crust itself
func generateProtectionRules(cfg EngineConfig) []Rule {
	rules := []Rule{}

	// Rule 1: Block deletion of Crust rules directory
	rules = append(rules, Rule{
		Name:        "block-crust-rules-dir-delete",
		Description: "Block deletion of Crust rules directory",
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/**"},
		},
		Actions:  []Operation{OpDelete},
		Message:  "BLOCKED: Cannot delete Crust rules directory",
		Severity: SeverityCritical,
		Source:   SourceBuiltin,
	})

	// Rule 2: Block writing to rules directory (except through API)
	rules = append(rules, Rule{
		Name:        "block-crust-rule-file-write",
		Description: "Block direct modification of rule files",
		Block: Block{
			Paths: []string{cfg.UserRulesDir + "/*.yaml"},
		},
		Actions:  []Operation{OpWrite},
		Message:  "BLOCKED: Cannot modify Crust rule files directly",
		Severity: SeverityCritical,
		Source:   SourceBuiltin,
	})

	return rules
}

// ReloadUserRules reloads rules from user directory.
// Integrity verification is performed inside LoadUser() using a read-once
// pattern: each file is read exactly once and the same bytes are used for
// both SHA3-256 checksum comparison and YAML parsing, eliminating any
// TOCTOU gap between integrity check and load.
func (e *Engine) ReloadUserRules() error {
	userRules, err := e.loader.LoadUser()
	if err != nil {
		return err
	}

	compiled, err := e.compileRules(userRules, false)
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

	// Step 1.5: Block evasive commands that prevent static analysis
	if info.Evasive {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:block-shell-evasion",
			Severity: "high",
			Action:   ActionBlock,
			Message:  info.EvasiveReason,
		}
	}

	// Step 1.55: Normalize content for confusable/fullwidth bypass prevention.
	// This protects both the hardcoded self-protection check and all content-only rules.
	if info.Content != "" {
		info.Content = NormalizeUnicode(info.Content)
	}

	// Step 1.6: Hardcoded self-protection — block management API access.
	// This check lives in Go code (not YAML) so it cannot be tampered with
	// by agents modifying rule files or triggering hot-reload.
	if info.Content != "" && selfProtectAPIRegex.MatchString(info.Content) {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:protect-crust-api",
			Severity: "critical",
			Action:   ActionBlock,
			Message:  "Cannot access Crust management API",
		}
	}

	e.mu.RLock()
	rules := e.merged
	e.mu.RUnlock()

	// Step 2: Normalize extracted paths and resolve symlinks to prevent bypasses
	normalizedPaths := e.normalizer.NormalizeAllWithSymlinks(info.Paths)

	// Step 3: Evaluate operation-based rules (for known tools)
	if info.Operation != "" {
		if result := e.evaluateOperationRules(rules, info, normalizedPaths, call.Name); result.Matched {
			return result
		}
	}

	// Step 4: Fallback rules (content-only) - matches raw JSON of ANY tool including MCP
	// Uses pre-compiled content regex from CompiledMatch when available.
	for _, compiled := range rules {
		if !compiled.Rule.IsEnabled() {
			continue
		}
		if compiled.Rule.IsContentOnly() && info.Content != "" {
			contentMatched := false
			if compiled.MatchCompiled != nil {
				// Use pre-compiled pattern
				if compiled.MatchCompiled.ContentRegex != nil {
					contentMatched = compiled.MatchCompiled.ContentRegex.MatchString(info.Content)
				} else {
					// Literal match (case-insensitive substring)
					contentMatched = containsIgnoreCase(info.Content, compiled.MatchCompiled.Match.Content)
				}
			}
			if contentMatched {
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
		if !compiled.Rule.HasAction(info.Operation) {
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

		// Evaluate advanced match conditions using pre-compiled patterns (Level 4+)
		if compiled.MatchCompiled != nil {
			if e.evaluateMatchCompiled(compiled.MatchCompiled, info, normalizedPaths, toolName) {
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

		// Evaluate AllConditions (AND logic - all conditions must match) using pre-compiled patterns
		if len(compiled.AllCompiledMatches) > 0 {
			allMatched := true
			for i := range compiled.AllCompiledMatches {
				if !e.evaluateMatchCompiled(&compiled.AllCompiledMatches[i], info, normalizedPaths, toolName) {
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

		// Evaluate AnyConditions (OR logic - any condition matches) using pre-compiled patterns
		if len(compiled.AnyCompiledMatches) > 0 {
			for i := range compiled.AnyCompiledMatches {
				if e.evaluateMatchCompiled(&compiled.AnyCompiledMatches[i], info, normalizedPaths, toolName) {
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

// evaluateMatchCompiled evaluates a single pre-compiled Match condition against the extracted info.
// Uses pre-compiled regex/glob patterns from CompiledMatch instead of re-compiling at runtime.
// Returns true only if ALL non-empty conditions in the Match are satisfied (AND within a single Match).
func (e *Engine) evaluateMatchCompiled(cm *CompiledMatch, info ExtractedInfo, normalizedPaths []string, toolName string) bool {
	if cm == nil {
		return true
	}

	// Path matching — use pre-compiled regex or glob
	if cm.Match.Path != "" {
		if len(normalizedPaths) == 0 {
			return false
		}
		matched := false
		if cm.PathRegex != nil {
			for _, p := range normalizedPaths {
				if cm.PathRegex.MatchString(p) {
					matched = true
					break
				}
			}
		} else if cm.PathGlob != nil {
			for _, p := range normalizedPaths {
				if cm.PathGlob.Match(p) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Command matching — use pre-compiled regex or literal substring
	if cm.Match.Command != "" {
		if info.Command == "" {
			return false
		}
		if cm.CommandRegex != nil {
			if !cm.CommandRegex.MatchString(info.Command) {
				return false
			}
		} else {
			// Literal match (case-insensitive substring)
			if !containsIgnoreCase(info.Command, cm.Match.Command) {
				return false
			}
		}
	}

	// Host matching — use pre-compiled regex or glob
	if cm.Match.Host != "" {
		if len(info.Hosts) == 0 {
			return false
		}
		matched := false
		if cm.HostRegex != nil {
			for _, h := range info.Hosts {
				if cm.HostRegex.MatchString(h) {
					matched = true
					break
				}
			}
		} else if cm.HostGlob != nil {
			for _, h := range info.Hosts {
				if cm.HostGlob.Match(h) {
					matched = true
					break
				}
			}
		} else {
			// Literal host match (exact)
			for _, h := range info.Hosts {
				if h == cm.Match.Host {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Content matching — use pre-compiled regex or literal substring
	if cm.Match.Content != "" {
		if info.Content == "" {
			return false
		}
		if cm.ContentRegex != nil {
			if !cm.ContentRegex.MatchString(info.Content) {
				return false
			}
		} else {
			// Literal match (case-insensitive substring)
			if !containsIgnoreCase(info.Content, cm.Match.Content) {
				return false
			}
		}
	}

	// Tool matching — just string comparison, no compilation needed
	if len(cm.Match.Tools) > 0 {
		if !matchTools(cm.Match.Tools, toolName) {
			return false
		}
	}

	// All non-empty conditions matched (or no conditions were set)
	return true
}

// evaluateMatch evaluates a single Match condition against the extracted info.
// Returns true only if ALL non-empty conditions in the Match are satisfied (AND within a single Match).
// maxRegexLen limits user-defined regex pattern length to bound compilation cost.
const maxRegexLen = 4096

// compileRegex compiles a regex with a length limit.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (%d > %d chars)", len(pattern), maxRegexLen)
	}
	return regexp.Compile(pattern)
}

// matchTools checks if toolName (lowercase) is in the list of allowed tools
func matchTools(tools []string, toolName string) bool {
	toolLower := strings.ToLower(toolName)
	for _, t := range tools {
		if t == toolLower {
			return true
		}
	}
	return false
}

// containsIgnoreCase checks if s contains substr (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
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

// RuleValidationResult holds per-rule validation results.
type RuleValidationResult struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// ValidateYAMLFull validates YAML content including pattern compilation.
// Returns per-rule validation results so callers can report all errors, not just the first.
func (e *Engine) ValidateYAMLFull(data []byte) ([]RuleValidationResult, error) {
	rules, err := e.loader.parseRuleSet(data, "inline", SourceCLI)
	if err != nil {
		return nil, err
	}

	results := make([]RuleValidationResult, 0, len(rules))
	for _, rule := range rules {
		result := RuleValidationResult{Name: rule.Name, Valid: true}
		if _, err := compileOneRule(rule); err != nil {
			result.Valid = false
			result.Error = err.Error()
		}
		results = append(results, result)
	}
	return results, nil
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

// sanitizePattern rejects patterns containing null bytes or control characters.
// Returns an error so the user gets a clear message about what's wrong.
func sanitizePattern(pattern string) error {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == 0 {
			return fmt.Errorf("pattern contains null byte at position %d", i)
		}
		if pattern[i] < 0x20 && pattern[i] != '\t' {
			return fmt.Errorf("pattern contains control character 0x%02x at position %d", pattern[i], i)
		}
	}
	return nil
}

// compileMatchPattern pre-compiles a single Match condition's patterns.
// Returns clear errors for invalid patterns so rules are rejected at insert time.
func compileMatchPattern(m *Match) (*CompiledMatch, error) {
	if m == nil {
		return nil, nil
	}
	cm := &CompiledMatch{Match: *m}

	// Sanitize all pattern fields
	for _, check := range []struct{ name, pattern string }{
		{"path", m.Path}, {"command", m.Command},
		{"host", m.Host}, {"content", m.Content},
	} {
		if check.pattern == "" {
			continue
		}
		if err := sanitizePattern(check.pattern); err != nil {
			return nil, fmt.Errorf("match.%s: %w", check.name, err)
		}
	}

	// Compile Path (regex or glob)
	if m.Path != "" {
		if strings.HasPrefix(m.Path, "re:") {
			re, err := compileRegex(m.Path[3:])
			if err != nil {
				return nil, fmt.Errorf("match.path regex %q: %w", m.Path, err)
			}
			cm.PathRegex = re
		} else {
			g, err := glob.Compile(m.Path, '/')
			if err != nil {
				return nil, fmt.Errorf("match.path glob %q: %w", m.Path, err)
			}
			cm.PathGlob = g
		}
	}

	// Compile Command (regex only; literals use substring match at runtime)
	if m.Command != "" && strings.HasPrefix(m.Command, "re:") {
		re, err := compileRegex(m.Command[3:])
		if err != nil {
			return nil, fmt.Errorf("match.command regex %q: %w", m.Command, err)
		}
		cm.CommandRegex = re
	}

	// Compile Host (regex or glob)
	if m.Host != "" {
		if strings.HasPrefix(m.Host, "re:") {
			re, err := compileRegex(m.Host[3:])
			if err != nil {
				return nil, fmt.Errorf("match.host regex %q: %w", m.Host, err)
			}
			cm.HostRegex = re
		} else {
			g, err := glob.Compile(m.Host, '.')
			if err != nil {
				return nil, fmt.Errorf("match.host glob %q: %w", m.Host, err)
			}
			cm.HostGlob = g
		}
	}

	// Compile Content (regex only; literals use substring match at runtime)
	if m.Content != "" && strings.HasPrefix(m.Content, "re:") {
		re, err := compileRegex(m.Content[3:])
		if err != nil {
			return nil, fmt.Errorf("match.content regex %q: %w", m.Content, err)
		}
		cm.ContentRegex = re
	}

	return cm, nil
}

// compileRules compiles path/host patterns in rules.
// When strict is true (builtin rules), any compilation error aborts the entire batch.
// When strict is false (user rules), bad rules are skipped with a warning.
func (e *Engine) compileRules(rules []Rule, strict bool) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rules))

	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}

		cr, err := compileOneRule(rule)
		if err != nil {
			if strict {
				return nil, err
			}
			log.Warn("Skipping rule %q from %s: %v", rule.Name, rule.FilePath, err)
			continue
		}
		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// compileOneRule validates and compiles a single rule's patterns.
// Returns a clear error if any pattern is invalid.
func compileOneRule(rule Rule) (CompiledRule, error) {
	// Sanitize Block patterns before compilation
	for i, p := range rule.Block.Paths {
		if err := sanitizePattern(p); err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q block.paths[%d]: %w", rule.Name, i, err)
		}
	}
	for i, p := range rule.Block.Except {
		if err := sanitizePattern(p); err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q block.except[%d]: %w", rule.Name, i, err)
		}
	}
	for i, p := range rule.Block.Hosts {
		if err := sanitizePattern(p); err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q block.hosts[%d]: %w", rule.Name, i, err)
		}
	}

	// Compile path matcher (Block.Paths/Except)
	var pathMatcher *Matcher
	if len(rule.Block.Paths) > 0 {
		var err error
		pathMatcher, err = NewMatcher(rule.Block.Paths, rule.Block.Except)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile host matcher (Block.Hosts)
	var hostMatcher *Matcher
	if len(rule.Block.Hosts) > 0 {
		var err error
		hostMatcher, err = NewMatcher(rule.Block.Hosts, nil)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile Match patterns (Level 4+ rules)
	var matchCompiled *CompiledMatch
	if rule.Match != nil {
		var err error
		matchCompiled, err = compileMatchPattern(rule.Match)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile AllConditions (AND logic)
	var allCompiled []CompiledMatch
	for i, cond := range rule.AllConditions {
		cm, err := compileMatchPattern(&cond)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q all[%d]: %w", rule.Name, i, err)
		}
		if cm != nil {
			allCompiled = append(allCompiled, *cm)
		}
	}

	// Compile AnyConditions (OR logic)
	var anyCompiled []CompiledMatch
	for i, cond := range rule.AnyConditions {
		cm, err := compileMatchPattern(&cond)
		if err != nil {
			return CompiledRule{}, fmt.Errorf("rule %q any[%d]: %w", rule.Name, i, err)
		}
		if cm != nil {
			anyCompiled = append(anyCompiled, *cm)
		}
	}

	return CompiledRule{
		Rule:               rule,
		PathMatcher:        pathMatcher,
		HostMatcher:        hostMatcher,
		MatchCompiled:      matchCompiled,
		AllCompiledMatches: allCompiled,
		AnyCompiledMatches: anyCompiled,
	}, nil
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
