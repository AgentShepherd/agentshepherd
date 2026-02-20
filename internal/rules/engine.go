package rules

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/gobwas/glob"
)

var log = logger.New("rules")

// selfProtectAPIRegex is a hardcoded, tamper-proof check for management API access.
// Compiled once at init — cannot be altered by YAML rule changes or hot-reload.
// Covers: localhost, entire 127.0.0.0/8 range, IPv6 loopback (::1),
// IPv6-mapped IPv4 (::ffff:127.x.x.x), 0.0.0.0, hex (0x7fXXXXXX), decimal (2130706433),
// inet_aton short forms (127.1, 127.0.1), DNS rebinding services (nip.io, sslip.io, etc.).
var selfProtectAPIRegex = regexp.MustCompile(
	`(?i)(` +
		`localhost|` +
		`127\.\d{1,3}\.\d{1,3}\.\d{1,3}|` + // entire 127.0.0.0/8 loopback range (4-part)
		`127\.\d+\.\d+|` + // inet_aton 3-part: 127.0.1
		`127\.\d+|` + // inet_aton 2-part: 127.1
		`\[?::(?:ffff:)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?|` + // IPv6-mapped 127.x.x.x
		`\[?::1\]?|` + // IPv6 loopback
		`0\.0\.0\.0|` + // all-interfaces bind
		`0x7f[0-9a-f]{6}|` + // hex representation of 127.0.0.0/8
		`0x0[0:]|` + // hex zero host: 0x0:port or 0x0/path → 0.0.0.0
		`0177\.\d{1,3}\.\d{1,3}\.\d{1,3}|` + // octal representation of 127.0.0.0/8
		`2130706433|` + // decimal representation of 127.0.0.1
		// DNS rebinding services: hostnames that resolve to loopback IPs
		`[a-z0-9.-]*\.(?:nip|sslip|xip)\.io|` + // wildcard DNS: A.B.C.D.nip.io → A.B.C.D
		`(?:localtest|lvh|vcap)\.me|` + // known rebinding domains → 127.0.0.1
		`lacolhost\.com` + // known rebinding domain → 127.0.0.1
		`)[:/].*crust` +
		`|://0[:/].*crust`) // bare 0 as URL host (= 0.0.0.0)

// selfProtectSocketRegex blocks agents from accessing the management API
// via Unix domain sockets or Windows named pipes. Compiled once at init.
var selfProtectSocketRegex = regexp.MustCompile(
	`(?i)(` +
		`--unix-socket|` + // curl --unix-socket
		`UNIX-CONNECT:|` + // socat UNIX-CONNECT:
		`AF_UNIX|` + // Python/C socket code
		`crust-api[-.]\S*\.sock|` + // socket filenames (crust-api-9090.sock etc.)
		`\\\\.\\pipe\\crust|` + // Windows named pipe \\.\pipe\crust*
		`NamedPipeClientStream` + // .NET named pipe access
		`)`)

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
	preFilter  *PreFilter

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
	UserRulesDir        string
	DisableBuiltin      bool
	SubprocessIsolation bool // Isolate shell interpreter in a subprocess for crash safety
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
		preFilter:  NewPreFilter(),
		config:     cfg,
		hitCounts:  make(map[string]*int64),
	}

	if cfg.SubprocessIsolation {
		if exe, err := os.Executable(); err == nil {
			if err := e.extractor.EnableSubprocessIsolation(exe); err != nil {
				log.Warn("Shell worker failed to start (falling back to in-process): %v", err)
			}
		}
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
		preFilter:  NewPreFilter(),
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
	// Match the extractor's env to the normalizer's env so variable
	// expansion ($HOME, etc.) resolves consistently in tests.
	engine.extractor = NewExtractorWithEnv(normalizer.env)
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

	// Rule 3: Block access to management API socket files
	rules = append(rules, Rule{
		Name:        "block-crust-socket-access",
		Description: "Block access to Crust management API sockets",
		Block: Block{
			Paths: []string{"**/.crust/crust-api-*.sock", "**/.crust/*.sock"},
		},
		Actions:  []Operation{OpRead, OpWrite, OpDelete},
		Message:  "BLOCKED: Cannot access Crust management socket",
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

	// Step 1.4: PreFilter — detect obfuscation patterns the AST parser misses
	// (base64 decode, hex escapes, IFS manipulation, dangerous curl/nc flags)
	if info.Command != "" {
		if match := e.preFilter.Check(info.Command); match != nil {
			return MatchResult{
				Matched:  true,
				RuleName: "builtin:block-obfuscation",
				Severity: SeverityHigh,
				Action:   ActionBlock,
				Message:  fmt.Sprintf("Blocked: %s (%s)", match.Reason, match.PatternName),
			}
		}
	}

	// Step 1.5: Block evasive commands that prevent static analysis
	if info.Evasive {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:block-shell-evasion",
			Severity: SeverityHigh,
			Action:   ActionBlock,
			Message:  info.EvasiveReason,
		}
	}

	// Step 1.55: Normalize content for confusable/fullwidth bypass prevention.
	// This protects both the hardcoded self-protection check and all content-only rules.
	if info.Content != "" {
		info.Content = NormalizeUnicode(info.Content)
	}
	if info.RawJSON != "" {
		info.RawJSON = NormalizeUnicode(info.RawJSON)
	}

	// Step 1.6: Hardcoded self-protection — block management API access.
	// This check lives in Go code (not YAML) so it cannot be tampered with
	// by agents modifying rule files or triggering hot-reload.
	// Uses RawJSON (full payload) — not Content, which may be overwritten to a single field.
	if info.RawJSON != "" && selfProtectAPIRegex.MatchString(info.RawJSON) {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:protect-crust-api",
			Severity: SeverityCritical,
			Action:   ActionBlock,
			Message:  "Cannot access Crust management API",
		}
	}

	// Step 1.65: Block management API access via Unix socket / named pipe.
	// Agents may try curl --unix-socket, socat, or direct Python AF_UNIX.
	if info.RawJSON != "" && selfProtectSocketRegex.MatchString(info.RawJSON) {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:protect-crust-socket",
			Severity: SeverityCritical,
			Action:   ActionBlock,
			Message:  "Cannot access Crust management socket",
		}
	}

	e.mu.RLock()
	rules := e.merged
	e.mu.RUnlock()

	// Step 1.9: Filter out bare shell globs from extracted paths.
	// The shell parser may extract glob patterns (*, ?, *.txt) from
	// redirections like "<*" or arguments. These are not real file paths —
	// the shell expands them before any file operation. Without filtering,
	// a bare "*" normalizes to "/cwd/*" which matches any protected glob
	// pattern (e.g., **/.env), causing false positives.
	info.Paths = filterShellGlobs(info.Paths)

	// Step 2: Normalize extracted paths (without symlink resolution yet)
	normalizedPaths := e.normalizer.NormalizeAll(info.Paths)

	// Step 2.1: Expand glob patterns against the real filesystem.
	// Crust runs on the same host as the agent and can check what files
	// actually exist. When a command uses a glob (e.g., "cat ~/.e*"), the
	// shell extractor preserves the literal glob since it can't expand it
	// in dry-run mode. We expand it here using filepath.Glob so that
	// "~/.e*" resolves to "~/.env" (if it exists) and the normal matcher
	// catches it precisely — no heuristic reverse-glob needed.
	// If the glob matches nothing, the path is dropped (nothing to protect).
	normalizedPaths = expandFileGlobs(normalizedPaths)

	// Step 2.5: Block /proc access (Linux-only, no-op on other platforms).
	// /proc exposes process environ, cmdline, memory — all sensitive.
	// Hardcoded in Go (not YAML) so it cannot be tampered with.
	// Check BEFORE symlink resolution: EvalSymlinks on /proc/self/fd/N resolves
	// to the target file, losing the /proc/ prefix. The normalizer already
	// maps /dev/fd → /proc/self/fd so traversals like /dev/fd/../environ match.
	if blocked, path := hasProcPath(normalizedPaths); blocked {
		return MatchResult{
			Matched:  true,
			RuleName: "builtin:protect-proc",
			Severity: SeverityCritical,
			Action:   ActionBlock,
			Message:  fmt.Sprintf("Cannot access %s — /proc may expose secrets, API keys, and process memory", path),
		}
	}

	// Step 2.9: Resolve symlinks for rule matching (after proc check).
	// Match against BOTH pre-resolved and post-resolved paths so rules work
	// regardless of whether they use symlink paths or real paths.
	// Example: on macOS /etc is a symlink to /private/etc — a rule for
	// "/etc/passwd" matches the pre-resolved path, while "/private/etc/passwd"
	// matches the resolved path. User-created symlinks (ln -s ~/.ssh/id_rsa
	// /tmp/x) are caught by the resolved path matching the SSH key rule.
	resolvedPaths := e.normalizer.resolveSymlinks(normalizedPaths)
	allPaths := mergeUnique(normalizedPaths, resolvedPaths)

	// Step 3: Evaluate operation-based rules (for known tools)
	if info.Operation != OpNone {
		if result := e.evaluateOperationRules(rules, info, allPaths, call.Name); result.Matched {
			return result
		}
	}

	// Step 4: Fallback rules (content-only) - matches raw JSON of ANY tool including MCP
	// Uses RawJSON (full payload) so extractContentField overwrites don't hide fields.
	// Uses pre-compiled content regex from CompiledMatch when available.
	contentForRules := info.RawJSON
	if contentForRules == "" {
		contentForRules = info.Content
	}
	for _, compiled := range rules {
		if !compiled.Rule.IsEnabled() {
			continue
		}
		if compiled.Rule.IsContentOnly() && contentForRules != "" {
			// Respect actions filter if rule specifies actions.
			// E.g., detect-private-key-write with actions:[write] should NOT
			// fire on read operations (grep "PRIVATE KEY" *.py).
			// OpNone (unknown tools, MCP plugins) still matches regardless —
			// preserves catch-all behavior for unrecognized tools.
			if info.Operation != OpNone && !compiled.Rule.HasAction(info.Operation) {
				continue
			}
			contentMatched := false
			if compiled.MatchCompiled != nil {
				// Use pre-compiled pattern
				if compiled.MatchCompiled.ContentRegex != nil {
					contentMatched = compiled.MatchCompiled.ContentRegex.MatchString(contentForRules)
				} else {
					// Literal match (case-insensitive substring)
					contentMatched = containsIgnoreCase(contentForRules, compiled.MatchCompiled.Match.Content)
				}
			}
			if contentMatched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, "")
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
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, matchedPath)
			}
		}

		// Check host matching whenever hosts are extracted (not just OpNetwork).
		// This enables host rules to fire for scp (OpCopy), rsync, etc.
		// The HasAction check at the top of this loop still scopes correctly.
		if compiled.HostMatcher != nil && len(info.Hosts) > 0 {
			matched, matchedHost := compiled.HostMatcher.MatchAny(info.Hosts)
			if matched {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, matchedHost)
			}
		}

		// Evaluate advanced match conditions using pre-compiled patterns (Level 4+)
		if compiled.MatchCompiled != nil {
			if e.evaluateMatchCompiled(compiled.MatchCompiled, info, normalizedPaths, toolName) {
				e.incrementHitCount(compiled.Rule.Name)
				return blockResult(&compiled.Rule, "")
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
				return blockResult(&compiled.Rule, "")
			}
		}

		// Evaluate AnyConditions (OR logic - any condition matches) using pre-compiled patterns
		if len(compiled.AnyCompiledMatches) > 0 {
			for i := range compiled.AnyCompiledMatches {
				if e.evaluateMatchCompiled(&compiled.AnyCompiledMatches[i], info, normalizedPaths, toolName) {
					e.incrementHitCount(compiled.Rule.Name)
					return blockResult(&compiled.Rule, "")
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
		if !matchAnyRegexGlob(normalizedPaths, cm.PathRegex, cm.PathGlob, "") {
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
			if !containsIgnoreCase(info.Command, cm.Match.Command) {
				return false
			}
		}
	}

	// Host matching — use pre-compiled regex, glob, or literal
	if cm.Match.Host != "" {
		if !matchAnyRegexGlob(info.Hosts, cm.HostRegex, cm.HostGlob, cm.Match.Host) {
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

// patternKind returns "regex" or "glob" based on the pattern prefix.
func patternKind(pattern string) string {
	if strings.HasPrefix(pattern, "re:") {
		return "regex"
	}
	return "glob"
}

// compilePattern compiles a pattern as either a regex (if "re:" prefixed) or a glob.
// The separator is used for glob compilation ('/' for paths, '.' for hosts).
func compilePattern(pattern string, separator rune) (*regexp.Regexp, glob.Glob, error) {
	if strings.HasPrefix(pattern, "re:") {
		re, err := compileRegex(pattern[3:])
		return re, nil, err
	}
	g, err := glob.Compile(pattern, separator)
	return nil, g, err
}

// matchAnyRegexGlob returns true if any item matches the regex, glob, or literal.
// Pass nil for unused matchers. Literal is only checked if both re and g are nil.
func matchAnyRegexGlob(items []string, re *regexp.Regexp, g glob.Glob, literal string) bool {
	for _, item := range items {
		if re != nil {
			if re.MatchString(item) {
				return true
			}
		} else if g != nil {
			if g.Match(item) {
				return true
			}
		} else if item == literal {
			return true
		}
	}
	return false
}

// matchTools checks if toolName (lowercase) is in the list of allowed tools
func matchTools(tools []string, toolName string) bool {
	toolLower := strings.ToLower(toolName)
	return slices.Contains(tools, toolLower)
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

// blockResult creates a MatchResult for a blocking rule match.
// If matchedValue is non-empty, {path} and {host} placeholders in the message are expanded.
func blockResult(rule *Rule, matchedValue string) MatchResult {
	msg := rule.Message
	if matchedValue != "" {
		msg = strings.Replace(msg, "{path}", matchedValue, 1)
		msg = strings.Replace(msg, "{host}", matchedValue, 1)
	}
	return MatchResult{
		Matched:  true,
		RuleName: rule.Name,
		Severity: rule.GetSeverity(),
		Action:   ActionBlock,
		Message:  msg,
	}
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
	return extractRules(e.builtin)
}

// GetUserRules returns only user rules
func (e *Engine) GetUserRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return extractRules(e.user)
}

// extractRules converts a slice of CompiledRule to a slice of Rule.
func extractRules(compiled []CompiledRule) []Rule {
	rules := make([]Rule, len(compiled))
	for i, cr := range compiled {
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
	e.mu.RLock()
	cbs := make([]ReloadCallback, len(e.onReloadCallbacks))
	copy(cbs, e.onReloadCallbacks)
	e.mu.RUnlock()
	for _, cb := range cbs {
		go cb(rules) // Non-blocking
	}
}

// sanitizePattern rejects patterns containing null bytes or control characters.
// Returns an error so the user gets a clear message about what's wrong.
func sanitizePattern(pattern string) error {
	for i := range len(pattern) {
		if pattern[i] == 0 {
			return fmt.Errorf("pattern contains null byte at position %d", i)
		}
		if pattern[i] < 0x20 && pattern[i] != '\t' {
			return fmt.Errorf("pattern contains control character 0x%02x at position %d", pattern[i], i)
		}
	}
	return nil
}

// sanitizePatterns validates a slice of patterns, returning a contextual error.
func sanitizePatterns(patterns []string, ruleName, fieldName string) error {
	for i, p := range patterns {
		if err := sanitizePattern(p); err != nil {
			return fmt.Errorf("rule %q %s[%d]: %w", ruleName, fieldName, i, err)
		}
	}
	return nil
}

// compileMatchConditions compiles a slice of Match conditions into CompiledMatch values.
func compileMatchConditions(conditions []Match, ruleName, condType string) ([]CompiledMatch, error) {
	var compiled []CompiledMatch
	for i, cond := range conditions {
		cm, err := compileMatchPattern(&cond)
		if err != nil {
			return nil, fmt.Errorf("rule %q %s[%d]: %w", ruleName, condType, i, err)
		}
		if cm != nil {
			compiled = append(compiled, *cm)
		}
	}
	return compiled, nil
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
		re, g, err := compilePattern(m.Path, '/')
		if err != nil {
			return nil, fmt.Errorf("match.path %s %q: %w", patternKind(m.Path), m.Path, err)
		}
		cm.PathRegex, cm.PathGlob = re, g
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
		re, g, err := compilePattern(m.Host, '.')
		if err != nil {
			return nil, fmt.Errorf("match.host %s %q: %w", patternKind(m.Host), m.Host, err)
		}
		cm.HostRegex, cm.HostGlob = re, g
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
	for _, check := range []struct {
		patterns []string
		field    string
	}{
		{rule.Block.Paths, "block.paths"},
		{rule.Block.Except, "block.except"},
		{rule.Block.Hosts, "block.hosts"},
	} {
		if err := sanitizePatterns(check.patterns, rule.Name, check.field); err != nil {
			return CompiledRule{}, err
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

	// Compile AllConditions (AND logic) and AnyConditions (OR logic)
	allCompiled, err := compileMatchConditions(rule.AllConditions, rule.Name, "all")
	if err != nil {
		return CompiledRule{}, err
	}
	anyCompiled, err := compileMatchConditions(rule.AnyConditions, rule.Name, "any")
	if err != nil {
		return CompiledRule{}, err
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
	slices.SortFunc(all, func(a, b CompiledRule) int {
		return cmp.Compare(a.Rule.GetPriority(), b.Rule.GetPriority())
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

// mergeUnique returns the union of two string slices, preserving order and
// removing duplicates. Used to combine pre-symlink and post-symlink resolved
// paths so that rule patterns match against both forms.
func mergeUnique(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	for _, s := range b {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// incrementHitCount increments the hit count for a rule.
// Acquires RLock to safely read the hitCounts map, which may be written
// by rebuildMergedLocked during concurrent ReloadUserRules.
func (e *Engine) incrementHitCount(name string) {
	e.mu.RLock()
	count := e.hitCounts[name]
	e.mu.RUnlock()
	if count != nil {
		atomic.AddInt64(count, 1)
	}
}

// expandFileGlobs expands paths containing glob metacharacters against the
// real filesystem. Crust runs locally on the same host as the agent, so it
// can resolve globs to actual files. This replaces the heuristic reverse-glob
// matcher with precise filesystem checks:
//   - "cat /home/user/.e*" → filepath.Glob finds /home/user/.env → blocked
//   - "tar -C /tmp/*" → filepath.Glob finds /tmp/foo, /tmp/bar → not protected → allowed
//   - "cat /home/user/.b*" → filepath.Glob finds /home/user/.bashrc → not protected → allowed
//
// If a glob matches no files, the path is dropped — there's nothing to protect.
// Non-glob paths pass through unchanged.
func expandFileGlobs(paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if !containsGlob(p) {
			result = append(result, p)
			continue
		}
		matches, err := filepath.Glob(p)
		if err != nil || len(matches) == 0 {
			continue
		}
		result = append(result, matches...)
	}
	return result
}

// filterShellGlobs removes bare shell glob patterns from a path list.
// The shell parser may extract glob patterns (e.g., "*" from "<*" redirections)
// as file paths. These are not real paths — the shell would expand them before
// any file operation. A bare "*" normalized to "/cwd/*" falsely matches any
// protected glob pattern like "**/.env".
//
// Only filters paths that consist entirely of glob metacharacters and digits
// (e.g., "*", "?", "0000", "*.txt"). Real file paths with glob chars in
// directory components (already quoted in shell) are unaffected because they
// contain non-glob path characters like "/".
func filterShellGlobs(paths []string) []string {
	result := paths[:0] // reuse backing array
	for _, p := range paths {
		if isShellGlob(p) {
			continue
		}
		result = append(result, p)
	}
	return result
}

// isShellGlob returns true if the path is a bare shell glob pattern
// (no path separators) that should not be treated as a real file path.
// The shell parser may extract glob patterns (e.g., "*" from "<*"
// redirections) as file paths. These are not real paths — the shell
// would expand them before any file operation.
//
// Only filters paths WITHOUT path separators (e.g., "*", "?.txt").
// Paths WITH separators like "/home/user/.ssh/id_*" are kept because
// they reference real file system locations and must be checked.
func isShellGlob(p string) bool {
	if p == "" {
		return false
	}
	// If it contains a path separator, it's a real path reference
	if strings.ContainsRune(p, '/') || strings.ContainsRune(p, '\\') {
		return false
	}
	// Must contain at least one glob metacharacter
	for _, r := range p {
		switch r {
		case '*', '?', '[':
			return true
		}
	}
	return false
}
