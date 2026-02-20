package rules

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BakeLens/crust/internal/tui"
	"gopkg.in/yaml.v3"
)

// LintSeverity represents the severity of a lint issue.
type LintSeverity string

// Lint severity levels (distinct from rule Severity).
const (
	LintError   LintSeverity = "error"
	LintWarning LintSeverity = "warning"
	LintInfo    LintSeverity = "info"
)

// LintIssue represents a problem found in a rule.
type LintIssue struct {
	RuleName string
	Field    string
	Severity LintSeverity
	Message  string
}

// LintResult contains all issues found during linting.
type LintResult struct {
	Issues []LintIssue
	Errors int
	Warns  int
}

// Linter validates security rules for common mistakes.
type Linter struct {
	// Regex patterns that are likely mistakes
	suspiciousPatterns []suspiciousPattern
}

type suspiciousPattern struct {
	pattern *regexp.Regexp
	message string
}

// NewLinter creates a new rule linter.
func NewLinter() *Linter {
	l := &Linter{}

	// Patterns that indicate likely mistakes in glob patterns
	suspicious := []struct {
		re  string
		msg string
	}{
		// Pattern starts with ** without / (might be mistake)
		{`^\*\*[^/]`, "pattern starts with '**' without '/' - did you mean '**/...'?"},
	}

	for _, s := range suspicious {
		if re, err := regexp.Compile(s.re); err == nil {
			l.suspiciousPatterns = append(l.suspiciousPatterns, suspiciousPattern{
				pattern: re,
				message: s.msg,
			})
		}
	}

	return l
}

// LintRules validates a list of path-based rules and returns all issues found.
func (l *Linter) LintRules(rules []Rule) LintResult {
	result := LintResult{}
	seenNames := make(map[string]bool)

	for _, rule := range rules {
		// Check for duplicate names
		if seenNames[rule.Name] {
			result.Issues = append(result.Issues, LintIssue{
				RuleName: rule.Name,
				Field:    "name",
				Severity: LintError,
				Message:  "duplicate rule name",
			})
			result.Errors++
		}
		seenNames[rule.Name] = true

		// Check required fields
		issues := l.lintRule(rule)
		for _, issue := range issues {
			result.Issues = append(result.Issues, issue)
			switch issue.Severity {
			case LintError:
				result.Errors++
			case LintWarning:
				result.Warns++
			case LintInfo:
				// info items don't increment counters
			}
		}
	}

	return result
}

func (l *Linter) lintRule(rule Rule) []LintIssue {
	var issues []LintIssue

	// Check required fields
	if rule.Name == "" {
		issues = append(issues, LintIssue{
			RuleName: "(unnamed)",
			Field:    "name",
			Severity: LintError,
			Message:  "rule name is required",
		})
	}

	if rule.Message == "" {
		issues = append(issues, LintIssue{
			RuleName: rule.Name,
			Field:    "message",
			Severity: LintError,
			Message:  "message is required",
		})
	}

	if len(rule.Actions) == 0 {
		issues = append(issues, LintIssue{
			RuleName: rule.Name,
			Field:    "actions",
			Severity: LintError,
			Message:  "at least one action is required",
		})
	}

	// Check for valid actions
	for i, op := range rule.Actions {
		if !ValidActions[op] {
			issues = append(issues, LintIssue{
				RuleName: rule.Name,
				Field:    fmt.Sprintf("actions[%d]", i),
				Severity: LintError,
				Message:  fmt.Sprintf("invalid action: %s", op),
			})
		}
	}

	// Check for matching criteria (simple block, advanced match, or composite)
	hasBlockPaths := len(rule.Block.Paths) > 0
	hasBlockHosts := len(rule.Block.Hosts) > 0
	hasMatch := rule.Match != nil
	hasAllConditions := len(rule.AllConditions) > 0
	hasAnyConditions := len(rule.AnyConditions) > 0

	if !hasBlockPaths && !hasBlockHosts && !hasMatch && !hasAllConditions && !hasAnyConditions {
		issues = append(issues, LintIssue{
			RuleName: rule.Name,
			Field:    "block",
			Severity: LintError,
			Message:  "block.paths, block.hosts, match, all, or any is required",
		})
	}

	// Lint path patterns (simple block format)
	for i, path := range rule.Block.Paths {
		pathIssues := l.lintPathPattern(rule.Name, fmt.Sprintf("block.paths[%d]", i), path)
		issues = append(issues, pathIssues...)
	}

	// Lint except patterns
	for i, path := range rule.Block.Except {
		pathIssues := l.lintPathPattern(rule.Name, fmt.Sprintf("block.except[%d]", i), path)
		issues = append(issues, pathIssues...)
	}

	// Lint advanced match
	if hasMatch {
		matchIssues := l.lintMatch(rule.Name, "match", *rule.Match)
		issues = append(issues, matchIssues...)
	}

	// Lint composite conditions
	for i, cond := range rule.AllConditions {
		matchIssues := l.lintMatch(rule.Name, fmt.Sprintf("all[%d]", i), cond)
		issues = append(issues, matchIssues...)
	}
	for i, cond := range rule.AnyConditions {
		matchIssues := l.lintMatch(rule.Name, fmt.Sprintf("any[%d]", i), cond)
		issues = append(issues, matchIssues...)
	}

	// Try full pattern compilation (catches invalid regex, malformed globs, null bytes, etc.)
	issues = append(issues, l.lintCompilation(rule)...)

	return issues
}

func (l *Linter) lintMatch(ruleName, fieldName string, match Match) []LintIssue {
	var issues []LintIssue

	// Check that match has at least one condition
	if match.Path == "" && match.Command == "" && match.Host == "" && match.Content == "" && len(match.Tools) == 0 {
		issues = append(issues, LintIssue{
			RuleName: ruleName,
			Field:    fieldName,
			Severity: LintError,
			Message:  "match must have at least one field (path, command, host, content, tools)",
		})
	}

	// Lint path pattern if present
	if match.Path != "" {
		pathIssues := l.lintPathPattern(ruleName, fieldName+".path", match.Path)
		issues = append(issues, pathIssues...)
	}

	return issues
}

func (l *Linter) lintPathPattern(ruleName, fieldName, pattern string) []LintIssue {
	var issues []LintIssue

	// Check for empty pattern
	if pattern == "" {
		issues = append(issues, LintIssue{
			RuleName: ruleName,
			Field:    fieldName,
			Severity: LintError,
			Message:  "empty path pattern",
		})
		return issues
	}

	// Check for suspicious patterns
	for _, sp := range l.suspiciousPatterns {
		if sp.pattern.MatchString(pattern) {
			issues = append(issues, LintIssue{
				RuleName: ruleName,
				Field:    fieldName,
				Severity: LintWarning,
				Message:  sp.message,
			})
		}
	}

	// Check for very short patterns (likely too broad)
	if len(pattern) < 3 && !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "*") {
		issues = append(issues, LintIssue{
			RuleName: ruleName,
			Field:    fieldName,
			Severity: LintWarning,
			Message:  "very short pattern may match too broadly",
		})
	}

	return issues
}

// lintCompilation tries to compile the rule's patterns and reports any errors.
// This catches: null bytes, control characters, invalid regex, malformed globs, regex length limits.
func (l *Linter) lintCompilation(rule Rule) []LintIssue {
	_, err := compileOneRule(rule)
	if err != nil {
		return []LintIssue{{
			RuleName: rule.Name,
			Field:    "patterns",
			Severity: LintError,
			Message:  err.Error(),
		}}
	}
	return nil
}

// LintFile loads and lints rules from a YAML file.
// Supports both progressive disclosure format (RuleSetConfig) and legacy format (RuleSet).
func (l *Linter) LintFile(path string) (LintResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LintResult{}, fmt.Errorf("failed to read file: %w", err)
	}

	// Try progressive disclosure format first
	var ruleSetConfig RuleSetConfig
	if err := yaml.Unmarshal(data, &ruleSetConfig); err != nil {
		return LintResult{}, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate the config
	if err := ruleSetConfig.Validate(); err != nil {
		return LintResult{}, fmt.Errorf("validation error: %w", err)
	}

	// Convert to internal Rule format
	rules := ruleSetConfig.ToRules()
	return l.LintRules(rules), nil
}

// LintBuiltin lints the builtin security rules.
func (l *Linter) LintBuiltin() (LintResult, error) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		return LintResult{}, fmt.Errorf("failed to load builtin rules: %w", err)
	}

	return l.LintRules(rules), nil
}

// FormatIssues returns a human-readable string of all issues.
func (r LintResult) FormatIssues(showInfo bool) string {
	if len(r.Issues) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, issue := range r.Issues {
		if issue.Severity == LintInfo && !showInfo {
			continue
		}

		var icon, styledLine string
		if tui.IsPlainMode() {
			switch issue.Severity {
			case LintError:
				icon = "X"
			case LintWarning:
				icon = "!"
			case LintInfo:
				icon = "i"
			default:
				icon = "?"
			}
			styledLine = fmt.Sprintf("  %s [%s] %s: %s - %s\n",
				icon, issue.Severity, issue.RuleName, issue.Field, issue.Message)
		} else {
			switch issue.Severity {
			case LintError:
				icon = tui.StyleError.Render(tui.IconCross)
			case LintWarning:
				icon = tui.StyleWarning.Render(tui.IconWarning)
			case LintInfo:
				icon = tui.StyleInfo.Render(tui.IconInfo)
			default:
				icon = "?"
			}
			severity := tui.SeverityBadge(string(issue.Severity))
			styledLine = fmt.Sprintf("  %s %s %s: %s - %s\n",
				icon, severity, tui.StyleBold.Render(issue.RuleName), issue.Field, issue.Message)
		}
		sb.WriteString(styledLine)
	}

	return sb.String()
}
