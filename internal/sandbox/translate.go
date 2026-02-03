package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
)

// Directive represents a single sandbox directive.
type Directive struct {
	Action    string // "deny" or "allow"
	Operation string // e.g., "file-read*", "file-write*", "file-write-unlink"
	Type      string // "subpath" or "regex"
	Value     string // The path or pattern
}

// String formats the directive as a sandbox profile line.
func (d Directive) String() string {
	action := d.Action
	if action == "" {
		action = "deny" // default to deny for backwards compatibility
	}
	switch d.Type {
	case "subpath":
		return "(" + action + " " + d.Operation + " (subpath \"" + d.Value + "\"))"
	case "regex":
		return "(" + action + " " + d.Operation + " (regex #\"" + d.Value + "\"))"
	default:
		return ""
	}
}

// TranslateRule converts a path-based rule to sandbox directives.
// It generates deny directives for blocked paths and allow directives for exceptions.
// Order matters: exceptions (allow) should come after denies in the profile.
func TranslateRule(rule rules.Rule) []Directive {
	var directives []Directive

	// Convert operations to sandbox operations
	ops := operationsToSandboxOps(rule.Operations)

	// Process path patterns (deny)
	for _, pattern := range rule.Block.Paths {
		expanded := expandHomeDir(pattern)
		sbPattern := globToSandboxRegex(expanded)

		for _, op := range ops {
			directives = append(directives, Directive{
				Action:    "deny",
				Operation: op,
				Type:      "regex",
				Value:     sbPattern,
			})
		}
	}

	// Process exception patterns (allow)
	// Exceptions override the deny rules for specific paths
	for _, pattern := range rule.Block.Except {
		expanded := expandHomeDir(pattern)
		sbPattern := globToSandboxRegex(expanded)

		for _, op := range ops {
			directives = append(directives, Directive{
				Action:    "allow",
				Operation: op,
				Type:      "regex",
				Value:     sbPattern,
			})
		}
	}

	return directives
}

// TranslateRules converts multiple path-based rules to sandbox directives.
func TranslateRules(pbRules []rules.Rule) []Directive {
	var all []Directive
	for _, rule := range pbRules {
		if rule.IsEnabled() {
			all = append(all, TranslateRule(rule)...)
		}
	}
	return all
}

// operationsToSandboxOps maps path-based operations to sandbox operations.
func operationsToSandboxOps(ops []rules.Operation) []string {
	var sandboxOps []string
	seen := make(map[string]bool)

	for _, op := range ops {
		var sbOps []string
		switch op {
		case rules.OpRead:
			sbOps = []string{"file-read*"}
		case rules.OpWrite:
			sbOps = []string{"file-write*"}
		case rules.OpDelete:
			sbOps = []string{"file-write-unlink"}
		case rules.OpCopy:
			sbOps = []string{"file-read*", "file-write*"}
		case rules.OpMove:
			sbOps = []string{"file-read*", "file-write*", "file-write-unlink"}
		case rules.OpExecute:
			sbOps = []string{"process-exec*"}
		case rules.OpNetwork:
			sbOps = []string{"network-outbound"}
		}

		for _, sbOp := range sbOps {
			if !seen[sbOp] {
				seen[sbOp] = true
				sandboxOps = append(sandboxOps, sbOp)
			}
		}
	}

	return sandboxOps
}

// globToSandboxRegex converts a glob pattern to macOS sandbox regex.
func globToSandboxRegex(glob string) string {
	// Use placeholders to avoid clobbering during replacement
	// These are unlikely to appear in real paths
	const (
		doubleStarSlash = "\x00DSS\x00" // **/
		doubleStar      = "\x00DS\x00"  // **
		singleStar      = "\x00SS\x00"  // *
	)

	pattern := glob

	// First, replace glob patterns with placeholders (order matters: longer first)
	pattern = strings.ReplaceAll(pattern, "**/", doubleStarSlash)
	pattern = strings.ReplaceAll(pattern, "**", doubleStar)
	pattern = strings.ReplaceAll(pattern, "*", singleStar)

	// Escape regex metacharacters
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "+", "\\+")
	pattern = strings.ReplaceAll(pattern, "?", ".")
	pattern = strings.ReplaceAll(pattern, "[", "\\[")
	pattern = strings.ReplaceAll(pattern, "]", "\\]")
	pattern = strings.ReplaceAll(pattern, "(", "\\(")
	pattern = strings.ReplaceAll(pattern, ")", "\\)")
	pattern = strings.ReplaceAll(pattern, "^", "\\^")
	pattern = strings.ReplaceAll(pattern, "$", "\\$")
	pattern = strings.ReplaceAll(pattern, "|", "\\|")

	// Escape # which is sandbox delimiter
	pattern = strings.ReplaceAll(pattern, "#", "\\#")

	// Replace placeholders with regex equivalents
	// **/ → (.*/)?  matches zero or more directory levels
	// **  → .*      matches anything
	// *   → [^/]*   matches anything except /
	pattern = strings.ReplaceAll(pattern, doubleStarSlash, "(.*/)?")
	pattern = strings.ReplaceAll(pattern, doubleStar, ".*")
	pattern = strings.ReplaceAll(pattern, singleStar, "[^/]*")

	// Add end anchor if not a directory pattern
	if !strings.HasSuffix(pattern, ".*") && !strings.HasSuffix(pattern, "/)?") {
		pattern += "$"
	}

	return pattern
}

// expandHomeDir expands ~ and $HOME in paths to the actual home directory.
func expandHomeDir(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}

	// Expand ~
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	if path == "~" {
		return home
	}

	// Expand $HOME and ${HOME}
	path = strings.ReplaceAll(path, "$HOME", home)
	path = strings.ReplaceAll(path, "${HOME}", home)

	return path
}

// GenerateSandboxProfile generates a complete sandbox profile from rules.
// Note: In Seatbelt, rules are evaluated in order and first match wins.
// Therefore, allow (exception) rules must come BEFORE deny rules.
func GenerateSandboxProfile(pbRules []rules.Rule) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n\n")
	sb.WriteString("; Auto-generated from path-based rules\n\n")

	for _, rule := range pbRules {
		if !rule.IsEnabled() {
			continue
		}

		sb.WriteString("; Rule: " + rule.Name + "\n")

		directives := TranslateRule(rule)

		// Separate allow (exceptions) and deny directives
		var allowDirectives, denyDirectives []Directive
		for _, d := range directives {
			if d.Action == "allow" {
				allowDirectives = append(allowDirectives, d)
			} else {
				denyDirectives = append(denyDirectives, d)
			}
		}

		// Write allow (exception) rules first (Seatbelt uses first-match)
		if len(allowDirectives) > 0 {
			sb.WriteString("; Exceptions:\n")
			for _, d := range allowDirectives {
				sb.WriteString(d.String() + "\n")
			}
		}

		// Then write deny rules
		for _, d := range denyDirectives {
			sb.WriteString(d.String() + "\n")
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
