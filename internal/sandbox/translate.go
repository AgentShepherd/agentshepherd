package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
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
func TranslateRule(rule SecurityRule) []Directive {
	var directives []Directive

	// Convert operations to sandbox operations
	ops := operationsToSandboxOps(rule.GetActions())

	// Use full normalizer for pattern expansion (handles ~, $HOME, $TMPDIR, etc.)
	normalizer := rules.NewNormalizer()

	// Process path patterns (deny)
	for _, pattern := range rule.GetBlockPaths() {
		expanded := normalizer.NormalizePattern(pattern)
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
	for _, pattern := range rule.GetBlockExcept() {
		expanded := normalizer.NormalizePattern(pattern)
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

// operationsToSandboxOps maps path-based operations to sandbox operations.
func operationsToSandboxOps(ops []string) []string {
	var sandboxOps []string
	seen := make(map[string]bool)

	for _, op := range ops {
		var sbOps []string
		switch Operation(op) {
		case OpRead:
			sbOps = []string{"file-read*"}
		case OpWrite:
			sbOps = []string{"file-write*"}
		case OpDelete:
			sbOps = []string{"file-write-unlink"}
		case OpCopy:
			sbOps = []string{"file-read*", "file-write*"}
		case OpMove:
			sbOps = []string{"file-read*", "file-write*", "file-write-unlink"}
		case OpExecute:
			sbOps = []string{"process-exec*"}
		case OpNetwork:
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

	// Escape backslash FIRST (before any other escaping adds backslashes)
	pattern = strings.ReplaceAll(pattern, `\`, `\\`)

	// Escape double-quote (Seatbelt profile string delimiter)
	pattern = strings.ReplaceAll(pattern, `"`, `\"`)

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

	// Add start anchor for absolute path patterns
	if strings.HasPrefix(pattern, "/") {
		pattern = "^" + pattern
	}

	// Add end anchor if not a directory pattern
	if !strings.HasSuffix(pattern, ".*") && !strings.HasSuffix(pattern, "/)?") {
		pattern += "$"
	}

	return pattern
}

// ExpandHomeDir expands ~ and $HOME in paths to the actual home directory.
func ExpandHomeDir(path string) string {
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
