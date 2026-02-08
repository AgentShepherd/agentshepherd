package rules

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
	"mvdan.cc/sh/v3/syntax"
)

// InputSanitizer provides security-focused input normalization.
// This helps prevent bypass attacks using encoding tricks, path obfuscation, etc.
type InputSanitizer struct {
	// Patterns for detecting nested command execution
	nestedCmdPatterns []*regexp.Regexp

	// Patterns for detecting shell variable expansion
	shellVarPatterns []*regexp.Regexp
}

// NewInputSanitizer creates a new sanitizer with compiled patterns.
func NewInputSanitizer() *InputSanitizer {
	s := &InputSanitizer{}

	// Nested command patterns: sh -c, bash -c, eval, xargs, find -exec, etc.
	nestedPatterns := []string{
		`(?i)(^|[;&|])\s*(sh|bash|zsh|ksh|dash|csh|tcsh|fish)\s+(-c|-i)\s`,
		`(?i)(^|[;&|])\s*eval\s`,
		`(?i)(^|[;&|])\s*xargs\s`,
		`(?i)\s+-exec\s`,
		`(?i)(^|[;&|])\s*source\s`,
		`(?i)(^|[;&|])\s*\.\s+`,
	}
	for _, p := range nestedPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.nestedCmdPatterns = append(s.nestedCmdPatterns, re)
		}
	}

	// Shell variable patterns: $VAR, ${VAR}, $(cmd), `cmd`
	varPatterns := []string{
		`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`,
		`\$\([^)]+\)`,
		"`[^`]+`",
	}
	for _, p := range varPatterns {
		if re, err := regexp.Compile(p); err == nil {
			s.shellVarPatterns = append(s.shellVarPatterns, re)
		}
	}

	return s
}

// SanitizeToolName removes dangerous characters from tool names.
func (s *InputSanitizer) SanitizeToolName(name string) string {
	// Remove null bytes
	name = stripNullBytes(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	// Remove control characters
	name = stripControlChars(name)

	return name
}

// SanitizeCommand normalizes a command string for consistent matching.
func (s *InputSanitizer) SanitizeCommand(cmd string) string {
	// Remove null bytes
	cmd = stripNullBytes(cmd)

	// Normalize whitespace (collapse multiple spaces/tabs to single space)
	cmd = normalizeWhitespace(cmd)

	// Trim leading/trailing whitespace
	cmd = strings.TrimSpace(cmd)

	// SECURITY: Normalize paths within the command
	cmd = normalizePathsInCommand(cmd)

	return cmd
}

// normalizePathsInCommand finds and normalizes file paths within a command string.
// Uses mvdan/sh to properly parse shell syntax and only normalize literal paths.
// SECURITY: Preserves shell special characters ($, `, *, etc.) needed for
// pattern matching against variable expansion and command substitution.
func normalizePathsInCommand(cmd string) string {
	// Fast path: if no path-like content, skip parsing
	if !strings.Contains(cmd, "/") {
		return cmd
	}

	// Fast path: if contains shell special chars in paths, use regex fallback
	// This handles cases like /proc/$PID where we want to preserve the structure
	if containsShellSpecialInPath(cmd) {
		return normalizePathsRegex(cmd)
	}

	// Use shell parser for proper handling
	return normalizePathsShellParse(cmd)
}

// containsShellSpecialInPath checks if the command has shell special chars after /
func containsShellSpecialInPath(cmd string) bool {
	specialAfterSlash := []string{"/$", "/`", "/*", "/("}
	for _, s := range specialAfterSlash {
		if strings.Contains(cmd, s) {
			return true
		}
	}
	return false
}

// normalizePathsRegex is the fast regex-based fallback for commands with shell special chars.
func normalizePathsRegex(cmd string) string {
	// Match complete absolute paths (not containing shell special chars)
	absPathRe := regexp.MustCompile(`(/[a-zA-Z0-9_./-]+)`)

	return absPathRe.ReplaceAllStringFunc(cmd, func(path string) string {
		normalized := filepath.Clean(path)
		if strings.HasPrefix(path, "/") && !strings.HasPrefix(normalized, "/") {
			normalized = "/" + normalized
		}
		if strings.HasSuffix(path, "/") && !strings.HasSuffix(normalized, "/") {
			normalized = normalized + "/"
		}
		return normalized
	})
}

// normalizePathsShellParse uses mvdan/sh to properly parse and normalize paths.
func normalizePathsShellParse(cmd string) string {
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))

	// Parse the command
	file, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		// If parsing fails, fall back to regex
		return normalizePathsRegex(cmd)
	}

	// Track replacements: original position -> normalized string
	var replacements []pathReplacement

	// Walk the AST to find literal words that look like paths
	syntax.Walk(file, func(node syntax.Node) bool {
		if word, ok := node.(*syntax.Word); ok {
			// Check if this word is a simple literal (no expansions)
			if isLiteralWord(word) {
				lit := getLiteralValue(word)
				if isAbsolutePath(lit) {
					normalized := filepath.Clean(lit)
					if strings.HasPrefix(lit, "/") && !strings.HasPrefix(normalized, "/") {
						normalized = "/" + normalized
					}
					if normalized != lit {
						// Safe conversion: command strings are always small
						startPos := word.Pos().Offset()
						endPos := word.End().Offset()
						if startPos <= uint(len(cmd)) && endPos <= uint(len(cmd)) {
							replacements = append(replacements, pathReplacement{
								start: int(startPos), //nolint:gosec // bounds checked above
								end:   int(endPos),   //nolint:gosec // bounds checked above
								value: normalized,
							})
						}
					}
				}
			}
		}
		return true
	})

	// Apply replacements in reverse order to preserve positions
	if len(replacements) == 0 {
		return cmd
	}

	result := []byte(cmd)
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		result = append(result[:r.start], append([]byte(r.value), result[r.end:]...)...)
	}

	return string(result)
}

type pathReplacement struct {
	start int
	end   int
	value string
}

// isLiteralWord checks if a word contains only literal parts (no expansions)
func isLiteralWord(word *syntax.Word) bool {
	for _, part := range word.Parts {
		if _, ok := part.(*syntax.Lit); !ok {
			return false
		}
	}
	return true
}

// getLiteralValue extracts the literal string value from a word
func getLiteralValue(word *syntax.Word) string {
	var buf bytes.Buffer
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok {
			buf.WriteString(lit.Value)
		}
	}
	return buf.String()
}

// isAbsolutePath checks if a string looks like an absolute path
func isAbsolutePath(s string) bool {
	return strings.HasPrefix(s, "/") && len(s) > 1
}

// SanitizePath normalizes a file path for consistent matching.
func (s *InputSanitizer) SanitizePath(path string) string {
	// Remove null bytes
	path = stripNullBytes(path)

	// Trim whitespace
	path = strings.TrimSpace(path)

	// Normalize path (resolve ., .., //)
	path = normalizePath(path)

	return path
}

// NormalizeForMatching prepares a string for case-insensitive regex matching.
// Returns both the original (sanitized) and lowercase versions.
func (s *InputSanitizer) NormalizeForMatching(value string) (original, lower string) {
	original = stripNullBytes(value)
	lower = strings.ToLower(original)
	return
}

// ExtractNestedCommands extracts commands from shell wrappers.
// e.g., "sh -c 'rm -rf /'" -> returns ["rm -rf /"]
func (s *InputSanitizer) ExtractNestedCommands(cmd string) []string {
	var nested []string

	// Pattern to extract content from: sh -c 'content' or sh -c "content"
	shellCmdRe := regexp.MustCompile(`(?i)(sh|bash|zsh|ksh)\s+(-c|-i)\s+['"]([^'"]+)['"]`)
	matches := shellCmdRe.FindAllStringSubmatch(cmd, -1)
	for _, m := range matches {
		if len(m) > 3 {
			nested = append(nested, m[3])
		}
	}

	// Pattern for eval 'content'
	evalRe := regexp.MustCompile(`(?i)eval\s+['"]([^'"]+)['"]`)
	evalMatches := evalRe.FindAllStringSubmatch(cmd, -1)
	for _, m := range evalMatches {
		if len(m) > 1 {
			nested = append(nested, m[1])
		}
	}

	return nested
}

// ExpandCommonVariables expands well-known shell variables for matching.
// This is a heuristic - we can't know actual values, but we can detect patterns.
func (s *InputSanitizer) ExpandCommonVariables(cmd string) string {
	// Replace common variables with patterns that match their typical content
	replacements := map[string]string{
		"$HOME":     "~",
		"${HOME}":   "~",
		"$USER":     "*",
		"${USER}":   "*",
		"$PWD":      ".",
		"${PWD}":    ".",
		"$OLDPWD":   "..",
		"${OLDPWD}": "..",
	}

	result := cmd
	for from, to := range replacements {
		result = strings.ReplaceAll(result, from, to)
	}

	return result
}

// HasShellVariables checks if the input contains shell variable references.
func (s *InputSanitizer) HasShellVariables(cmd string) bool {
	for _, re := range s.shellVarPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// HasNestedCommands checks if the input contains nested command execution.
func (s *InputSanitizer) HasNestedCommands(cmd string) bool {
	for _, re := range s.nestedCmdPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// stripNullBytes removes null bytes and other dangerous characters.
func stripNullBytes(s string) string {
	return strings.Map(func(r rune) rune {
		if r == 0 {
			return -1 // Drop null bytes
		}
		return r
	}, s)
}

// stripControlChars removes ASCII control characters (except tab, newline).
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}

// normalizeWhitespace collapses multiple whitespace chars to single space.
// Handles all characters that unicode.IsSpace/strings.TrimSpace considers whitespace,
// ensuring SanitizeCommand is idempotent.
func normalizeWhitespace(s string) string {
	// Replace all whitespace variants with regular space
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\v", " ")
	s = strings.ReplaceAll(s, "\f", " ")

	// Collapse multiple spaces
	spaceRe := regexp.MustCompile(` {2,}`)
	return spaceRe.ReplaceAllString(s, " ")
}

// normalizePath normalizes a filesystem path.
func normalizePath(path string) string {
	if path == "" {
		return path
	}

	// Handle home directory
	if strings.HasPrefix(path, "~/") || path == "~" {
		// Keep ~ as-is for matching purposes
		return path
	}

	// Use filepath.Clean to resolve . and ..
	// But preserve leading / for absolute paths
	isAbs := strings.HasPrefix(path, "/")
	cleaned := filepath.Clean(path)

	// filepath.Clean removes leading //, we want to normalize that
	if isAbs && !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}

// NormalizeUnicode applies NFKC normalization and cross-script confusable stripping.
// NFKC handles fullwidth→ASCII, compatibility decomposition, etc.
// stripConfusables handles Cyrillic/Greek homoglyphs (а→a, е→e, etc.).
func NormalizeUnicode(s string) string {
	s = norm.NFKC.String(s)
	return stripConfusables(s)
}

// IsSuspiciousInput checks for common evasion patterns.
func IsSuspiciousInput(s string) (suspicious bool, reasons []string) {
	// Check for null bytes
	if strings.ContainsRune(s, 0) {
		suspicious = true
		reasons = append(reasons, "contains null bytes")
	}

	// Check for fullwidth characters
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			suspicious = true
			reasons = append(reasons, "contains fullwidth characters")
			break
		}
	}

	// Check for cross-script confusable characters
	for _, r := range s {
		if _, ok := confusableMap[r]; ok {
			suspicious = true
			reasons = append(reasons, "contains cross-script confusable characters")
			break
		}
	}

	// Check for excessive path traversal
	if strings.Count(s, "..") > 3 {
		suspicious = true
		reasons = append(reasons, "excessive path traversal")
	}

	// Check for very long repeated patterns (potential ReDoS)
	if len(s) > 10000 {
		suspicious = true
		reasons = append(reasons, "excessively long input")
	}

	// Check for control characters
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			suspicious = true
			reasons = append(reasons, "contains control characters")
			break
		}
	}

	return
}

// Global sanitizer instance
var defaultSanitizer = NewInputSanitizer()

// GetSanitizer returns the default input sanitizer.
func GetSanitizer() *InputSanitizer {
	return defaultSanitizer
}
