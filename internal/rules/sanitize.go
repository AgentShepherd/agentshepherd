package rules

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// SanitizeToolName removes dangerous characters from tool names.
func SanitizeToolName(name string) string {
	// Remove null bytes
	name = stripNullBytes(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	// Remove control characters
	name = stripControlChars(name)

	return name
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

// NormalizeUnicode applies NFKC normalization and cross-script confusable stripping.
// NFKC handles fullwidth→ASCII, compatibility decomposition, etc.
// stripConfusables handles Cyrillic/Greek homoglyphs (а→a, е→e, etc.).
func NormalizeUnicode(s string) string {
	// SECURITY: Sanitize invalid UTF-8 before NFKC normalization.
	// Invalid bytes (e.g., 0xF5) can interfere with NFKC processing of
	// subsequent valid runes, breaking idempotency.
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = norm.NFKC.String(s)
	s = stripConfusables(s)
	// Re-normalize: confusable replacement (e.g., Cyrillic а→a) can create
	// new composition pairs with adjacent combining marks (e.g., a + U+0323
	// → ạ U+1EA1). Without this second pass, NormalizeUnicode is not idempotent.
	s = norm.NFKC.String(s)
	return s
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
