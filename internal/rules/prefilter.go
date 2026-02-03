package rules

import (
	"regexp"
	"strings"
)

// PreFilter detects obfuscation and dangerous patterns BEFORE path extraction.
// This catches evasion techniques that path-based matching would miss.
type PreFilter struct {
	patterns []*CompiledPreFilterPattern
}

// CompiledPreFilterPattern is a pre-compiled obfuscation pattern
type CompiledPreFilterPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Reason  string
}

// PreFilterMatch represents a match from the pre-filter
type PreFilterMatch struct {
	PatternName string
	Reason      string
	Matched     string // The matched substring
}

// NewPreFilter creates a new PreFilter with default obfuscation patterns
func NewPreFilter() *PreFilter {
	pf := &PreFilter{}
	pf.compilePatterns(defaultPreFilterPatterns)
	return pf
}

// NewPreFilterWithPatterns creates a PreFilter with custom patterns
func NewPreFilterWithPatterns(patterns []PreFilterPatternDef) *PreFilter {
	pf := &PreFilter{}
	pf.compilePatterns(patterns)
	return pf
}

// PreFilterPatternDef defines an obfuscation pattern
type PreFilterPatternDef struct {
	Name    string
	Pattern string
	Reason  string
}

// compilePatterns compiles the pattern definitions
func (pf *PreFilter) compilePatterns(defs []PreFilterPatternDef) {
	pf.patterns = make([]*CompiledPreFilterPattern, 0, len(defs))
	for _, def := range defs {
		re, err := regexp.Compile(def.Pattern)
		if err != nil {
			// Skip invalid patterns but log them
			log.Warn("Invalid pre-filter pattern %s: %v", def.Name, err)
			continue
		}
		pf.patterns = append(pf.patterns, &CompiledPreFilterPattern{
			Name:    def.Name,
			Pattern: re,
			Reason:  def.Reason,
		})
	}
}

// Check checks a command for obfuscation patterns.
// Returns the first match found, or nil if no patterns match.
func (pf *PreFilter) Check(cmd string) *PreFilterMatch {
	for _, p := range pf.patterns {
		if match := p.Pattern.FindString(cmd); match != "" {
			return &PreFilterMatch{
				PatternName: p.Name,
				Reason:      p.Reason,
				Matched:     match,
			}
		}
	}
	return nil
}

// CheckAll checks a command and returns ALL matches (for comprehensive logging)
func (pf *PreFilter) CheckAll(cmd string) []*PreFilterMatch {
	var matches []*PreFilterMatch
	for _, p := range pf.patterns {
		if match := p.Pattern.FindString(cmd); match != "" {
			matches = append(matches, &PreFilterMatch{
				PatternName: p.Name,
				Reason:      p.Reason,
				Matched:     match,
			})
		}
	}
	return matches
}

// ContainsObfuscation is a quick check that returns true if any obfuscation is detected
func (pf *PreFilter) ContainsObfuscation(cmd string) bool {
	return pf.Check(cmd) != nil
}

// defaultPreFilterPatterns contains patterns for common obfuscation techniques
var defaultPreFilterPatterns = []PreFilterPatternDef{
	// Command substitution - used to hide commands
	{
		Name:    "command-substitution-dollar",
		Pattern: `\$\([^)]+\)`,
		Reason:  "command substitution $()",
	},
	{
		Name:    "command-substitution-backtick",
		Pattern: "`[^`]+`",
		Reason:  "command substitution backticks",
	},

	// Eval - executes strings as commands
	{
		Name:    "eval-keyword",
		Pattern: `\beval\s+`,
		Reason:  "eval command execution",
	},

	// Base64 decoding - commonly used to hide payloads
	{
		Name:    "base64-decode",
		Pattern: `base64\s+(-d|--decode)`,
		Reason:  "base64 decode (hiding payload)",
	},
	{
		Name:    "base64-pipe-decode",
		Pattern: `\|\s*base64\s+(-d|--decode)`,
		Reason:  "piped base64 decode",
	},

	// Hex encoding
	{
		Name:    "hex-escape",
		Pattern: `\\x[0-9a-fA-F]{2}`,
		Reason:  "hex escape sequence",
	},
	{
		Name:    "printf-escape",
		Pattern: `printf\s+['"]\\`,
		Reason:  "printf with escapes",
	},

	// Indirect variable expansion
	{
		Name:    "indirect-expansion",
		Pattern: `\$\{![^}]+\}`,
		Reason:  "indirect variable expansion",
	},

	// Environment variable tricks
	{
		Name:    "ifs-manipulation",
		Pattern: `\bIFS\s*=`,
		Reason:  "IFS manipulation (word splitting attack)",
	},

	// Network exfiltration patterns
	{
		Name:    "curl-data-at",
		Pattern: `curl\s+.*(-d|--data)\s+@`,
		Reason:  "curl sending file contents",
	},
	{
		Name:    "curl-upload-file",
		Pattern: `curl\s+.*--upload-file`,
		Reason:  "curl file upload",
	},
	{
		Name:    "nc-exec",
		Pattern: `nc\s+.*-e`,
		Reason:  "netcat with execution (reverse shell)",
	},

	// Fork bomb patterns
	{
		Name:    "fork-bomb",
		Pattern: `:\(\)\s*\{[^}]*:\s*\|`,
		Reason:  "fork bomb pattern",
	},
	{
		Name:    "fork-bomb-named",
		Pattern: `\w+\(\)\s*\{\s*\w+\s*\|\s*\w+\s*&`,
		Reason:  "named fork bomb pattern",
	},

	// Process substitution
	{
		Name:    "process-substitution",
		Pattern: `<\([^)]+\)|>\([^)]+\)`,
		Reason:  "process substitution",
	},
}

// IsSafeCommand performs a quick safety check on a command.
// Returns true if the command appears safe, false if it contains suspicious patterns.
// This is a convenience wrapper for simple use cases.
func IsSafeCommand(cmd string) bool {
	// Quick string checks before regex (performance)
	suspicious := []string{
		"$(", "`", "eval ", "base64 -d", "base64 --decode",
		"\\x", "${!", "IFS=", ":()", "-e /bin",
	}
	cmdLower := strings.ToLower(cmd)
	for _, s := range suspicious {
		if strings.Contains(cmdLower, s) {
			return false
		}
	}
	return true
}
