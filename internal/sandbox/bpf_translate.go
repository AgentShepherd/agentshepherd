package sandbox

import (
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// BPFMsgType identifies the type of IPC message between the main process
// and the BPF helper daemon. Messages are JSON-encoded, one per line.
type BPFMsgType string

const (
	BPFMsgRules     BPFMsgType = "RULES"     // Main → Helper: update deny rules
	BPFMsgReload    BPFMsgType = "RELOAD"    // Main → Helper: reload from current rules
	BPFMsgPID       BPFMsgType = "PID"       // Main → Helper: add/remove target PID
	BPFMsgOK        BPFMsgType = "OK"        // Helper → Main: success response
	BPFMsgViolation BPFMsgType = "VIOLATION" // Helper → Main: access violation event
	BPFMsgError     BPFMsgType = "ERROR"     // Helper → Main: error response
)

// BPFRequest is sent from the main Crust process to the BPF helper.
type BPFRequest struct {
	Type  BPFMsgType  `json:"type"`
	Rules *BPFDenySet `json:"rules,omitempty"` // for RULES messages
	PID   uint32      `json:"pid,omitempty"`   // for PID messages
	Add   bool        `json:"add"`             // for PID messages: true=add, false=remove
}

// BPFResponse is sent from the BPF helper back to the main process.
type BPFResponse struct {
	Type      BPFMsgType    `json:"type"`
	Count     int           `json:"count,omitempty"`     // for OK: number of rules loaded
	Violation *BPFViolation `json:"violation,omitempty"` // for VIOLATION messages
	Error     string        `json:"error,omitempty"`     // for ERROR messages
}

// BPFViolation represents a denied file access caught by the BPF LSM program.
type BPFViolation struct {
	RuleID    uint32 `json:"rule_id"`
	RuleName  string `json:"rule_name,omitempty"`
	Filename  string `json:"filename"`
	PID       uint32 `json:"pid"`
	Inode     uint64 `json:"inode"`
	Timestamp int64  `json:"timestamp"`
}

// BPFDenyEntry represents a single BPF map entry for deny rules.
type BPFDenyEntry struct {
	Type     string `json:"type"`      // "filename" or "inode"
	Key      string `json:"key"`       // filename for filename type, absolute path for inode type
	RuleID   uint32 `json:"rule_id"`   // numeric rule identifier
	RuleName string `json:"rule_name"` // human-readable rule name
}

// BPFDenySet holds all deny entries derived from rules.
type BPFDenySet struct {
	Filenames  []BPFDenyEntry `json:"filenames"`   // → denied_filenames BPF map
	InodePaths []BPFDenyEntry `json:"inode_paths"` // → resolve to inodes, then denied_inodes map
	Exceptions []string       `json:"exceptions"`  // → allowed_filenames BPF map
}

// TranslateToBPF converts rules to BPF deny/allow entries.
// Rules are classified into filename-based (basename match) or inode-based
// (absolute path, resolved to inode at load time). Content-only rules and
// host/command-only rules are skipped (not translatable to BPF file_open hook).
func TranslateToBPF(allRules []SecurityRule) *BPFDenySet {
	ds := &BPFDenySet{}
	var ruleID uint32
	normalizer := rules.NewNormalizer()

	for _, rule := range allRules {
		if !rule.IsEnabled() {
			continue
		}
		// Skip rules without path patterns (content-only, host-only, command-only)
		if len(rule.GetBlockPaths()) == 0 {
			continue
		}

		ruleID++

		// Process deny patterns
		for _, pattern := range rule.GetBlockPaths() {
			expanded := normalizer.NormalizePattern(pattern)
			entry := classifyPattern(expanded, ruleID, rule.GetName())
			if entry.Type == "filename" {
				ds.Filenames = append(ds.Filenames, entry)
			} else {
				ds.InodePaths = append(ds.InodePaths, entry)
			}
		}

		// Process exception patterns → allowed_filenames
		for _, pattern := range rule.GetBlockExcept() {
			basename := extractBasename(pattern)
			if basename != "" {
				ds.Exceptions = append(ds.Exceptions, basename)
			}
		}
	}

	return ds
}

// classifyPattern determines whether a glob pattern should be matched by
// filename (basename) or by inode (absolute path resolution).
//
// Classification heuristic:
//   - "**/basename"       → filename (basename extracted)
//   - "**/dir/basename"   → filename (basename extracted; parent dir hint ignored for now)
//   - "**/dir/**"         → filename for each known file in dir (defer to inode)
//   - "~/path" or "/path" → inode (absolute path, resolve at load time)
//   - Glob with * in basename (e.g. "id_*") → inode (must expand at load time)
func classifyPattern(pattern string, ruleID uint32, ruleName string) BPFDenyEntry {
	// Absolute or home-relative paths → inode-based
	if strings.HasPrefix(pattern, "/") {
		basename := filepath.Base(pattern)
		// If basename contains glob wildcards, still use inode
		// (helper will expand the glob at load time)
		if containsGlob(basename) {
			return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
		}
		// If pattern ends with /**, it's a directory wildcard → inode
		if strings.HasSuffix(pattern, "/**") {
			return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
		}
		return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
	}

	// Patterns starting with **/ are filename-based (match by basename)
	if strings.HasPrefix(pattern, "**/") {
		rest := strings.TrimPrefix(pattern, "**/")

		// If rest contains another **/, it's a nested wildcard → inode
		if strings.Contains(rest, "**/") {
			return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
		}

		// If rest has directory components (e.g. ".aws/credentials"), use inode
		// to preserve path context. Basename-only matching would block ALL files
		// with that name system-wide (e.g. every file named "credentials" or "config").
		if strings.Contains(rest, "/") {
			return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
		}

		basename := filepath.Base(rest)

		// If basename has glob wildcards (e.g. id_*, key*.db), use inode
		// because BPF hash map needs exact keys
		if containsGlob(basename) {
			return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
		}

		// Pure basename match: **/.env, **/.bashrc, **/Login Data
		return BPFDenyEntry{Type: "filename", Key: basename, RuleID: ruleID, RuleName: ruleName}
	}

	// Fallback: treat as inode-based
	return BPFDenyEntry{Type: "inode", Key: pattern, RuleID: ruleID, RuleName: ruleName}
}

// extractBasename extracts the filename from an exception pattern.
// Returns empty string if the pattern can't be reduced to a simple basename.
func extractBasename(pattern string) string {
	expanded := rules.NewNormalizer().NormalizePattern(pattern)

	// **/basename patterns
	if strings.HasPrefix(expanded, "**/") {
		rest := strings.TrimPrefix(expanded, "**/")
		if !strings.Contains(rest, "/") && !containsGlob(rest) {
			return rest
		}
		// **/dir/basename
		basename := filepath.Base(rest)
		if !containsGlob(basename) {
			return basename
		}
	}

	// Absolute paths
	if strings.HasPrefix(expanded, "/") {
		basename := filepath.Base(expanded)
		if !containsGlob(basename) {
			return basename
		}
	}

	return ""
}

// containsGlob returns true if the string contains glob metacharacters.
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}
