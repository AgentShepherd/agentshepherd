//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// LandlockMode represents the access mode for a Landlock path entry.
type LandlockMode string

const (
	ModeRO   LandlockMode = "ro"  // Read only (no execute, no write)
	ModeRX   LandlockMode = "rx"  // Read + execute (no write) — system binaries
	ModeRW   LandlockMode = "rw"  // Read + write (NO execute) — data/temp dirs
	ModeRWX  LandlockMode = "rwx" // Full access (read, write, execute)
	ModeNone LandlockMode = "0"   // Not added to ruleset (effectively blocked)
)

// PathMode pairs a filesystem path with its Landlock access mode.
type PathMode struct {
	Path string
	Mode LandlockMode
}

// currentRules holds the rules for intent-aware mode derivation.
// Set via SetRules() from main.go after rule engine initialization.
var currentRules []SecurityRule

// SetRules stores rules for intent-aware Landlock mode derivation.
// Called from main.go after the rule engine is initialized.
func SetRules(allRules []SecurityRule) {
	currentRules = allRules
}

// DerivePathModes analyzes rules and returns a map of $HOME child directories
// to their most restrictive Landlock modes.
func DerivePathModes(allRules []SecurityRule) map[string]LandlockMode {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	// Track per-directory needs: does the rule need to deny reads? writes?
	type accessNeeds struct {
		denyRead  bool
		denyWrite bool
		hasExcept bool // rule has exceptions within this directory
	}
	dirNeeds := make(map[string]*accessNeeds)

	for _, rule := range allRules {
		if !rule.IsEnabled() || len(rule.GetBlockPaths()) == 0 {
			continue
		}

		// Determine what this rule needs to deny
		needsRead, needsWrite := operationDenyNeeds(rule.GetActions())

		// Extract sensitive directories from patterns
		for _, pattern := range rule.GetBlockPaths() {
			dir := extractHomeChildDir(pattern, home)
			if dir == "" {
				continue
			}

			needs, ok := dirNeeds[dir]
			if !ok {
				needs = &accessNeeds{}
				dirNeeds[dir] = needs
			}
			if needsRead {
				needs.denyRead = true
			}
			if needsWrite {
				needs.denyWrite = true
			}
		}

		// Check if exceptions target the same directories
		for _, pattern := range rule.GetBlockExcept() {
			dir := extractHomeChildDir(pattern, home)
			if dir == "" {
				continue
			}
			if needs, ok := dirNeeds[dir]; ok {
				needs.hasExcept = true
			}
		}
	}

	// Convert needs to modes
	modes := make(map[string]LandlockMode, len(dirNeeds))
	for dir, needs := range dirNeeds {
		if needs.hasExcept {
			// Landlock can't express per-file exceptions within a directory.
			// Use rw (no execute) and defer fine-grained control to proxy/BPF.
			modes[dir] = ModeRW
			continue
		}
		if needs.denyRead && needs.denyWrite {
			modes[dir] = ModeNone
		} else if needs.denyWrite && !needs.denyRead {
			modes[dir] = ModeRO
		} else {
			// denyRead only (no Landlock mapping for write-only access)
			// or no deny needs — use rw (no execute), defer to proxy/BPF
			modes[dir] = ModeRW
		}
	}

	return modes
}

// operationDenyNeeds returns whether operations imply denying reads and/or writes.
func operationDenyNeeds(ops []string) (needsRead, needsWrite bool) {
	for _, op := range ops {
		switch Operation(op) {
		case OpRead:
			needsRead = true
		case OpWrite, OpDelete:
			needsWrite = true
		case OpCopy, OpMove:
			// copy and move imply both read and write
			needsRead = true
			needsWrite = true
		case OpExecute:
			// execute doesn't map cleanly to Landlock read/write
		case OpNetwork:
			// network is not filesystem
		}
	}
	return
}

// extractHomeChildDir extracts the first-level $HOME child directory
// that a pattern targets. Returns the full path to the child directory,
// or "" if the pattern doesn't target a $HOME child.
//
// Examples:
//
//	"**/.ssh/id_*"     → "$HOME/.ssh"
//	"**/.aws/credentials" → "$HOME/.aws"
//	"**/.bashrc"       → "" (file in $HOME root, not a directory)
//	"/etc/shadow"      → "" (not under $HOME)
func extractHomeChildDir(pattern string, home string) string {
	// Handle **/ prefix patterns (most common)
	if strings.HasPrefix(pattern, "**/") {
		rest := strings.TrimPrefix(pattern, "**/")
		// Must have at least one directory component (e.g., ".ssh/id_*")
		// Pure basenames like ".bashrc" are files in $HOME root, not directories
		slashIdx := strings.Index(rest, "/")
		if slashIdx <= 0 {
			return "" // no dir component or starts with /
		}
		dirName := rest[:slashIdx]
		if dirName == "" || strings.Contains(dirName, "*") {
			return ""
		}
		return filepath.Join(home, dirName)
	}

	// Handle absolute/home-expanded paths
	expanded := rules.NewNormalizer().NormalizePattern(pattern)
	if !strings.HasPrefix(expanded, home+"/") {
		return "" // not under $HOME
	}

	// Extract first directory component after $HOME
	rel := strings.TrimPrefix(expanded, home+"/")
	slashIdx := strings.Index(rel, "/")
	if slashIdx <= 0 {
		return "" // file directly in $HOME, not a directory
	}
	dirName := rel[:slashIdx]
	return filepath.Join(home, dirName)
}

// IntentAwareAllowPaths generates Landlock allow paths with per-directory modes
// derived from security rules.
func IntentAwareAllowPaths(allRules []SecurityRule) []PathMode {
	modes := DerivePathModes(allRules)

	// System paths: least-privilege modes.
	// rx = execute binaries (no write), ro = read only, rw = write data (no execute).
	result := []PathMode{
		{"/bin", ModeRX},   // execute binaries, no write
		{"/usr", ModeRX},   // execute binaries, no write
		{"/sbin", ModeRX},  // execute binaries, no write
		{"/lib", ModeRO},   // read shared libs (mmap, not execve)
		{"/lib64", ModeRO}, // read shared libs
		{"/tmp", ModeRW},   // read+write temp files, NO execute
		{"/var", ModeRW},   // read+write, NO execute
		{"/dev", ModeRW},   // read+write devices, NO execute
		{"/etc", ModeRO},   // read config files, no write
		{"/sys", ModeRO},   // read sysfs, no write
		{"/run", ModeRW},   // read+write runtime, NO execute
		{"/opt", ModeRX},   // execute optional packages, no write
	}

	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return result
	}

	// Enumerate $HOME first-level children
	entries, err := os.ReadDir(home)
	if err != nil {
		// Fallback: add $HOME with rw
		result = append(result, PathMode{home, ModeRW})
		return result
	}

	seen := make(map[string]bool)
	for _, entry := range entries {
		fullPath := filepath.Join(home, entry.Name())
		seen[fullPath] = true

		if mode, ok := modes[fullPath]; ok {
			if mode != ModeNone {
				result = append(result, PathMode{fullPath, mode})
			}
			// ModeNone: don't add (blocked by Landlock)
		} else {
			result = append(result, PathMode{fullPath, ModeRW})
		}
	}

	// Add CWD if not already covered
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		if !seen[cwd] && !isSubpathOf(cwd, home) {
			result = append(result, PathMode{cwd, ModeRW})
		}
	}

	return result
}

// isSubpathOf returns true if child is the same as or a subdirectory of parent.
func isSubpathOf(child, parent string) bool {
	return child == parent || strings.HasPrefix(child, parent+"/")
}

// defaultPathModes returns system paths with least-privilege modes when no rules are configured.
// Uses the same mode assignments as IntentAwareAllowPaths for system dirs.
func defaultPathModes() []PathMode {
	return []PathMode{
		{"/bin", ModeRX},
		{"/usr", ModeRX},
		{"/sbin", ModeRX},
		{"/lib", ModeRO},
		{"/lib64", ModeRO},
		{"/tmp", ModeRW},
		{"/var", ModeRW},
		{"/dev", ModeRW},
		{"/etc", ModeRO},
		{"/sys", ModeRO},
		{"/run", ModeRW},
		{"/opt", ModeRX},
	}
}
