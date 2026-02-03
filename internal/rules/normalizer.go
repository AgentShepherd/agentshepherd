package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pre-compiled regexes for environment variable expansion (performance)
var (
	bracedVarRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	simpleVarRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
)

// Normalizer normalizes paths for consistent matching.
// It handles variable expansion, relative path resolution, and path cleaning.
type Normalizer struct {
	homeDir string
	workDir string
	env     map[string]string
}

// NewNormalizer creates a new Normalizer with the current environment.
// homeDir is obtained from os.UserHomeDir() and workDir from os.Getwd().
func NewNormalizer() *Normalizer {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	workDir, err := os.Getwd()
	if err != nil {
		workDir = ""
	}

	// Build environment map
	env := make(map[string]string)
	for _, e := range os.Environ() {
		if idx := strings.Index(e, "="); idx > 0 {
			env[e[:idx]] = e[idx+1:]
		}
	}

	return &Normalizer{
		homeDir: homeDir,
		workDir: workDir,
		env:     env,
	}
}

// NewNormalizerWithEnv creates a Normalizer with custom home/work directories and environment.
// This is useful for testing.
func NewNormalizerWithEnv(homeDir, workDir string, env map[string]string) *Normalizer {
	if env == nil {
		env = make(map[string]string)
	}
	return &Normalizer{
		homeDir: homeDir,
		workDir: workDir,
		env:     env,
	}
}

// Normalize normalizes a single path.
// Normalization rules (in order):
//  1. Expand ~ to home directory
//  2. Expand $HOME and ${HOME} to home directory
//  3. Expand other environment variables ($VAR, ${VAR})
//  4. Convert relative paths to absolute
//  5. Resolve parent directory references (../)
//  6. Remove duplicate slashes
//  7. Clean the path using filepath.Clean
func (n *Normalizer) Normalize(path string) string {
	if path == "" {
		return ""
	}

	// Step 1: Expand tilde (~)
	path = n.expandTilde(path)

	// Step 2 & 3: Expand environment variables ($HOME, ${HOME}, $VAR, ${VAR})
	path = n.expandEnvVars(path)

	// Step 4: Convert relative paths to absolute
	path = n.makeAbsolute(path)

	// Step 5: Resolve parent directory references
	// Step 6: Remove duplicate slashes
	// Step 7: Clean the path
	path = n.cleanPath(path)

	return path
}

// NormalizeAll normalizes multiple paths.
func (n *Normalizer) NormalizeAll(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = n.Normalize(p)
	}
	return result
}

// expandTilde expands ~ at the beginning of a path to the home directory.
func (n *Normalizer) expandTilde(path string) string {
	if n.homeDir == "" {
		return path
	}

	if path == "~" {
		return n.homeDir
	}

	if strings.HasPrefix(path, "~/") {
		return n.homeDir + path[1:]
	}

	return path
}

// expandEnvVars expands environment variables in a path.
// Supports both $VAR and ${VAR} syntax.
// If a variable doesn't exist, it becomes empty (consistent with shell behavior).
func (n *Normalizer) expandEnvVars(path string) string {
	// Process ${VAR} first, then $VAR to avoid conflicts
	path = bracedVarRe.ReplaceAllStringFunc(path, func(match string) string {
		// Extract variable name from ${VAR}
		varName := match[2 : len(match)-1]
		if val, ok := n.env[varName]; ok {
			return val
		}
		// Variable not found - return empty string to be consistent with shell behavior
		return ""
	})

	// Pattern for $VAR syntax
	path = simpleVarRe.ReplaceAllStringFunc(path, func(match string) string {
		// Extract variable name from $VAR
		varName := match[1:]
		if val, ok := n.env[varName]; ok {
			return val
		}
		// Variable not found - return empty string to be consistent with shell behavior
		return ""
	})

	return path
}

// makeAbsolute converts a relative path to an absolute path.
func (n *Normalizer) makeAbsolute(path string) string {
	if path == "" {
		return path
	}

	// Already absolute
	if filepath.IsAbs(path) {
		return path
	}

	// No working directory, can't make absolute
	if n.workDir == "" {
		return path
	}

	// Handle ./ prefix
	if strings.HasPrefix(path, "./") {
		return filepath.Join(n.workDir, path[2:])
	}

	// Handle ../ prefix or just a relative path
	return filepath.Join(n.workDir, path)
}

// cleanPath cleans the path by resolving .., removing duplicate slashes, etc.
func (n *Normalizer) cleanPath(path string) string {
	if path == "" {
		return ""
	}

	// filepath.Clean handles:
	// - Multiple slashes (// -> /)
	// - . and .. references
	// - Trailing slashes (except for root)
	cleaned := filepath.Clean(path)

	// Ensure absolute paths stay absolute
	// (filepath.Clean might produce "." for some edge cases)
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}

	return cleaned
}

// GetHomeDir returns the home directory used by this normalizer.
func (n *Normalizer) GetHomeDir() string {
	return n.homeDir
}

// GetWorkDir returns the working directory used by this normalizer.
func (n *Normalizer) GetWorkDir() string {
	return n.workDir
}

// ResolveSymlink resolves symlinks in a path if the file exists.
// If the path doesn't exist or symlink resolution fails, returns the original path.
// This prevents bypasses like: ln -s /etc/passwd /tmp/x && cat /tmp/x
func (n *Normalizer) ResolveSymlink(path string) string {
	if path == "" {
		return ""
	}

	// Try to resolve symlinks using EvalSymlinks
	// This will fail if the path doesn't exist, which is fine
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Path doesn't exist or can't be resolved - return original
		return path
	}

	return resolved
}

// NormalizeWithSymlinks normalizes a path AND resolves symlinks.
// Use this for security-critical matching where symlink bypasses are a concern.
func (n *Normalizer) NormalizeWithSymlinks(path string) string {
	// First normalize the path
	normalized := n.Normalize(path)

	// Then resolve symlinks
	return n.ResolveSymlink(normalized)
}

// NormalizeAllWithSymlinks normalizes multiple paths and resolves symlinks.
func (n *Normalizer) NormalizeAllWithSymlinks(paths []string) []string {
	if paths == nil {
		return nil
	}

	result := make([]string, len(paths))
	for i, p := range paths {
		result[i] = n.NormalizeWithSymlinks(p)
	}
	return result
}
