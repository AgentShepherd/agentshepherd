package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Loader handles loading rules from embedded files and user directory
type Loader struct {
	userDir string
}

// NewLoader creates a new rule loader
func NewLoader(userDir string) *Loader {
	return &Loader{
		userDir: userDir,
	}
}

// DefaultUserRulesDir returns the default user rules directory
func DefaultUserRulesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".agentshepherd/rules.d"
	}
	return filepath.Join(home, ".agentshepherd", "rules.d")
}

// LoadBuiltin loads all embedded builtin path-based rules
func (l *Loader) LoadBuiltin() ([]Rule, error) {
	var allRules []Rule

	log.Trace("Loading builtin path-based rules from embedded filesystem")

	err := fs.WalkDir(builtinFS, "builtin", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Trace("  Error walking %s: %v", path, err)
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return nil
		}

		log.Trace("  Loading builtin file: %s", path)

		data, err := builtinFS.ReadFile(path)
		if err != nil {
			log.Trace("    FAILED to read: %v", err)
			return fmt.Errorf("failed to read %s: %w", path, err)
		}

		rules, err := l.parseRuleSet(data, path, SourceBuiltin)
		if err != nil {
			log.Trace("    FAILED to parse: %v", err)
			return fmt.Errorf("failed to parse %s: %w", path, err)
		}

		log.Trace("    Loaded %d path-based rules from %s", len(rules), path)
		allRules = append(allRules, rules...)
		return nil
	})

	if err != nil {
		return nil, err
	}

	log.Trace("Total builtin path-based rules loaded: %d", len(allRules))
	return allRules, nil
}

// LoadUser loads path-based rules from the user rules directory
func (l *Loader) LoadUser() ([]Rule, error) {
	if l.userDir == "" {
		log.Trace("User rules directory not configured, skipping")
		return nil, nil
	}

	log.Trace("Loading user path-based rules from: %s", l.userDir)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(l.userDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rules directory: %w", err)
	}

	var allRules []Rule

	entries, err := os.ReadDir(l.userDir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Trace("  User rules directory does not exist")
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read rules directory: %w", err)
	}

	log.Trace("  Found %d entries in user rules directory", len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			log.Trace("  Skipping non-YAML: %s", entry.Name())
			continue
		}

		path := filepath.Join(l.userDir, entry.Name())
		log.Trace("  Loading user file: %s", path)

		data, err := os.ReadFile(path)
		if err != nil {
			log.Warn("Failed to read rule file %s: %v", path, err)
			log.Trace("    FAILED to read: %v", err)
			continue
		}

		rules, err := l.parseRuleSet(data, path, SourceUser)
		if err != nil {
			log.Warn("Failed to parse rule file %s: %v", path, err)
			log.Trace("    FAILED to parse: %v", err)
			continue
		}

		log.Trace("    Loaded %d rules from %s", len(rules), entry.Name())
		allRules = append(allRules, rules...)
	}

	log.Trace("Total user path-based rules loaded: %d", len(allRules))
	return allRules, nil
}

// validateFile validates a rule file without loading it
func (l *Loader) validateFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	_, err = l.parseRuleSet(data, path, SourceCLI)
	return err
}

// ValidateYAML validates rule YAML content
func (l *Loader) ValidateYAML(data []byte) error {
	_, err := l.parseRuleSet(data, "inline", SourceCLI)
	return err
}

// AddRuleFile copies a rule file to the user rules directory
func (l *Loader) AddRuleFile(srcPath string) (string, error) {
	// Validate first
	if err := l.validateFile(srcPath); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Create directory if needed
	if err := os.MkdirAll(l.userDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create rules directory: %w", err)
	}

	// Read source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("failed to read source file: %w", err)
	}

	// Destination path
	filename := filepath.Base(srcPath)
	destPath := filepath.Join(l.userDir, filename)

	// Check for existing file
	if _, err := os.Stat(destPath); err == nil {
		// Add timestamp to avoid overwrite
		ext := filepath.Ext(filename)
		name := strings.TrimSuffix(filename, ext)
		filename = fmt.Sprintf("%s_%d%s", name, time.Now().Unix(), ext)
		destPath = filepath.Join(l.userDir, filename)
	}

	// Write to destination
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return "", fmt.Errorf("failed to write rule file: %w", err)
	}

	return destPath, nil
}

// ValidateSafeFilename checks if a filename is safe (no path traversal)
// Returns the sanitized filename or an error
func ValidateSafeFilename(filename string) (string, error) {
	// Extract just the base name to prevent path traversal
	base := filepath.Base(filename)

	// Reject if base is empty, ".", or ".."
	if base == "" || base == "." || base == ".." {
		return "", fmt.Errorf("invalid filename: %s", filename)
	}

	// Reject if original filename differs from base (had path components)
	if base != filename {
		return "", fmt.Errorf("path traversal detected in filename: %s", filename)
	}

	// Only allow safe characters: alphanumeric, underscore, dash, dot
	for _, r := range base {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
			return "", fmt.Errorf("invalid character in filename: %c", r)
		}
	}

	return base, nil
}

// ValidatePathInDirectory checks if a path is safely within a directory
// Resolves symlinks to prevent symlink-based path traversal
func (l *Loader) ValidatePathInDirectory(filename string) (string, error) {
	// First validate the filename itself
	safeFilename, err := ValidateSafeFilename(filename)
	if err != nil {
		return "", err
	}

	// Construct the full path
	fullPath := filepath.Join(l.userDir, safeFilename)

	// Get absolute paths
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	absUserDir, err := filepath.Abs(l.userDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve user dir: %w", err)
	}

	// Ensure the path is within the user directory
	// Add trailing separator to prevent prefix matching issues (e.g., /rules vs /rules-backup)
	if !strings.HasPrefix(absPath, absUserDir+string(os.PathSeparator)) && absPath != absUserDir {
		return "", fmt.Errorf("path traversal detected: %s is outside %s", absPath, absUserDir)
	}

	// If file exists, also check resolved symlinks
	if _, err := os.Lstat(fullPath); err == nil {
		realPath, err := filepath.EvalSymlinks(fullPath)
		if err == nil {
			absRealPath, err := filepath.Abs(realPath)
			if err != nil {
				return "", fmt.Errorf("failed to resolve symlink: %w", err)
			}
			if !strings.HasPrefix(absRealPath, absUserDir+string(os.PathSeparator)) && absRealPath != absUserDir {
				return "", fmt.Errorf("symlink points outside rules directory")
			}
		}
	}

	return fullPath, nil
}

// RemoveRuleFile removes a rule file from the user rules directory
func (l *Loader) RemoveRuleFile(filename string) error {
	// Validate path is safe
	path, err := l.ValidatePathInDirectory(filename)
	if err != nil {
		return err
	}

	return os.Remove(path)
}

// ListUserRuleFiles returns the list of user rule files
func (l *Loader) ListUserRuleFiles() ([]string, error) {
	entries, err := os.ReadDir(l.userDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// GetUserDir returns the user rules directory
func (l *Loader) GetUserDir() string {
	return l.userDir
}

// parseRuleSet parses YAML data into path-based rules using progressive disclosure schema
func (l *Loader) parseRuleSet(data []byte, path string, source string) ([]Rule, error) {
	var ruleSetConfig RuleSetConfig
	if err := yaml.Unmarshal(data, &ruleSetConfig); err != nil {
		log.Trace("      YAML parse error: %v", err)
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	if err := ruleSetConfig.Validate(); err != nil {
		return nil, err
	}

	rules := ruleSetConfig.ToRules()

	log.Trace("      Parsing %d path-based rules from %s", len(rules), path)

	for i := range rules {
		rule := &rules[i]

		// Set runtime fields
		rule.Source = source
		rule.FilePath = path

		// Log rule status
		status := "enabled"
		if !rule.IsEnabled() {
			status = "DISABLED"
		}
		log.Trace("        Rule %s: %s (priority=%d, severity=%s, ops=%v)",
			rule.Name, status, rule.GetPriority(), rule.GetSeverity(), rule.Operations)
	}

	return rules, nil
}
