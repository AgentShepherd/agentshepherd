package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	boolTrue  = true
	boolFalse = false
)

// testRule implements SecurityRule for unit tests.
type testRule struct {
	name       string
	enabled    *bool
	paths      []string
	except     []string
	operations []string
}

func (r *testRule) IsEnabled() bool {
	if r.enabled == nil {
		return true
	}
	return *r.enabled
}
func (r *testRule) GetName() string          { return r.name }
func (r *testRule) GetBlockPaths() []string  { return r.paths }
func (r *testRule) GetBlockExcept() []string { return r.except }
func (r *testRule) GetActions() []string     { return r.operations }

func newTestMapper(t testing.TB) *Mapper {
	t.Helper()
	return NewMapper(filepath.Join(t.TempDir(), "sandbox.sb"))
}

func TestNewMapper(t *testing.T) {
	mapper := NewMapper("/tmp/test.sb")

	if mapper.profilePath != "/tmp/test.sb" {
		t.Errorf("expected profilePath /tmp/test.sb, got %s", mapper.profilePath)
	}
	if mapper.mappings == nil {
		t.Error("mappings should be initialized")
	}
	if len(mapper.mappings) != 0 {
		t.Errorf("mappings should be empty, got %d", len(mapper.mappings))
	}
}

func TestDefaultProfilePath(t *testing.T) {
	path := DefaultProfilePath()

	if !strings.HasSuffix(path, ".crust/sandbox.sb") {
		t.Errorf("expected path ending with .crust/sandbox.sb, got %s", path)
	}
}

func TestAddRule_PathBased(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	rule := &testRule{
		name:       "block-env-access",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read", "write"},
	}

	err := mapper.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Check mapping exists
	if !mapper.HasRule("block-env-access") {
		t.Error("rule should be mapped")
	}

	// Check profile was written
	content, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("failed to read profile: %v", err)
	}

	profileStr := string(content)

	// Check header
	if !strings.Contains(profileStr, "(version 1)") {
		t.Error("profile should contain version")
	}
	if !strings.Contains(profileStr, "(allow default)") {
		t.Error("profile should allow default")
	}

	// Check rule markers
	if !strings.Contains(profileStr, "; --- RULE: block-env-access ---") {
		t.Error("profile should contain rule start marker")
	}
	if !strings.Contains(profileStr, "; --- END RULE: block-env-access ---") {
		t.Error("profile should contain rule end marker")
	}

	// Check deny directive
	if !strings.Contains(profileStr, "(deny file-read*") {
		t.Error("profile should contain deny directive")
	}
}

func TestAddRule_DisabledRule(t *testing.T) {
	mapper := newTestMapper(t)

	rule := &testRule{
		name:       "disabled-rule",
		enabled:    &boolFalse,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}

	err := mapper.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Disabled rules should not be mapped
	if mapper.HasRule("disabled-rule") {
		t.Error("disabled rule should not be mapped")
	}
}

func TestRemoveRule(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	rule1 := &testRule{
		name:       "rule-one",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	rule2 := &testRule{
		name:       "rule-two",
		enabled:    &boolTrue,
		paths:      []string{"**/.ssh/*"},
		operations: []string{"read"},
	}

	_ = mapper.AddRule(rule1)
	_ = mapper.AddRule(rule2)

	if mapper.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", mapper.RuleCount())
	}

	// Remove rule-one
	err := mapper.RemoveRule("rule-one")
	if err != nil {
		t.Fatalf("RemoveRule failed: %v", err)
	}

	if mapper.HasRule("rule-one") {
		t.Error("rule-one should be removed")
	}
	if !mapper.HasRule("rule-two") {
		t.Error("rule-two should still exist")
	}
	if mapper.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", mapper.RuleCount())
	}

	// Check profile was updated
	content, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("failed to read profile: %v", err)
	}

	profileStr := string(content)
	if strings.Contains(profileStr, "rule-one") {
		t.Error("profile should not contain removed rule")
	}
	if !strings.Contains(profileStr, "rule-two") {
		t.Error("profile should still contain rule-two")
	}
}

func TestRemoveRule_NonExistent(t *testing.T) {
	mapper := newTestMapper(t)

	// Remove non-existent rule - should not error
	err := mapper.RemoveRule("does-not-exist")
	if err != nil {
		t.Errorf("removing non-existent rule should not error: %v", err)
	}
}

func TestLoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")

	// Create a profile with rules
	mapper1 := NewMapper(profilePath)
	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper1.AddRule(rule)

	// Create new mapper and load from file
	mapper2 := NewMapper(profilePath)
	err := mapper2.LoadFromFile()
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if !mapper2.HasRule("test-rule") {
		t.Error("loaded mapper should have test-rule")
	}

	// Verify directives were loaded
	directives, ok := mapper2.GetRuleDirectives("test-rule")
	if !ok {
		t.Error("should get directives for test-rule")
	}
	if !strings.Contains(directives, "(deny file-read*") {
		t.Error("directives should contain deny file-read")
	}
}

func TestLoadFromFile_NonExistent(t *testing.T) {
	mapper := NewMapper("/nonexistent/path/sandbox.sb")

	err := mapper.LoadFromFile()
	if err != nil {
		t.Errorf("loading non-existent file should not error: %v", err)
	}

	if mapper.RuleCount() != 0 {
		t.Errorf("should have no rules, got %d", mapper.RuleCount())
	}
}

func TestGetMappings(t *testing.T) {
	mapper := newTestMapper(t)

	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule)

	mappings := mapper.GetMappings()

	if len(mappings) != 1 {
		t.Errorf("expected 1 mapping, got %d", len(mappings))
	}
	if _, ok := mappings["test-rule"]; !ok {
		t.Error("mappings should contain test-rule")
	}

	// Verify it's a copy (modifying shouldn't affect original)
	mappings["new-rule"] = "test"
	if mapper.HasRule("new-rule") {
		t.Error("modifying returned map should not affect mapper")
	}
}

func TestGetProfile(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule)

	profile, err := mapper.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile failed: %v", err)
	}

	if !strings.Contains(string(profile), "(version 1)") {
		t.Error("profile should contain version")
	}
	if !strings.Contains(string(profile), "test-rule") {
		t.Error("profile should contain rule")
	}
}

func TestGenerateProfileContent(t *testing.T) {
	mapper := newTestMapper(t)

	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule)

	content := mapper.GenerateProfileContent()

	if !strings.Contains(content, "(version 1)") {
		t.Error("content should contain version")
	}
	if !strings.Contains(content, "; --- RULE: test-rule ---") {
		t.Error("content should contain rule marker")
	}
}

func TestMultipleRulesOrdering(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	// Add multiple rules
	ruleNames := []string{"alpha-rule", "beta-rule", "gamma-rule"}
	for _, name := range ruleNames {
		rule := &testRule{
			name:       name,
			enabled:    &boolTrue,
			paths:      []string{"**/" + name},
			operations: []string{"read"},
		}
		_ = mapper.AddRule(rule)
	}

	if mapper.RuleCount() != 3 {
		t.Errorf("expected 3 rules, got %d", mapper.RuleCount())
	}

	// All rules should be present
	for _, name := range ruleNames {
		if !mapper.HasRule(name) {
			t.Errorf("rule %s should be mapped", name)
		}
	}

	// Profile should contain all rules
	content, _ := os.ReadFile(profilePath)
	for _, name := range ruleNames {
		if !strings.Contains(string(content), name) {
			t.Errorf("profile should contain %s", name)
		}
	}
}

func TestAddRule_UpdateExisting(t *testing.T) {
	mapper := newTestMapper(t)

	// Add initial rule
	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}
	_ = mapper.AddRule(rule)

	oldDirectives, _ := mapper.GetRuleDirectives("test-rule")

	// Update with different pattern
	rule.paths = []string{"**/.ssh/*"}
	_ = mapper.AddRule(rule)

	newDirectives, _ := mapper.GetRuleDirectives("test-rule")

	if oldDirectives == newDirectives {
		t.Error("directives should be updated")
	}

	if !strings.Contains(newDirectives, ".ssh") {
		t.Error("new directives should contain .ssh pattern")
	}

	// Should still be only one rule
	if mapper.RuleCount() != 1 {
		t.Errorf("expected 1 rule after update, got %d", mapper.RuleCount())
	}
}

func TestParseRuleSections(t *testing.T) {
	mapper := newTestMapper(t)

	// Manually create a profile with sections
	profile := `; Crust Sandbox Profile
(version 1)
(allow default)

; --- RULE: rule-one ---
(deny file-read* (regex #"\.env$"))
; --- END RULE: rule-one ---

; --- RULE: rule-two ---
(deny file-read* (subpath "/etc/secrets"))
(deny file-write* (subpath "/etc/secrets"))
; --- END RULE: rule-two ---
`
	err := mapper.parseRuleSections(profile)
	if err != nil {
		t.Fatalf("parseRuleSections failed: %v", err)
	}

	if mapper.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", mapper.RuleCount())
	}

	if !mapper.HasRule("rule-one") {
		t.Error("should have rule-one")
	}
	if !mapper.HasRule("rule-two") {
		t.Error("should have rule-two")
	}

	// Check directives were parsed correctly
	dir1, _ := mapper.GetRuleDirectives("rule-one")
	if !strings.Contains(dir1, "(deny file-read*") {
		t.Error("rule-one directives should contain deny")
	}

	dir2, _ := mapper.GetRuleDirectives("rule-two")
	if !strings.Contains(dir2, "/etc/secrets") {
		t.Error("rule-two directives should contain path")
	}
}

func TestAddRule_EmptyDirectives(t *testing.T) {
	mapper := newTestMapper(t)

	// A rule with no block paths generates no directives
	rule := &testRule{
		name:    "content-only-rule",
		enabled: &boolTrue,
		// No paths, no operations → TranslateRule returns empty
	}

	err := mapper.AddRule(rule)
	if err != nil {
		t.Fatalf("AddRule failed: %v", err)
	}

	// Should not be mapped (0 directives → early return)
	if mapper.HasRule("content-only-rule") {
		t.Error("content-only rule should not be mapped (no directives)")
	}
}

func TestDefaultProfilePath_NoHome(t *testing.T) {
	// Set HOME to a non-existent directory
	t.Setenv("HOME", "/nonexistent-home-dir-for-test")

	path := DefaultProfilePath()
	// On Linux, os.UserHomeDir may fall back to /etc/passwd.
	// Either way, the path should end with .crust/sandbox.sb
	if !strings.HasSuffix(path, filepath.Join(".crust", "sandbox.sb")) {
		t.Errorf("DefaultProfilePath() = %q, expected to end with .crust/sandbox.sb", path)
	}
}

func TestWriteProfile_BadDir(t *testing.T) {
	// /proc/nonexistent is not writable — MkdirAll should fail
	mapper := NewMapper("/proc/nonexistent/subdir/sandbox.sb")
	rule := &testRule{
		name:       "test",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}

	err := mapper.AddRule(rule)
	if err == nil {
		t.Error("expected error when profile directory can't be created")
	}
}

func TestLoadFromFile_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("cannot test permission errors as root")
	}

	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "sandbox.sb")

	// Create file with no read permissions
	if err := os.WriteFile(profilePath, []byte("data"), 0000); err != nil {
		t.Fatalf("create file: %v", err)
	}

	mapper := NewMapper(profilePath)
	err := mapper.LoadFromFile()
	if err == nil {
		t.Error("expected error reading unreadable file")
	}
}

func TestConcurrentAccess(t *testing.T) {
	mapper := newTestMapper(t)

	// Run concurrent add/remove operations
	done := make(chan bool)

	// Writer goroutine - add rules
	go func() {
		for i := 0; i < 100; i++ {
			rule := &testRule{
				name:       "concurrent-rule",
				enabled:    &boolTrue,
				paths:      []string{"**/.test"},
				operations: []string{"read"},
			}
			_ = mapper.AddRule(rule)
		}
		done <- true
	}()

	// Reader goroutine - check rules
	go func() {
		for i := 0; i < 100; i++ {
			_ = mapper.HasRule("concurrent-rule")
			_ = mapper.RuleCount()
			_ = mapper.GetMappings()
		}
		done <- true
	}()

	// Remover goroutine - remove rules
	go func() {
		for i := 0; i < 100; i++ {
			_ = mapper.RemoveRule("concurrent-rule")
		}
		done <- true
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}

	// If we get here without deadlock or panic, test passes
}

func TestMapperProfileDirPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	profileDir := filepath.Join(tmpDir, "subdir")
	profilePath := filepath.Join(profileDir, "sandbox.sb")
	mapper := NewMapper(profilePath)

	rule := &testRule{
		name:       "test-rule",
		enabled:    &boolTrue,
		paths:      []string{"**/.env"},
		operations: []string{"read"},
	}

	if err := mapper.AddRule(rule); err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	fi, err := os.Stat(profileDir)
	if err != nil {
		t.Fatalf("stat profile dir: %v", err)
	}

	perm := fi.Mode().Perm()
	if perm != 0700 {
		t.Errorf("profile directory permissions = %o, want 0700", perm)
	}
}

func TestSanitizeRuleName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"clean name", "my-rule", "my-rule"},
		{"strips newline", "rule\ninjected", "ruleinjected"},
		{"strips carriage return", "rule\rinjected", "ruleinjected"},
		{"strips semicolons", "rule;injected", "ruleinjected"},
		{"strips parens", "rule(injected)", "ruleinjected"},
		{"strips quotes", `rule"injected`, "ruleinjected"},
		{"strips hash", "rule#comment", "rulecomment"},
		{"combined injection", "rule\n;(allow default)\n", "ruleallow default"},
		{"empty string", "", ""},
		{"unicode preserved", "rule-日本語", "rule-日本語"},
		{"strips invalid utf8", "rule\x94name", "rulename"},
		{"strips replacement char", "rule\xef\xbf\xbdname", "rulename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeRuleName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeRuleName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
