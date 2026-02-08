//go:build linux

package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectLandlockABI(t *testing.T) {
	version := detectLandlockABI()
	// On a modern kernel (6.2+) we expect >= 3
	// On older kernels or containers without Landlock, version may be 0
	if version < 0 {
		t.Errorf("detectLandlockABI() = %d, expected >= 0", version)
	}
	t.Logf("Landlock ABI version: %d", version)
}

func TestIsLandlockSupported(t *testing.T) {
	supported := isLandlockSupported()
	version := detectLandlockABI()

	if version >= 1 && !supported {
		t.Error("isLandlockSupported() = false, but detectLandlockABI() >= 1")
	}
	if version == 0 && supported {
		t.Error("isLandlockSupported() = true, but detectLandlockABI() == 0")
	}
	t.Logf("Landlock supported: %v (ABI: %d)", supported, version)
}

func TestCheckLandlockVersion(t *testing.T) {
	// Reset the global flag so checkLandlockVersion actually runs
	origChecked := landlockChecked
	defer func() { landlockChecked = origChecked }()
	landlockChecked = false

	version := detectLandlockABI()

	if version == 0 {
		// Landlock not available — should panic
		defer func() {
			r := recover()
			if r == nil {
				t.Error("expected panic for Landlock not available")
			}
			t.Logf("got expected panic: %v", r)
		}()
		_ = checkLandlockVersion()
		return
	}

	if version < MinRequiredLandlockABI {
		// Too old — should panic
		defer func() {
			r := recover()
			if r == nil {
				t.Errorf("expected panic for Landlock v%d < v%d", version, MinRequiredLandlockABI)
			}
			t.Logf("got expected panic: %v", r)
		}()
		_ = checkLandlockVersion()
		return
	}

	// Version sufficient — should not panic
	if err := checkLandlockVersion(); err != nil {
		t.Errorf("checkLandlockVersion() error: %v", err)
	}
}

func TestCheckLandlockVersion_SkipsOnSecondCall(t *testing.T) {
	origChecked := landlockChecked
	defer func() { landlockChecked = origChecked }()

	// Pretend it was already checked
	landlockChecked = true
	if err := checkLandlockVersion(); err != nil {
		t.Errorf("checkLandlockVersion() with landlockChecked=true should return nil, got: %v", err)
	}
}

func TestMinRequiredLandlockABI_Constant(t *testing.T) {
	if MinRequiredLandlockABI != 3 {
		t.Errorf("MinRequiredLandlockABI = %d, want 3", MinRequiredLandlockABI)
	}
}

func TestSysLandlockCreateRuleset_Constant(t *testing.T) {
	if sysLandlockCreateRuleset != 444 {
		t.Errorf("sysLandlockCreateRuleset = %d, want 444", sysLandlockCreateRuleset)
	}
}

func TestBuildUnifiedPolicy_ModePassthrough(t *testing.T) {
	// Set up rules so IntentAwareAllowPaths is used
	origRules := currentRules
	defer func() { currentRules = origRules }()
	currentRules = nil // Use defaultPathModes

	policyJSON, err := buildUnifiedPolicy([]string{"ls", "/tmp"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	var policy unifiedPolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	// Verify command is passed through
	if len(policy.Command) != 2 || policy.Command[0] != "ls" || policy.Command[1] != "/tmp" {
		t.Errorf("command = %v, want [ls /tmp]", policy.Command)
	}

	// Verify mode strings are valid Rust-parseable values
	validModes := map[string]bool{"ro": true, "rx": true, "rw": true, "rwx": true, "none": true}
	for _, entry := range policy.Landlock.AllowPaths {
		if !validModes[entry.Mode] {
			t.Errorf("path %q has invalid mode %q (not parseable by Rust)", entry.Path, entry.Mode)
		}
	}
}

func TestBuildUnifiedPolicy_NoExecuteOnTmp(t *testing.T) {
	origRules := currentRules
	defer func() { currentRules = origRules }()

	// Use rules to trigger IntentAwareAllowPaths
	currentRules = []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.ssh/id_*"},
			operations: []string{"read", "write"},
		},
	}

	policyJSON, err := buildUnifiedPolicy([]string{"true"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	var policy unifiedPolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	for _, entry := range policy.Landlock.AllowPaths {
		if entry.Path == "/tmp" {
			if entry.Mode != "rw" {
				t.Errorf("/tmp mode = %q, want \"rw\" (no execute)", entry.Mode)
			}
			return
		}
	}
	t.Error("/tmp not found in policy allow_paths")
}

func TestBuildUnifiedPolicy_SystemBinsAreRX(t *testing.T) {
	origRules := currentRules
	defer func() { currentRules = origRules }()
	currentRules = []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.ssh/id_*"},
			operations: []string{"read"},
		},
	}

	policyJSON, err := buildUnifiedPolicy([]string{"true"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	var policy unifiedPolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	binDirs := map[string]bool{"/usr": true, "/bin": true, "/sbin": true, "/opt": true}
	for _, entry := range policy.Landlock.AllowPaths {
		if binDirs[entry.Path] {
			if entry.Mode != "rx" {
				t.Errorf("%s mode = %q, want \"rx\"", entry.Path, entry.Mode)
			}
		}
	}
}

// ---- ATTACK SURFACE TESTS ----

// SECURITY: verifyCurrentUserOwnership must reject world-writable files.
// A world-writable binary can be replaced by any user, including an attacker.
func TestVerifyCurrentUserOwnership_RejectsWorldWritable(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o777); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}
	// Explicitly chmod to bypass umask (which may reduce 0777 to 0755)
	if err := os.Chmod(fakeBin, 0o777); err != nil {
		t.Fatalf("chmod fake binary: %v", err)
	}

	if verifyCurrentUserOwnership(fakeBin) {
		t.Error("SECURITY: verifyCurrentUserOwnership must reject world-writable files (mode 0777)")
	}
}

// SECURITY: verifyCurrentUserOwnership accepts files owned by current user with safe perms.
func TestVerifyCurrentUserOwnership_AcceptsOwnedFile(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	if !verifyCurrentUserOwnership(fakeBin) {
		t.Error("verifyCurrentUserOwnership should accept a file owned by current user with mode 0755")
	}
}

// SECURITY: verifyHelperOwnership must reject non-root-owned files.
// Only root-owned binaries are trusted for system-wide installation.
func TestVerifyHelperOwnership_RejectsNonRootOwned(t *testing.T) {
	// Current user is not root in test environment
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")

	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	if verifyHelperOwnership(fakeBin) {
		t.Error("SECURITY: verifyHelperOwnership must reject files NOT owned by root (uid 0)")
	}
}

// SECURITY: verifyHelperOwnership rejects nonexistent paths.
func TestVerifyHelperOwnership_RejectsNonexistent(t *testing.T) {
	if verifyHelperOwnership("/nonexistent/path/bakelens-sandbox") {
		t.Error("verifyHelperOwnership must return false for nonexistent paths")
	}
}

// SECURITY: buildUnifiedPolicy must include ALL defaultDenySyscalls in the output.
func TestBuildUnifiedPolicy_IncludesAllDefaultDenySyscalls(t *testing.T) {
	origRules := currentRules
	defer func() { currentRules = origRules }()
	currentRules = nil

	policyJSON, err := buildUnifiedPolicy([]string{"echo", "test"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	var policy unifiedPolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if policy.Seccomp == nil {
		t.Fatal("SECURITY: buildUnifiedPolicy must include seccomp section")
	}

	// Build a set from the policy output
	outputSyscalls := make(map[string]bool)
	for _, sc := range policy.Seccomp.DenySyscalls {
		outputSyscalls[sc] = true
	}

	for _, expected := range defaultDenySyscalls {
		if !outputSyscalls[expected] {
			t.Errorf("SECURITY: defaultDenySyscall %q missing from policy output", expected)
		}
	}
}

// SECURITY: buildUnifiedPolicy converts ModeNone ("0") to "none" string for Rust.
func TestBuildUnifiedPolicy_ModeNoneConversion(t *testing.T) {
	origRules := currentRules
	defer func() { currentRules = origRules }()

	// Create rules that will cause a directory to get ModeNone
	currentRules = []SecurityRule{
		&mockRule{
			enabled:    true,
			blockPaths: []string{"**/.ssh/id_*"},
			operations: []string{"read", "write"},
		},
	}

	policyJSON, err := buildUnifiedPolicy([]string{"true"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	// Verify no entry has mode "0" — it should be converted to "none"
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(policyJSON, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}

	policyStr := string(policyJSON)
	if strings.Contains(policyStr, `"mode":"0"`) {
		t.Error("SECURITY: ModeNone should be serialized as \"none\", not \"0\" — Rust serde won't parse \"0\"")
	}
}

// SECURITY: findBakelensSandbox must NOT search in CWD.
// An agent could place a malicious binary in the working directory.
func TestFindBakelensSandbox_DoesNotSearchCWD(t *testing.T) {
	// The helperExecPaths list should contain only absolute system paths
	for _, path := range helperExecPaths {
		if !filepath.IsAbs(path) {
			t.Errorf("SECURITY: helperExecPaths contains relative path %q — agents could substitute a fake binary", path)
		}
		// Also verify no path is "bakelens-sandbox" alone (bare name = CWD search)
		if path == helperBinaryName {
			t.Errorf("SECURITY: helperExecPaths contains bare binary name %q — this searches CWD", path)
		}
	}

	// Verify the function doesn't find a binary placed in CWD
	cwd, err := os.Getwd()
	if err != nil {
		t.Skip("cannot get CWD")
	}

	// Create a fake binary in CWD
	fakeBin := filepath.Join(cwd, helperBinaryName)
	// Only create if it doesn't already exist (don't clobber real binary)
	if _, err := os.Stat(fakeBin); os.IsNotExist(err) {
		if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho pwned"), 0o755); err != nil {
			t.Skipf("cannot create fake binary in CWD: %v", err)
		}
		defer os.Remove(fakeBin)

		found, err := findBakelensSandbox()
		if err == nil && found == fakeBin {
			t.Error("SECURITY: findBakelensSandbox must NOT return a binary found in CWD")
		}
	}
}

func TestFindBakelensSandbox_NotFound(t *testing.T) {
	orig := helperExecPaths
	defer func() { helperExecPaths = orig }()
	helperExecPaths = []string{"/nonexistent/path/bakelens-sandbox"}

	_, err := findBakelensSandbox()
	if err == nil {
		t.Error("expected error when binary not found")
	}
}

func TestIsHelperInstalled_WithoutBinary(t *testing.T) {
	orig := helperExecPaths
	defer func() { helperExecPaths = orig }()
	helperExecPaths = []string{"/nonexistent/path/bakelens-sandbox"}

	if IsHelperInstalled() {
		t.Error("expected false when binary not installed")
	}
}

func TestIsHelperInstalled_WithBinary(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "bakelens-sandbox")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho ok"), 0o755); err != nil {
		t.Fatalf("create fake binary: %v", err)
	}

	orig := helperExecPaths
	defer func() { helperExecPaths = orig }()
	helperExecPaths = []string{fakeBin}

	if !IsHelperInstalled() {
		t.Error("expected true when binary is installed")
	}
}

// SECURITY: Policy JSON has deny_unknown_fields protection via version validation.
// The Rust side uses #[serde(deny_unknown_fields)] and validates version == 1.
func TestBuildUnifiedPolicy_VersionFieldValidation(t *testing.T) {
	origRules := currentRules
	defer func() { currentRules = origRules }()
	currentRules = nil

	policyJSON, err := buildUnifiedPolicy([]string{"echo"})
	if err != nil {
		t.Fatalf("buildUnifiedPolicy() error: %v", err)
	}

	var policy unifiedPolicyJSON
	if err := json.Unmarshal(policyJSON, &policy); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}

	if policy.Version != 1 {
		t.Errorf("SECURITY: policy version must be 1 (Rust side uses deny_unknown_fields + version check), got %d", policy.Version)
	}
}
