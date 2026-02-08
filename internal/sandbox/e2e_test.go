//go:build sandbox_e2e

package sandbox

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// getTestDataDir returns the test data directory for ALLOWED files.
// Can be overridden with TEST_DATA_DIR env var.
func getTestDataDir() string {
	if dir := os.Getenv("TEST_DATA_DIR"); dir != "" {
		return dir
	}
	return "/test-data"
}

// getBlockedDataDir returns the test data directory for BLOCKED files.
// On Linux, this must be outside Landlock's allowed paths (/tmp, /var, etc.)
// Can be overridden with TEST_BLOCKED_DATA_DIR env var.
func getBlockedDataDir() string {
	if dir := os.Getenv("TEST_BLOCKED_DATA_DIR"); dir != "" {
		return dir
	}
	// Default: same as test data dir (works for macOS Seatbelt which does file-level filtering)
	return getTestDataDir()
}

// setupTestSandbox creates a sandbox with builtin rules for E2E testing.
func setupTestSandbox(t *testing.T) *Sandbox {
	t.Helper()

	// Ensure bakelens-sandbox helper is found
	setupBakelensSandboxPath(t)

	profilePath := filepath.Join(t.TempDir(), "sandbox.sb")
	mapper := NewMapper(profilePath)

	// Load builtin rules
	loader := rules.NewLoader("")
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	// Add rules to mapper (all path-based rules are blocking rules)
	for i := range builtinRules {
		if builtinRules[i].IsEnabled() {
			_ = mapper.AddRule(&builtinRules[i])
		}
	}

	return New(mapper)
}

// runCommand executes a command inside the sandbox and captures output.
func runCommand(sb *Sandbox, args ...string) (exitCode int, stdout, stderr string) {
	// Create command
	cmd := exec.Command(args[0], args[1:]...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// For E2E tests, we run without the sandbox wrapper to test individual components
	// The actual sandbox enforcement is tested via the Wrap method
	err := cmd.Run()

	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return exitCode, stdoutBuf.String(), stderrBuf.String()
}

// runInSandbox executes a command inside the sandbox.
func runInSandbox(t *testing.T, sb *Sandbox, args ...string) (exitCode int, stdout, stderr string) {
	t.Helper()

	// Capture stdout/stderr by redirecting to temp files
	stdoutFile := filepath.Join(t.TempDir(), "stdout")
	stderrFile := filepath.Join(t.TempDir(), "stderr")

	// Build command that redirects output
	shellCmd := strings.Join(args, " ") + " >" + stdoutFile + " 2>" + stderrFile

	exitCode, err := sb.Wrap([]string{"sh", "-c", shellCmd})
	if err != nil {
		t.Logf("Sandbox error: %v", err)
	}

	stdoutBytes, _ := os.ReadFile(stdoutFile)
	stderrBytes, _ := os.ReadFile(stderrFile)

	return exitCode, string(stdoutBytes), string(stderrBytes)
}

// assertBlocked verifies that a command was blocked by the sandbox.
func assertBlocked(t *testing.T, name string, exitCode int, stderr string) {
	t.Helper()

	if exitCode == 0 {
		t.Errorf("%s: expected to be BLOCKED (non-zero exit), but succeeded", name)
		return
	}

	// Check for permission denied indicators
	blockedIndicators := []string{
		"Permission denied",
		"Operation not permitted",
		"not permitted",
		"denied",
	}

	found := false
	for _, indicator := range blockedIndicators {
		if strings.Contains(strings.ToLower(stderr), strings.ToLower(indicator)) {
			found = true
			break
		}
	}

	if !found && stderr != "" {
		t.Logf("%s: blocked with unexpected error: %s", name, stderr)
	}

	t.Logf("%s: correctly BLOCKED (exit=%d)", name, exitCode)
}

// assertAllowed verifies that a command was allowed by the sandbox.
func assertAllowed(t *testing.T, name string, exitCode int, stderr string) {
	t.Helper()

	if exitCode != 0 {
		t.Errorf("%s: expected to be ALLOWED (exit=0), but failed with exit=%d, stderr=%s",
			name, exitCode, stderr)
		return
	}

	t.Logf("%s: correctly ALLOWED", name)
}

// checkTestDataExists verifies the test data directory is set up.
func checkTestDataExists(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(getTestDataDir()); os.IsNotExist(err) {
		t.Skipf("Test data directory %s does not exist. Run in Docker or create test files.", getTestDataDir())
	}
}

// checkBlockedDataExists verifies the blocked data directory is set up.
func checkBlockedDataExists(t *testing.T) {
	t.Helper()

	if _, err := os.Stat(getBlockedDataDir()); os.IsNotExist(err) {
		t.Skipf("Blocked data directory %s does not exist. Run in Docker or create test files.", getBlockedDataDir())
	}
}

// TestSandboxPlatformSupport verifies sandbox is available.
func TestSandboxPlatformSupport(t *testing.T) {
	if !IsSupported() {
		t.Skipf("Sandbox not supported on this platform: %s", Platform())
	}

	t.Logf("Sandbox platform: %s", Platform())
}

// TestSandbox_BlocksEnvFile tests that .env files are blocked.
func TestSandbox_BlocksEnvFile(t *testing.T) {
	checkBlockedDataExists(t)

	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	tests := []struct {
		name string
		file string
	}{
		{"read .env", filepath.Join(getBlockedDataDir(), ".env")},
		{"read .env.local", filepath.Join(getBlockedDataDir(), ".env.local")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.file); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tt.file)
			}

			exitCode, _, stderr := runInSandbox(t, sb, "cat", tt.file)
			assertBlocked(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_BlocksSSHKeys tests that SSH private keys are blocked.
func TestSandbox_BlocksSSHKeys(t *testing.T) {
	checkBlockedDataExists(t)

	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	sshDir := filepath.Join(getBlockedDataDir(), ".ssh")
	tests := []struct {
		name string
		file string
	}{
		{"read id_rsa", filepath.Join(sshDir, "id_rsa")},
		{"read id_ed25519", filepath.Join(sshDir, "id_ed25519")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.file); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tt.file)
			}

			exitCode, _, stderr := runInSandbox(t, sb, "cat", tt.file)
			assertBlocked(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_BlocksCredentialFiles tests that credential files are blocked.
func TestSandbox_BlocksCredentialFiles(t *testing.T) {
	checkBlockedDataExists(t)

	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	secretsDir := filepath.Join(getBlockedDataDir(), "secrets")
	tests := []struct {
		name string
		file string
	}{
		{"read credentials.json", filepath.Join(secretsDir, "credentials.json")},
		{"read secrets.yaml", filepath.Join(secretsDir, "secrets.yaml")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.file); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tt.file)
			}

			exitCode, _, stderr := runInSandbox(t, sb, "cat", tt.file)
			assertBlocked(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_BlocksDeletion tests that destructive commands are blocked.
func TestSandbox_BlocksDeletion(t *testing.T) {
	checkTestDataExists(t)

	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	// Create a temp file to try to delete
	tmpFile := filepath.Join(t.TempDir(), "delete-me.txt")
	if err := os.WriteFile(tmpFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{"rm system dir", []string{"rm", "-rf", "/etc"}},
		{"rm usr", []string{"rm", "-rf", "/usr"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, _, stderr := runInSandbox(t, sb, tt.args...)
			assertBlocked(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_AllowsNormalFiles tests that normal file access works.
func TestSandbox_AllowsNormalFiles(t *testing.T) {
	checkTestDataExists(t)

	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	projectDir := filepath.Join(getTestDataDir(), "project")
	tests := []struct {
		name string
		file string
	}{
		{"read main.go", filepath.Join(projectDir, "main.go")},
		{"read README.md", filepath.Join(projectDir, "README.md")},
		{"read data.txt", filepath.Join(projectDir, "data.txt")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := os.Stat(tt.file); os.IsNotExist(err) {
				t.Skipf("Test file %s does not exist", tt.file)
			}

			exitCode, _, stderr := runInSandbox(t, sb, "cat", tt.file)
			assertAllowed(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_AllowsBasicCommands tests that basic commands work.
func TestSandbox_AllowsBasicCommands(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	tests := []struct {
		name string
		args []string
	}{
		{"echo", []string{"echo", "hello world"}},
		{"pwd", []string{"pwd"}},
		{"ls tmp", []string{"ls", "/tmp"}},
		{"date", []string{"date"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, _, stderr := runInSandbox(t, sb, tt.args...)
			assertAllowed(t, tt.name, exitCode, stderr)
		})
	}
}

// TestSandbox_BlocksExecuteFromTmp tests that executing binaries from /tmp is blocked.
// This is the core security property of the rw/rx split: /tmp is rw (no execute).
func TestSandbox_BlocksExecuteFromTmp(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}
	if !isLandlockSupported() {
		t.Skip("Requires Landlock for execute enforcement")
	}

	sb := setupTestSandbox(t)

	// Copy a binary to /tmp and try to execute it directly
	tmpBin := "/tmp/test-exec-blocked-" + t.Name()
	defer os.Remove(tmpBin)

	// Copy /usr/bin/true to /tmp
	exitCode, _, stderr := runInSandbox(t, sb, "cp", "/usr/bin/true", tmpBin)
	if exitCode != 0 {
		t.Skipf("Cannot copy binary to /tmp (exit=%d stderr=%s)", exitCode, stderr)
	}

	// Make it executable (chmod works at filesystem level)
	exitCode, _, stderr = runInSandbox(t, sb, "chmod", "+x", tmpBin)
	if exitCode != 0 {
		t.Skipf("Cannot chmod (exit=%d stderr=%s)", exitCode, stderr)
	}

	// Try to execute it — should fail because /tmp has rw mode (no execute)
	exitCode, _, stderr = runInSandbox(t, sb, tmpBin)
	assertBlocked(t, "execute from /tmp", exitCode, stderr)
}

// TestSandbox_AllowsExecuteFromUsr tests that executing binaries from /usr works.
// /usr has rx mode — execute is allowed.
func TestSandbox_AllowsExecuteFromUsr(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	exitCode, _, stderr := runInSandbox(t, sb, "/usr/bin/ls", "/tmp")
	assertAllowed(t, "execute from /usr", exitCode, stderr)
}

// TestSandbox_BlocksWriteToUsr tests that writing to /usr is blocked.
// /usr has rx mode — write is denied.
func TestSandbox_BlocksWriteToUsr(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}
	if !isLandlockSupported() {
		t.Skip("Requires Landlock for write enforcement")
	}

	sb := setupTestSandbox(t)

	exitCode, _, stderr := runInSandbox(t, sb, "touch", "/usr/bin/evil-test-file")
	assertBlocked(t, "write to /usr", exitCode, stderr)
}

// TestSandbox_AllowsWriteToTmp tests that writing to /tmp works.
// /tmp has rw mode — write is allowed.
func TestSandbox_AllowsWriteToTmp(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	tmpFile := "/tmp/test-write-" + t.Name()
	defer os.Remove(tmpFile)

	exitCode, _, stderr := runInSandbox(t, sb, "touch", tmpFile)
	assertAllowed(t, "write to /tmp", exitCode, stderr)
}

// TestSandbox_BlocksWriteToEtc tests that writing to /etc is blocked.
// /etc has ro mode — write is denied.
func TestSandbox_BlocksWriteToEtc(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}
	if !isLandlockSupported() {
		t.Skip("Requires Landlock for write enforcement")
	}

	sb := setupTestSandbox(t)

	exitCode, _, stderr := runInSandbox(t, sb, "touch", "/etc/evil-test-file")
	assertBlocked(t, "write to /etc", exitCode, stderr)
}

// TestSandbox_AllowsReadFromEtc tests that reading from /etc works.
// /etc has ro mode — read is allowed.
func TestSandbox_AllowsReadFromEtc(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	exitCode, _, stderr := runInSandbox(t, sb, "cat", "/etc/hostname")
	assertAllowed(t, "read from /etc", exitCode, stderr)
}

// TestSandbox_BinaryPlantingBlocked tests the binary planting attack scenario.
// Agent writes a binary to /tmp and tries to execute it — must fail.
func TestSandbox_BinaryPlantingBlocked(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}
	if !isLandlockSupported() {
		t.Skip("Requires Landlock for execute enforcement")
	}

	sb := setupTestSandbox(t)

	// Simulate: agent copies echo to /tmp and tries to run it
	tmpBin := "/tmp/test-planted-" + t.Name()
	defer os.Remove(tmpBin)

	exitCode, _, stderr := runInSandbox(t, sb, "sh", "-c",
		"cp /usr/bin/echo "+tmpBin+" && chmod +x "+tmpBin+" && "+tmpBin+" pwned")
	if exitCode == 0 {
		t.Error("binary planting attack succeeded — /tmp execute should be blocked")
	} else {
		t.Logf("binary planting correctly blocked (exit=%d)", exitCode)
	}
	_ = stderr
}

// TestSandbox_InterpreterFromRXDir tests that interpreted scripts work.
// The interpreter (e.g., sh) runs from /usr (rx), reading a script from /tmp (rw).
func TestSandbox_InterpreterFromRXDir(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	// Write a script to /tmp, run it via sh (from /usr/bin)
	tmpScript := "/tmp/test-script-" + t.Name() + ".sh"
	defer os.Remove(tmpScript)

	if err := os.WriteFile(tmpScript, []byte("#!/bin/sh\necho hello\n"), 0644); err != nil {
		t.Fatalf("Cannot write test script: %v", err)
	}

	// Run via interpreter (sh reads the script as data from /tmp rw)
	exitCode, stdout, stderr := runInSandbox(t, sb, "sh", tmpScript)
	assertAllowed(t, "interpreter from rx dir", exitCode, stderr)
	if !strings.Contains(stdout, "hello") {
		t.Errorf("expected 'hello' in stdout, got: %s", stdout)
	}
}

// TestSandbox_SharedLibsLoadWithRO tests that dynamically linked binaries work.
// /lib is ro — shared libraries are loaded via mmap (not execve), so ro is sufficient.
func TestSandbox_SharedLibsLoadWithRO(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	sb := setupTestSandbox(t)

	// ls is dynamically linked and needs /lib for libc.so
	exitCode, _, stderr := runInSandbox(t, sb, "ls", "/tmp")
	assertAllowed(t, "shared libs load with ro on /lib", exitCode, stderr)
}

// TestSandbox_BlocksProcAccess tests that /proc access is blocked.
// NOTE: Landlock (Layer 2) cannot block specific files within allowed directories.
// /proc is in the allowlist because many commands need it. Blocking /proc/*/cmdline
// is a Layer 1 (rules engine) responsibility, not Layer 2 (sandbox).
// This test is skipped on Linux because Landlock can't provide this protection.
func TestSandbox_BlocksProcAccess(t *testing.T) {
	if !IsSupported() {
		t.Skip("Sandbox not supported")
	}

	// /proc only exists on Linux
	if _, err := os.Stat("/proc"); os.IsNotExist(err) {
		t.Skip("/proc does not exist on this platform")
	}

	// Skip on Linux: Landlock can't block specific files within allowed directories.
	// /proc must be in the allowlist for commands to work, so /proc/*/cmdline is accessible.
	// Blocking these paths is done by Layer 1 (rules engine), not Layer 2 (sandbox).
	if isLandlockSupported() {
		t.Skip("Landlock cannot block specific files within allowed directories; /proc access is blocked by Layer 1 rules engine")
	}

	sb := setupTestSandbox(t)

	tests := []struct {
		name string
		file string
	}{
		{"read /proc/1/cmdline", "/proc/1/cmdline"},
		{"read /proc/1/environ", "/proc/1/environ"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, _, stderr := runInSandbox(t, sb, "cat", tt.file)
			assertBlocked(t, tt.name, exitCode, stderr)
		})
	}
}
