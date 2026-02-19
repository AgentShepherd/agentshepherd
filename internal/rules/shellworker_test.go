package rules

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestMain enables the test binary to act as a shell worker subprocess.
// When invoked with _CRUST_SHELL_WORKER=1, it enters the worker loop
// instead of running tests.
func TestMain(m *testing.M) {
	if RunShellWorkerMain() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestShellWorkerSubprocess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot get test executable path: %v", err)
	}

	ext := NewExtractor()
	if err := ext.EnableSubprocessIsolation(exe); err != nil {
		t.Fatalf("EnableSubprocessIsolation failed: %v", err)
	}
	defer ext.Close()

	// Simple command extraction via worker
	info := ext.Extract("Bash", json.RawMessage(`{"command":"cat /etc/passwd"}`))
	if len(info.Paths) == 0 {
		t.Error("expected paths from worker extraction, got none")
	}
	if !slices.Contains(info.Paths, "/etc/passwd") {
		t.Errorf("expected /etc/passwd in paths, got %v", info.Paths)
	}

	// Pipeline extraction via worker
	info2 := ext.Extract("Bash", json.RawMessage(`{"command":"cat /etc/shadow | grep root > /tmp/out"}`))
	if len(info2.Paths) == 0 {
		t.Error("expected paths from pipeline extraction, got none")
	}

	// Process substitution should be flagged as evasive
	info3 := ext.Extract("Bash", json.RawMessage(`{"command":"diff <(cat /etc/passwd) <(cat /etc/shadow)"}`))
	if !info3.Evasive {
		t.Error("expected process substitution to be flagged as evasive")
	}
}

func TestShellWorkerCrashRecovery(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot get test executable path: %v", err)
	}

	ext := NewExtractor()
	if err := ext.EnableSubprocessIsolation(exe); err != nil {
		t.Fatalf("EnableSubprocessIsolation failed: %v", err)
	}
	defer ext.Close()

	// Coproc should be handled (either by astHasUnsafe pre-check or worker crash)
	info := ext.Extract("Bash", json.RawMessage(`{"command":"coproc cat /etc/shadow"}`))
	if !info.Evasive {
		t.Error("expected coproc to be flagged as evasive")
	}

	// After a potential crash, the next command should still work
	info2 := ext.Extract("Bash", json.RawMessage(`{"command":"cat /tmp/test"}`))
	if len(info2.Paths) == 0 {
		t.Error("expected paths after crash recovery, got none")
	}
}
