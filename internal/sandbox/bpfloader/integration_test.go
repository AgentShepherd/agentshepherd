//go:build linux

package bpfloader

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/sandbox"
)

// skipUnlessBPF skips the test if BPF LSM is not available (not root, no LSM support).
func skipUnlessBPF(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_SYS_ADMIN)")
	}
}

func TestBPFLoader_Load(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()
}

func TestBPFLoader_DenyFilename(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	// Create a temp .env file
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envFile, []byte("SECRET=hunter2"), 0644); err != nil {
		t.Fatalf("create .env: %v", err)
	}

	// Add ".env" to denied filenames
	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test-deny-env"},
	}); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}

	// Add our PID as target
	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// Try to open .env — should be denied
	_, err = os.Open(envFile)
	if err == nil {
		t.Fatal("expected EPERM opening .env, got nil")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got: %v", err)
	}

	// A file with a different name should still be accessible
	otherFile := filepath.Join(tmpDir, "config.txt")
	if err := os.WriteFile(otherFile, []byte("ok"), 0644); err != nil {
		t.Fatalf("create config.txt: %v", err)
	}
	f, err := os.Open(otherFile)
	if err != nil {
		t.Fatalf("opening config.txt should succeed: %v", err)
	}
	f.Close()
}

func TestBPFLoader_DenyFilename_Exception(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	envExample := filepath.Join(tmpDir, ".env.example")
	os.WriteFile(envFile, []byte("SECRET=hunter2"), 0644)
	os.WriteFile(envExample, []byte("SECRET=placeholder"), 0644)

	// Deny ".env", allow ".env.example"
	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test-deny-env"},
	}); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}
	if err := loader.UpdateExceptions([]string{".env.example"}); err != nil {
		t.Fatalf("UpdateExceptions: %v", err)
	}

	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// .env should be denied
	_, err = os.Open(envFile)
	if err == nil {
		t.Fatal("expected EPERM opening .env")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got: %v", err)
	}

	// .env.example should be allowed (exception)
	f, err := os.Open(envExample)
	if err != nil {
		t.Fatalf("opening .env.example should succeed (exception): %v", err)
	}
	f.Close()
}

func TestBPFLoader_DenyInode(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "credentials")
	os.WriteFile(secretFile, []byte("AWS_KEY=xxx"), 0644)

	// Resolve inode and add to denied_inodes
	ino, err := resolveInode(secretFile)
	if err != nil {
		t.Fatalf("resolveInode: %v", err)
	}

	if err := loader.maps.DeniedInodes.Put(ino, uint32(2)); err != nil {
		t.Fatalf("put denied_inodes: %v", err)
	}

	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// Opening the file by inode should be denied
	_, err = os.Open(secretFile)
	if err == nil {
		t.Fatal("expected EPERM opening inode-denied file")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got: %v", err)
	}
}

func TestBPFLoader_TargetPIDScope(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("SECRET=hunter2"), 0644)

	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test"},
	}); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}

	// Without adding our PID as target, the file should be accessible
	f, err := os.Open(envFile)
	if err != nil {
		t.Fatalf("expected .env to be accessible without target PID: %v", err)
	}
	f.Close()

	// Now add our PID
	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}

	// Should be denied now
	_, err = os.Open(envFile)
	if err == nil {
		t.Fatal("expected EPERM after adding target PID")
	}
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("expected EPERM, got: %v", err)
	}

	// Remove our PID
	if err := loader.RemoveTargetPID(pid); err != nil {
		t.Fatalf("RemoveTargetPID: %v", err)
	}

	// Should be accessible again
	f, err = os.Open(envFile)
	if err != nil {
		t.Fatalf("expected .env to be accessible after removing target PID: %v", err)
	}
	f.Close()
}

func TestBPFLoader_ViolationEvent(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	os.WriteFile(envFile, []byte("SECRET=hunter2"), 0644)

	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 42, RuleName: "test-violation"},
	}); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}

	// Register violation callback
	violations := make(chan sandbox.BPFViolation, 10)
	loader.OnViolation(func(v sandbox.BPFViolation) {
		violations <- v
	})

	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// Trigger violation
	_, _ = os.Open(envFile)

	// Wait for violation event
	select {
	case v := <-violations:
		if v.RuleID != 42 {
			t.Errorf("violation RuleID = %d, want 42", v.RuleID)
		}
		if v.Filename != ".env" {
			t.Errorf("violation Filename = %q, want .env", v.Filename)
		}
		if v.PID != pid {
			t.Errorf("violation PID = %d, want %d", v.PID, pid)
		}
		t.Logf("Got violation event: rule=%d filename=%q pid=%d inode=%d", v.RuleID, v.Filename, v.PID, v.Inode)
	case <-time.After(2 * time.Second):
		t.Error("timed out waiting for violation event")
	}
}

func TestBPFLoader_RuleUpdate(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	bashrcFile := filepath.Join(tmpDir, ".bashrc")
	os.WriteFile(envFile, []byte("SECRET=hunter2"), 0644)
	os.WriteFile(bashrcFile, []byte("alias ls='ls --color'"), 0644)

	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// Initially deny only .env
	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test"},
	}); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}

	// .env denied, .bashrc allowed
	_, err = os.Open(envFile)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf(".env: expected EPERM, got %v", err)
	}
	f, err := os.Open(bashrcFile)
	if err != nil {
		t.Fatalf(".bashrc should be accessible: %v", err)
	}
	f.Close()

	// Update rules: now deny .bashrc too
	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test"},
		{Type: "filename", Key: ".bashrc", RuleID: 2, RuleName: "test2"},
	}); err != nil {
		t.Fatalf("UpdateFilenames (update): %v", err)
	}

	// Both should be denied
	_, err = os.Open(envFile)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf(".env: expected EPERM after update, got %v", err)
	}
	_, err = os.Open(bashrcFile)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf(".bashrc: expected EPERM after update, got %v", err)
	}

	// Update rules: remove .env, keep only .bashrc
	if err := loader.UpdateFilenames([]sandbox.BPFDenyEntry{
		{Type: "filename", Key: ".bashrc", RuleID: 2, RuleName: "test2"},
	}); err != nil {
		t.Fatalf("UpdateFilenames (remove): %v", err)
	}

	// .env should now be accessible, .bashrc still denied
	f, err = os.Open(envFile)
	if err != nil {
		t.Fatalf(".env should be accessible after rule removal: %v", err)
	}
	f.Close()
	_, err = os.Open(bashrcFile)
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf(".bashrc: expected EPERM, got %v", err)
	}
}

func TestBPFLoader_E2E_FullStack(t *testing.T) {
	skipUnlessBPF(t)

	loader, err := NewBPFLoader()
	if err != nil {
		t.Fatalf("NewBPFLoader: %v", err)
	}
	defer loader.Close()

	// Use the real rule pipeline: rules → TranslateToBPF → BPF maps
	testRules := []rules.Rule{
		{
			Name:  "protect-env",
			Block: rules.Block{Paths: []string{"**/.env"}, Except: []string{"**/.env.example"}},
		},
		{
			Name:  "protect-bashrc",
			Block: rules.Block{Paths: []string{"**/.bashrc"}},
		},
	}

	secRules := make([]sandbox.SecurityRule, len(testRules))
	for i := range testRules {
		secRules[i] = &testRules[i]
	}
	ds := sandbox.TranslateToBPF(secRules)

	if err := loader.UpdateFilenames(ds.Filenames); err != nil {
		t.Fatalf("UpdateFilenames: %v", err)
	}
	if err := loader.UpdateInodes(ds.InodePaths); err != nil {
		t.Fatalf("UpdateInodes: %v", err)
	}
	if err := loader.UpdateExceptions(ds.Exceptions); err != nil {
		t.Fatalf("UpdateExceptions: %v", err)
	}

	// Create test files
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, ".env")
	envExample := filepath.Join(tmpDir, ".env.example")
	bashrcFile := filepath.Join(tmpDir, ".bashrc")
	normalFile := filepath.Join(tmpDir, "README.md")

	os.WriteFile(envFile, []byte("SECRET=x"), 0644)
	os.WriteFile(envExample, []byte("SECRET=placeholder"), 0644)
	os.WriteFile(bashrcFile, []byte("alias ls=ls"), 0644)
	os.WriteFile(normalFile, []byte("# readme"), 0644)

	pid := uint32(os.Getpid())
	if err := loader.AddTargetPID(pid); err != nil {
		t.Fatalf("AddTargetPID: %v", err)
	}
	defer loader.RemoveTargetPID(pid)

	// Test matrix
	tests := []struct {
		name      string
		file      string
		expectErr bool
	}{
		{".env should be denied", envFile, true},
		{".env.example should be allowed (exception)", envExample, false},
		{".bashrc should be denied", bashrcFile, true},
		{"README.md should be allowed", normalFile, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			if tt.expectErr {
				if err == nil {
					t.Errorf("expected EPERM, got nil")
				} else if !errors.Is(err, syscall.EPERM) {
					t.Errorf("expected EPERM, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("expected success, got: %v", err)
				} else {
					f.Close()
				}
			}
		})
	}
}
