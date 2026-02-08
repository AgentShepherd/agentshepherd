//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/BakeLens/crust/internal/sandbox"
)

func TestVerifyPeer_SameUID(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Connect from same UID
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- verifyPeer(conn, uint32(os.Getuid()))
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	if err := <-done; err != nil {
		t.Fatalf("verifyPeer should succeed for same UID: %v", err)
	}
}

func TestVerifyPeer_WrongUID(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	// Use a UID that doesn't match
	wrongUID := uint32(os.Getuid()) + 12345
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		done <- verifyPeer(conn, wrongUID)
	}()

	client, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	err = <-done
	if err == nil {
		t.Fatal("verifyPeer should reject wrong UID")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestSocketPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	if err := os.Chmod(sockPath, 0600); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Check mode bits (mask out socket type bits)
	perm := fi.Mode().Perm()
	if perm != 0600 {
		t.Errorf("socket permissions = %o, want 0600", perm)
	}
}

func TestValidateRules_Valid(t *testing.T) {
	rules := &sandbox.BPFDenySet{
		Filenames: []sandbox.BPFDenyEntry{
			{Type: "filename", Key: ".env", RuleID: 1, RuleName: "test"},
		},
		InodePaths: []sandbox.BPFDenyEntry{
			{Type: "inode", Key: "/etc/passwd", RuleID: 2, RuleName: "test2"},
		},
	}
	if err := validateRules(rules); err != nil {
		t.Fatalf("validateRules should accept valid rules: %v", err)
	}
}

func TestValidateRules_TooMany(t *testing.T) {
	entries := make([]sandbox.BPFDenyEntry, maxRulesPerMessage+1)
	for i := range entries {
		entries[i] = sandbox.BPFDenyEntry{Type: "filename", Key: ".env", RuleID: uint32(i)}
	}
	rules := &sandbox.BPFDenySet{Filenames: entries}
	err := validateRules(rules)
	if err == nil {
		t.Fatal("validateRules should reject too many rules")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestValidateRules_InvalidType(t *testing.T) {
	rules := &sandbox.BPFDenySet{
		Filenames: []sandbox.BPFDenyEntry{
			{Type: "bogus", Key: ".env", RuleID: 1},
		},
	}
	err := validateRules(rules)
	if err == nil {
		t.Fatal("validateRules should reject invalid type")
	}
	t.Logf("correctly rejected: %v", err)
}

func TestValidateRules_InvalidInodeType(t *testing.T) {
	rules := &sandbox.BPFDenySet{
		InodePaths: []sandbox.BPFDenyEntry{
			{Type: "filename", Key: "/etc/passwd", RuleID: 1},
		},
	}
	err := validateRules(rules)
	if err == nil {
		t.Fatal("validateRules should reject invalid inode type")
	}
}
