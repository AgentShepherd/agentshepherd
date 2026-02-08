//go:build linux

package bpfloader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilenameKey(t *testing.T) {
	tests := []struct {
		name string
		want byte // first byte after the name should be 0
	}{
		{".env", 0},
		{".bashrc", 0},
		{"credentials", 0},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := filenameKey(tt.name)

			// Check that the name is at the start
			for i := 0; i < len(tt.name); i++ {
				if key[i] != tt.name[i] {
					t.Errorf("key[%d] = %d, want %d", i, key[i], tt.name[i])
				}
			}

			// Check that the rest is zero-padded
			for i := len(tt.name); i < maxFilename; i++ {
				if key[i] != 0 {
					t.Errorf("key[%d] = %d, want 0 (zero padding)", i, key[i])
					break
				}
			}
		})
	}
}

func TestFilenameKey_MaxLength(t *testing.T) {
	// Name exactly maxFilename chars
	long := make([]byte, maxFilename)
	for i := range long {
		long[i] = 'a'
	}
	key := filenameKey(string(long))
	if key[0] != 'a' || key[maxFilename-1] != 'a' {
		t.Error("max-length name should fill entire key")
	}
}

func TestCStringToGo(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"normal", []byte{'.', 'e', 'n', 'v', 0, 0, 0}, ".env"},
		{"empty", []byte{0, 0, 0}, ""},
		{"no null", []byte{'a', 'b', 'c'}, "abc"},
		{"null at start", []byte{0, 'a', 'b'}, ""},
		{"single char", []byte{'x', 0}, "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cStringToGo(tt.input)
			if got != tt.want {
				t.Errorf("cStringToGo(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveInode(t *testing.T) {
	// Create a temp file and resolve its inode
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test-file")
	if err := os.WriteFile(tmpFile, []byte("test"), 0600); err != nil {
		t.Fatalf("create temp file: %v", err)
	}

	ino, err := resolveInode(tmpFile)
	if err != nil {
		t.Fatalf("resolveInode(%q): %v", tmpFile, err)
	}
	if ino == 0 {
		t.Error("expected non-zero inode")
	}

	// Same file should return same inode
	ino2, err := resolveInode(tmpFile)
	if err != nil {
		t.Fatalf("resolveInode(%q) second call: %v", tmpFile, err)
	}
	if ino != ino2 {
		t.Errorf("inode changed: %d != %d", ino, ino2)
	}
}

func TestResolveInode_NonExistent(t *testing.T) {
	_, err := resolveInode("/nonexistent/path/that/doesnt/exist")
	if err == nil {
		t.Error("expected error for non-existent path")
	}
}

func TestResolveInode_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	ino, err := resolveInode(tmpDir)
	if err != nil {
		t.Fatalf("resolveInode directory: %v", err)
	}
	if ino == 0 {
		t.Error("expected non-zero inode for directory")
	}
}

func TestResolveInode_DifferentFiles(t *testing.T) {
	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "file1")
	file2 := filepath.Join(tmpDir, "file2")
	os.WriteFile(file1, []byte("a"), 0600)
	os.WriteFile(file2, []byte("b"), 0600)

	ino1, _ := resolveInode(file1)
	ino2, _ := resolveInode(file2)

	if ino1 == ino2 {
		t.Errorf("different files should have different inodes: %d == %d", ino1, ino2)
	}
}
