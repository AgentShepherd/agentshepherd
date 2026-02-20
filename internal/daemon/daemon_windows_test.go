//go:build windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWritePID_ExclusiveLock(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pid")

	// Acquire exclusive lock at the high offset (matching production code)
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()

	ol := &windows.Overlapped{Offset: 0x7FFFFFFF}
	err = windows.LockFileEx(
		windows.Handle(f1.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	)
	if err != nil {
		t.Fatalf("first LockFileEx: %v", err)
	}

	// Write PID content
	fmt.Fprintf(f1, "%d", os.Getpid())

	// Second lock attempt should fail (LOCKFILE_FAIL_IMMEDIATELY)
	f2, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer f2.Close()

	ol2 := &windows.Overlapped{Offset: 0x7FFFFFFF}
	err = windows.LockFileEx(
		windows.Handle(f2.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol2,
	)
	if err == nil {
		t.Fatal("second LockFileEx should fail when first holds lock")
	}

	// Release first lock
	ol3 := &windows.Overlapped{Offset: 0x7FFFFFFF}
	windows.UnlockFileEx(windows.Handle(f1.Fd()), 0, 1, 0, ol3)
	f1.Close()

	// Now second should succeed
	f3, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open third: %v", err)
	}
	defer f3.Close()

	ol4 := &windows.Overlapped{Offset: 0x7FFFFFFF}
	if err := windows.LockFileEx(
		windows.Handle(f3.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol4,
	); err != nil {
		t.Fatalf("LockFileEx after release should succeed: %v", err)
	}
}

func TestPIDFile_ReadableWhileLocked(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pid")

	// Simulate daemon: open, lock at high offset, write PID
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	ol := &windows.Overlapped{Offset: 0x7FFFFFFF}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, ol,
	)
	if err != nil {
		t.Fatalf("LockFileEx: %v", err)
	}

	pid := os.Getpid()
	fmt.Fprintf(f, "%d", pid)
	f.Sync()

	// Simulate status command: another process reads the PID file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile should succeed while lock is at high offset: %v", err)
	}

	got := string(data)
	want := fmt.Sprintf("%d", pid)
	if got != want {
		t.Errorf("PID content = %q, want %q", got, want)
	}
}
