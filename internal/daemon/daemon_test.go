//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWritePID_ExclusiveLock(t *testing.T) {
	// Use a temp dir so we don't interfere with real PID files.
	tmpDir := t.TempDir()

	// Override pidFile() via a custom profile path isn't possible here since
	// pidFile() uses DataDir(). Instead, we test the flock logic directly.
	path := filepath.Join(tmpDir, "test.pid")

	// Acquire lock manually
	f1, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f1.Close()

	if err := unix.Flock(int(f1.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("first flock: %v", err)
	}

	// Second attempt should fail (EWOULDBLOCK)
	f2, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open second: %v", err)
	}
	defer f2.Close()

	err = unix.Flock(int(f2.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		t.Fatal("second flock should fail when first holds lock")
	}

	// Release first lock
	unix.Flock(int(f1.Fd()), unix.LOCK_UN)

	// Now second should succeed
	if err := unix.Flock(int(f2.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("flock after release should succeed: %v", err)
	}
}
