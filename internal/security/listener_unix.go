//go:build unix

package security

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const maxSocketPathLen = 104 // macOS floor (Linux is 108)

// socketLockFile holds the flock on the socket lockfile.
// Released on process exit (kernel clears advisory locks).
var socketLockFile *os.File

// apiListener creates a Unix domain socket listener at the given path.
// It uses a lockfile (socketPath + ".lock") with flock to atomically
// detect stale sockets from crashed instances, eliminating TOCTOU races.
func apiListener(socketPath string) (net.Listener, error) {
	if len(socketPath) >= maxSocketPathLen {
		return nil, fmt.Errorf("socket path too long (%d bytes, max %d): %s", len(socketPath), maxSocketPathLen-1, socketPath)
	}

	// Acquire exclusive flock on a lockfile — this is the authoritative
	// ownership check. If the lock succeeds, no other instance owns this socket.
	lockPath := socketPath + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open socket lockfile %s: %w", lockPath, err)
	}
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // Fd() fits in int
		lf.Close()
		return nil, fmt.Errorf("another instance owns %s (flock %s): %w", socketPath, lockPath, err)
	}
	socketLockFile = lf

	// Safe to remove stale socket — we hold the lock
	_ = os.Remove(socketPath)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", socketPath)
	if err != nil {
		lf.Close()
		socketLockFile = nil
		return nil, fmt.Errorf("listen unix %s: %w", socketPath, err)
	}

	// Explicit chmod — don't rely on umask
	if err := os.Chmod(socketPath, 0600); err != nil {
		ln.Close()
		_ = os.Remove(socketPath)
		lf.Close()
		socketLockFile = nil
		return nil, fmt.Errorf("chmod socket %s: %w", socketPath, err)
	}

	return ln, nil
}

// cleanupSocket removes the socket file and releases the flock on shutdown.
func cleanupSocket(socketPath string) {
	_ = os.Remove(socketPath)
	_ = os.Remove(socketPath + ".lock")
	if socketLockFile != nil {
		socketLockFile.Close()
		socketLockFile = nil
	}
}
