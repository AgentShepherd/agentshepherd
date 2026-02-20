//go:build unix

package security

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortTempDir creates a temp directory under /tmp with a short path, working
// around the macOS t.TempDir() paths that exceed the 103-byte Unix socket limit.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "crust-") //nolint:usetesting // t.TempDir() paths exceed the 103-byte Unix socket sun_path limit on macOS
	if err != nil {
		t.Fatalf("shortTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestAPIListener_CreatesSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("apiListener: %v", err)
	}
	defer ln.Close()
	defer cleanupSocket(sockPath)

	// Socket file should exist with 0600 permissions
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	// On Linux/macOS, socket mode includes the socket type bit
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("socket perm = %o, want 0600", perm)
	}

	// Lockfile should exist
	lockPath := sockPath + ".lock"
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("lockfile should exist: %v", err)
	}
}

func TestAPIListener_DetectsLiveInstance(t *testing.T) {
	dir := shortTempDir(t)
	sockPath := filepath.Join(dir, "test.sock")

	ln1, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("first listener: %v", err)
	}
	defer ln1.Close()
	defer cleanupSocket(sockPath)

	// Second listener should fail — flock held
	_, err = apiListener(sockPath)
	if err == nil {
		t.Fatal("second listener should fail")
	}
	if !strings.Contains(err.Error(), "another instance") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAPIListener_RemovesStaleSocket(t *testing.T) {
	dir := shortTempDir(t)
	sockPath := filepath.Join(dir, "test.sock")

	// Create a listener, then close it to simulate a crash
	ln1, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("first listener: %v", err)
	}
	ln1.Close()
	cleanupSocket(sockPath) // release flock + remove files

	// Recreate stale socket file (simulates crash leaving file behind)
	_ = os.WriteFile(sockPath, nil, 0600)

	// New listener should succeed (stale socket cleaned up, flock available)
	ln2, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("second listener after cleanup: %v", err)
	}
	defer ln2.Close()
	defer cleanupSocket(sockPath)
}

func TestAPIListener_PathTooLong(t *testing.T) {
	dir := t.TempDir()
	longName := strings.Repeat("a", 200) + ".sock"
	sockPath := filepath.Join(dir, longName)

	_, err := apiListener(sockPath)
	if err == nil {
		t.Fatal("should fail for long path")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAPIListener_HTTPOverSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "api.sock")

	ln, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("apiListener: %v", err)
	}
	defer cleanupSocket(sockPath)

	// Start a simple HTTP server on the socket
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// Wait briefly for server to start
	time.Sleep(10 * time.Millisecond)

	// Connect via socket transport
	transport := APITransport(sockPath)
	client := &http.Client{Transport: transport}

	resp, err := client.Get("http://crust-api/health")
	if err != nil || resp == nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAPIListener_MultiSession(t *testing.T) {
	dir := shortTempDir(t)
	sock1 := filepath.Join(dir, "crust-api-9090.sock")
	sock2 := filepath.Join(dir, "crust-api-9091.sock")

	// Start two listeners on different socket paths (simulating two crust sessions)
	ln1, err := apiListener(sock1)
	if err != nil {
		t.Fatalf("listener 1: %v", err)
	}
	defer ln1.Close()
	defer cleanupSocket(sock1)

	ln2, err := apiListener(sock2)
	if err != nil {
		t.Fatalf("listener 2: %v", err)
	}
	defer ln2.Close()
	defer cleanupSocket(sock2)

	// Both sockets should exist
	if _, err := os.Stat(sock1); err != nil {
		t.Errorf("sock1 missing: %v", err)
	}
	if _, err := os.Stat(sock2); err != nil {
		t.Errorf("sock2 missing: %v", err)
	}

	// Start HTTP servers on each
	for i, ln := range []net.Listener{ln1, ln2} {
		port := 9090 + i
		mux := http.NewServeMux()
		mux.HandleFunc("/port", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", port)))
		})
		srv := &http.Server{Handler: mux}
		go func() { _ = srv.Serve(ln) }()
		defer srv.Close()
	}

	time.Sleep(10 * time.Millisecond)

	// Both sessions should be independently reachable
	for _, sockPath := range []string{sock1, sock2} {
		client := &http.Client{Transport: APITransport(sockPath)}
		resp, err := client.Get("http://crust-api/port")
		if err != nil || resp == nil {
			t.Fatalf("GET /port on %s: %v", sockPath, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status on %s = %d, want 200", sockPath, resp.StatusCode)
		}
	}
}

func TestCleanupSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := apiListener(sockPath)
	if err != nil {
		t.Fatalf("apiListener: %v", err)
	}
	ln.Close()
	cleanupSocket(sockPath)

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Error("socket file should be removed after cleanup")
	}
	if _, err := os.Stat(sockPath + ".lock"); !os.IsNotExist(err) {
		t.Error("lockfile should be removed after cleanup")
	}
}
