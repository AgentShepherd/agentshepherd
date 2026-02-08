//go:build linux

// bpf-helper is a privileged daemon that loads eBPF LSM programs for
// Crust Layer 2b deny-list enforcement.
//
// It runs as root (requires CAP_BPF + CAP_SYS_ADMIN), loads the BPF
// program once, then listens on a Unix socket for rule updates from
// the main Crust process.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/sandbox"
	"github.com/BakeLens/crust/internal/sandbox/bpfloader"
)

const (
	pidFileName        = "bpf-helper.pid"
	socketFileName     = "bpf.sock"
	maxClients         = 8
	maxRulesPerMessage = 10000
)

var log = logger.New("bpf-helper")

func main() {
	socketFlag := flag.String("socket", "", "Unix socket path (default: ~/.crust/bpf.sock)")
	uidFlag := flag.Int("uid", -1, "Allowed client UID (required; set to the user who runs crust)")
	flag.Parse()

	if *uidFlag < 0 || *uidFlag > 0xFFFFFFFF {
		fmt.Fprintln(os.Stderr, "bpf-helper: --uid flag is required and must be a valid UID (0–4294967295)")
		os.Exit(1)
	}
	allowedUID := uint32(*uidFlag) //nolint:gosec // range validated above

	// Check capabilities
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "bpf-helper requires root privileges (CAP_BPF + CAP_SYS_ADMIN)")
		os.Exit(1)
	}

	// Determine socket path
	var sockPath string
	if *socketFlag != "" {
		sockPath = *socketFlag
		dir := filepath.Dir(sockPath)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Socket directory does not exist: %s\n", dir)
			os.Exit(1)
		}
	} else {
		sockPath = filepath.Join(dataDir(), socketFileName)
	}

	dataDirectory := filepath.Dir(sockPath)

	// Write PID file with flock to prevent duplicate instances
	pidPath := filepath.Join(dataDirectory, pidFileName)
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open PID file: %v\n", err)
		os.Exit(1)
	}
	if err := unix.Flock(int(pidFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		pidFile.Close()
		fmt.Fprintf(os.Stderr, "Another bpf-helper instance is running (flock %s): %v\n", pidPath, err)
		os.Exit(1)
	}
	if err := pidFile.Truncate(0); err != nil {
		pidFile.Close()
		fmt.Fprintf(os.Stderr, "Failed to truncate PID file: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(pidFile, "%d", os.Getpid())
	defer func() {
		pidFile.Close()
		os.Remove(pidPath)
	}()

	// Load BPF program
	loader, err := bpfloader.NewBPFLoader()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load BPF program: %v\n", err)
		os.Exit(1)
	}
	defer loader.Close()

	// Setup violation event forwarding
	var clientsMu sync.Mutex
	var clients []net.Conn

	loader.OnViolation(func(v sandbox.BPFViolation) {
		resp := sandbox.BPFResponse{
			Type:      sandbox.BPFMsgViolation,
			Violation: &v,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return
		}
		data = append(data, '\n')

		clientsMu.Lock()
		defer clientsMu.Unlock()
		for i := 0; i < len(clients); i++ {
			if _, err := clients[i].Write(data); err != nil {
				clients[i].Close()
				clients = append(clients[:i], clients[i+1:]...)
				i--
			}
		}
	})

	// Create Unix socket with restrictive umask to eliminate TOCTOU race
	// between socket creation and chmod. The socket is created with 0600
	// permissions from the start.
	oldUmask := syscall.Umask(0077)
	os.Remove(sockPath) // clean up stale socket
	listener, err := net.Listen("unix", sockPath)
	syscall.Umask(oldUmask) // restore original umask
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on %s: %v\n", sockPath, err)
		os.Exit(1)
	}
	defer listener.Close()
	defer os.Remove(sockPath)
	// Chown socket to the allowed UID so only they can connect
	if err := os.Chown(sockPath, int(allowedUID), -1); err != nil {
		log.Warn("Failed to chown socket: %v", err)
	}

	log.Info("BPF helper listening on %s (allowed UID=%d)", sockPath, allowedUID)

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Connection limiter
	var activeConns atomic.Int32

	// Accept connections in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}

			// Verify peer credentials via SO_PEERCRED
			if err := verifyPeer(conn, allowedUID); err != nil {
				log.Warn("Rejected connection: %v", err)
				conn.Close()
				continue
			}

			// Enforce connection limit
			if activeConns.Load() >= maxClients {
				log.Warn("Connection limit reached (%d), rejecting", maxClients)
				conn.Close()
				continue
			}
			activeConns.Add(1)

			clientsMu.Lock()
			clients = append(clients, conn)
			clientsMu.Unlock()

			go func() {
				defer activeConns.Add(-1)
				handleClient(conn, loader)
			}()
		}
	}()

	// Wait for signal
	sig := <-sigCh
	log.Info("Received %v, shutting down", sig)
}

func handleClient(conn net.Conn, loader *bpfloader.BPFLoader) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB max message

	for scanner.Scan() {
		line := scanner.Bytes()
		var req sandbox.BPFRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendError(conn, fmt.Sprintf("invalid JSON: %v", err))
			continue
		}

		switch req.Type {
		case sandbox.BPFMsgRules:
			if req.Rules == nil {
				sendError(conn, "RULES message missing rules")
				continue
			}
			if err := validateRules(req.Rules); err != nil {
				sendError(conn, err.Error())
				continue
			}
			count, err := applyRules(loader, req.Rules)
			if err != nil {
				sendError(conn, err.Error())
				continue
			}
			sendOK(conn, count)

		case sandbox.BPFMsgPID:
			var err error
			if req.Add {
				err = loader.AddTargetPID(req.PID)
			} else {
				err = loader.RemoveTargetPID(req.PID)
			}
			if err != nil {
				sendError(conn, err.Error())
				continue
			}
			sendOK(conn, 0)

		default:
			sendError(conn, fmt.Sprintf("unknown message type: %s", req.Type))
		}
	}
}

func applyRules(loader *bpfloader.BPFLoader, rules *sandbox.BPFDenySet) (int, error) {
	if err := loader.UpdateFilenames(rules.Filenames); err != nil {
		return 0, fmt.Errorf("update filenames: %w", err)
	}
	if err := loader.UpdateInodes(rules.InodePaths); err != nil {
		return 0, fmt.Errorf("update inodes: %w", err)
	}
	if err := loader.UpdateExceptions(rules.Exceptions); err != nil {
		return 0, fmt.Errorf("update exceptions: %w", err)
	}
	count := len(rules.Filenames) + len(rules.InodePaths)
	log.Info("Applied %d deny rules (%d filenames, %d inodes, %d exceptions)",
		count, len(rules.Filenames), len(rules.InodePaths), len(rules.Exceptions))
	return count, nil
}

func sendOK(conn net.Conn, count int) {
	resp := sandbox.BPFResponse{Type: sandbox.BPFMsgOK, Count: count}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		log.Warn("Failed to send OK response: %v", err)
	}
}

func sendError(conn net.Conn, msg string) {
	resp := sandbox.BPFResponse{Type: sandbox.BPFMsgError, Error: msg}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if _, err := conn.Write(append(data, '\n')); err != nil {
		log.Warn("Failed to send error response: %v", err)
	}
}

// verifyPeer checks that the connecting client has the expected UID using SO_PEERCRED.
func verifyPeer(conn net.Conn, allowedUID uint32) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return fmt.Errorf("get syscall conn: %w", err)
	}
	var ucred *unix.Ucred
	var credErr error
	if err = raw.Control(func(fd uintptr) {
		ucred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("raw control: %w", err)
	}
	if credErr != nil {
		return fmt.Errorf("getsockopt SO_PEERCRED: %w", credErr)
	}
	if ucred.Uid != allowedUID {
		return fmt.Errorf("unauthorized UID %d (expected %d)", ucred.Uid, allowedUID)
	}
	return nil
}

// validateRules checks that a BPFDenySet is within limits and has valid entries.
func validateRules(rules *sandbox.BPFDenySet) error {
	total := len(rules.Filenames) + len(rules.InodePaths)
	if total > maxRulesPerMessage {
		return fmt.Errorf("too many rules: %d (max %d)", total, maxRulesPerMessage)
	}
	for _, e := range rules.Filenames {
		if e.Type != "filename" {
			return fmt.Errorf("invalid entry type %q for filename rule (expected \"filename\")", e.Type)
		}
	}
	for _, e := range rules.InodePaths {
		if e.Type != "inode" {
			return fmt.Errorf("invalid entry type %q for inode rule (expected \"inode\")", e.Type)
		}
	}
	return nil
}

func dataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	dir := filepath.Join(home, ".crust")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return filepath.Join("/tmp", ".crust")
	}
	return dir
}
