//go:build linux

package sandbox

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockBPFHelper starts a mock Unix socket server that simulates the bpf-helper daemon.
// Returns the socket path and a cleanup function.
func mockBPFHelper(t *testing.T, handler func(net.Conn)) (string, func()) {
	t.Helper()
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "bpf-test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()

	return sockPath, func() { ln.Close(); os.Remove(sockPath) }
}

func TestBPFClient_Connect(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		// Just accept and hold connection
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			// echo OK for any message
			resp := BPFResponse{Type: BPFMsgOK, Count: 0}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()
}

func TestBPFClient_ConnectFailure(t *testing.T) {
	_, err := NewBPFClient("/nonexistent/path/bpf.sock")
	if err == nil {
		t.Error("expected error connecting to non-existent socket")
	}
}

func TestBPFClient_SyncRules(t *testing.T) {
	var receivedReq BPFRequest

	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			json.Unmarshal(scanner.Bytes(), &receivedReq)
			resp := BPFResponse{Type: BPFMsgOK, Count: 5}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	syncRules := []SecurityRule{
		&testRule{
			name:   "protect-env-files",
			paths:  []string{"**/.env"},
			except: []string{"**/.env.example"},
		},
		&testRule{
			name:  "protect-bashrc",
			paths: []string{"**/.bashrc"},
		},
	}

	if err := client.SyncRules(syncRules); err != nil {
		t.Fatalf("SyncRules: %v", err)
	}

	// Verify the request was received
	if receivedReq.Type != BPFMsgRules {
		t.Errorf("received type = %q, want RULES", receivedReq.Type)
	}
	if receivedReq.Rules == nil {
		t.Fatal("received rules is nil")
	}
	if len(receivedReq.Rules.Filenames) != 2 {
		t.Errorf("received %d filenames, want 2", len(receivedReq.Rules.Filenames))
	}
}

func TestBPFClient_SyncRules_ErrorResponse(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			resp := BPFResponse{Type: BPFMsgError, Error: "test error"}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	err = client.SyncRules([]SecurityRule{
		&testRule{name: "test", paths: []string{"**/.env"}},
	})
	if err == nil {
		t.Error("expected error from error response")
	}
}

func TestBPFClient_SetTargetPID(t *testing.T) {
	var receivedReq BPFRequest

	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			json.Unmarshal(scanner.Bytes(), &receivedReq)
			resp := BPFResponse{Type: BPFMsgOK}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	if err := client.SetTargetPID(12345, true); err != nil {
		t.Fatalf("SetTargetPID(add): %v", err)
	}
	if receivedReq.Type != BPFMsgPID {
		t.Errorf("type = %q, want PID", receivedReq.Type)
	}
	if receivedReq.PID != 12345 {
		t.Errorf("PID = %d, want 12345", receivedReq.PID)
	}
	if !receivedReq.Add {
		t.Error("Add = false, want true")
	}

	if err := client.SetTargetPID(12345, false); err != nil {
		t.Fatalf("SetTargetPID(remove): %v", err)
	}
	if receivedReq.Add {
		t.Error("Add = true, want false for remove")
	}
}

func TestBPFClient_OnViolation(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			resp := BPFResponse{Type: BPFMsgOK}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	called := false
	client.OnViolation(func(v BPFViolation) {
		called = true
	})

	// Verify callback was set
	client.mu.Lock()
	if client.onViolation == nil {
		t.Error("onViolation should be set after OnViolation call")
	}
	client.mu.Unlock()

	// The callback won't be called in this test since the mock doesn't send violations,
	// but we verified it was stored. The BPF integration tests cover actual violations.
	_ = called
}

func TestBPFClient_SetTargetPID_ErrorResponse(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			resp := BPFResponse{Type: BPFMsgError, Error: "test pid error"}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	err = client.SetTargetPID(999, true)
	if err == nil {
		t.Error("expected error from error response")
	}
	if err != nil && !strings.Contains(err.Error(), "test pid error") {
		t.Errorf("expected 'test pid error' in error, got: %v", err)
	}
}

func TestBPFClient_ReadResponse_Disconnect(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		// Close immediately without writing any response
		conn.Close()
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}
	defer client.Close()

	// SyncRules will send a request and then try to read a response,
	// but the server closed the connection — should get a disconnect error
	err = client.SyncRules([]SecurityRule{
		&testRule{name: "test", paths: []string{"**/.env"}},
	})
	if err == nil {
		t.Error("expected error from disconnected server")
	}
}

func TestBPFClient_Close(t *testing.T) {
	sockPath, cleanup := mockBPFHelper(t, func(conn net.Conn) {
		defer conn.Close()
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			resp := BPFResponse{Type: BPFMsgOK}
			data, _ := json.Marshal(resp)
			conn.Write(append(data, '\n'))
		}
	})
	defer cleanup()

	client, err := NewBPFClient(sockPath)
	if err != nil {
		t.Fatalf("NewBPFClient: %v", err)
	}

	// Close should not error
	if err := client.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Double close should not error
	if err := client.Close(); err != nil {
		t.Errorf("double Close: %v", err)
	}

	// Operations after close should error
	err = client.SyncRules([]SecurityRule{
		&testRule{name: "test", paths: []string{"**/.env"}},
	})
	if err == nil {
		t.Error("expected error after close")
	}
}
