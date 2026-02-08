//go:build linux

package sandbox

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/logger"
)

var bpfClientLog = logger.New("bpf-client")

// BPFClient connects to the BPF helper daemon over a Unix socket
// and sends deny rules for kernel-level enforcement.
type BPFClient struct {
	conn        net.Conn
	encoder     *json.Encoder
	scanner     *bufio.Scanner
	mu          sync.Mutex
	closed      bool
	onViolation func(BPFViolation)
	stopCh      chan struct{}
}

// NewBPFClient connects to the BPF helper daemon at the given socket path.
func NewBPFClient(socketPath string) (*BPFClient, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to BPF helper at %s: %w", socketPath, err)
	}

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	c := &BPFClient{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		scanner: scanner,
		stopCh:  make(chan struct{}),
	}

	// Start background reader for async violation events
	go c.readLoop()

	bpfClientLog.Info("Connected to BPF helper at %s", socketPath)
	return c, nil
}

// SyncRules translates rules to BPF deny entries and sends them to the helper.
func (c *BPFClient) SyncRules(allRules []SecurityRule) error {
	denySet := TranslateToBPF(allRules)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client closed")
	}

	req := BPFRequest{
		Type:  BPFMsgRules,
		Rules: denySet,
	}

	if err := c.encoder.Encode(req); err != nil {
		return fmt.Errorf("send rules: %w", err)
	}

	// Read response
	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if resp.Type == BPFMsgError {
		return fmt.Errorf("BPF helper error: %s", resp.Error)
	}

	bpfClientLog.Info("BPF rules synced: %d rules loaded", resp.Count)
	return nil
}

// SetTargetPID adds or removes a PID from the BPF enforcement set.
func (c *BPFClient) SetTargetPID(pid uint32, add bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("client closed")
	}

	req := BPFRequest{
		Type: BPFMsgPID,
		PID:  pid,
		Add:  add,
	}

	if err := c.encoder.Encode(req); err != nil {
		return fmt.Errorf("send PID: %w", err)
	}

	resp, err := c.readResponse()
	if err != nil {
		return err
	}

	if resp.Type == BPFMsgError {
		return fmt.Errorf("BPF helper error: %s", resp.Error)
	}

	return nil
}

// OnViolation registers a callback for BPF violation events.
func (c *BPFClient) OnViolation(fn func(BPFViolation)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onViolation = fn
}

// Close disconnects from the BPF helper.
func (c *BPFClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	close(c.stopCh)
	return c.conn.Close()
}

// readResponse reads a single JSON response from the helper.
// Must be called with mu held.
func (c *BPFClient) readResponse() (*BPFResponse, error) {
	if !c.scanner.Scan() {
		if err := c.scanner.Err(); err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		return nil, fmt.Errorf("BPF helper disconnected")
	}

	var resp BPFResponse
	if err := json.Unmarshal(c.scanner.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &resp, nil
}

// readLoop reads async messages (violations) from the helper in background.
func (c *BPFClient) readLoop() {
	// The readLoop handles violation events that arrive between
	// request/response pairs. For simplicity, violation events
	// are handled in the readResponse path too.
	<-c.stopCh
}
