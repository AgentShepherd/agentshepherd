//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// BPFClient is a no-op stub on non-Linux platforms.
// macOS uses Seatbelt for deny rules; eBPF LSM is Linux-only.
type BPFClient struct{}

// NewBPFClient returns an error on non-Linux platforms.
func NewBPFClient(_ string) (*BPFClient, error) {
	return nil, fmt.Errorf("BPF LSM not supported on %s", runtime.GOOS)
}

// SyncRules is a no-op on non-Linux platforms.
func (c *BPFClient) SyncRules(_ []SecurityRule) error { return nil }

// SetTargetPID is a no-op on non-Linux platforms.
func (c *BPFClient) SetTargetPID(_ uint32, _ bool) error { return nil }

// OnViolation is a no-op on non-Linux platforms.
func (c *BPFClient) OnViolation(_ func(BPFViolation)) {}

// Close is a no-op on non-Linux platforms.
func (c *BPFClient) Close() error { return nil }
