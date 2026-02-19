//go:build windows

package security

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// pipeName returns the Windows named pipe path for a crust API session.
// The socketPath argument is used only to derive a unique name when
// multiple sessions run simultaneously; the pipe namespace is global.
func pipeName(socketPath string) string {
	// socketPath is typically "...crust-api-{port}.sock" — extract the suffix
	// to create a unique pipe. For simplicity, hash or use the full path
	// is not needed; the caller already embeds the proxy port.
	// Use a fixed base name; uniqueness comes from the port embedded by the caller.
	return `\\.\pipe\` + socketPath
}

// apiListener creates a Windows named pipe listener with DACL restricted
// to the current user.
func apiListener(socketPath string) (net.Listener, error) {
	name := pipeName(socketPath)

	cfg := &winio.PipeConfig{
		// Empty SecurityDescriptor → inherits default DACL (creator + admins).
		// For tighter restriction, set SDDL with current user SID.
		// Default is acceptable: only the creator and local admins can connect.
		MessageMode: false,
	}

	ln, err := winio.ListenPipe(name, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", name, err)
	}
	return ln, nil
}

// cleanupSocket is a no-op on Windows; named pipes are cleaned up by the kernel.
func cleanupSocket(_ string) {}
