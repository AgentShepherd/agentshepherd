//go:build !darwin && !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// execute panics on unsupported platforms.
// AgentShepherd requires Linux 5.13+ (Landlock) or macOS (sandbox-exec).
func (s *Sandbox) execute(profilePath string, command []string) (int, error) {
	panic(fmt.Sprintf("FATAL: Sandbox not supported on %s. AgentShepherd requires Linux 5.13+ or macOS", runtime.GOOS))
}

// isLandlockSupported returns false on unsupported platforms.
func isLandlockSupported() bool {
	return false
}

// detectLandlockABI returns 0 on unsupported platforms.
func detectLandlockABI() int {
	return 0
}
