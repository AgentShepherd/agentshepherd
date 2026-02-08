//go:build !darwin && !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// findBakelensSandbox is not available on unsupported platforms.
func findBakelensSandbox() (string, error) {
	return "", fmt.Errorf("bakelens-sandbox not available on %s", runtime.GOOS)
}

// execute panics on unsupported platforms.
// Crust requires Linux 5.13+ (Landlock) or macOS (Seatbelt).
func (s *Sandbox) execute(command []string) (int, error) {
	panic(fmt.Sprintf("FATAL: Sandbox not supported on %s. Crust requires Linux 5.13+ or macOS", runtime.GOOS))
}

// isLandlockSupported returns false on unsupported platforms.
func isLandlockSupported() bool {
	return false
}

// detectLandlockABI returns 0 on unsupported platforms.
func detectLandlockABI() int {
	return 0
}
