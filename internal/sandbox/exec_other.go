//go:build !unix && !windows

package sandbox

import (
	"fmt"
	"runtime"
)

// findBakelensSandbox is not available on unsupported platforms.
func findBakelensSandbox() (string, error) {
	return "", fmt.Errorf("bakelens-sandbox not available on %s", runtime.GOOS)
}
