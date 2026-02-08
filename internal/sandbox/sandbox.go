package sandbox

import (
	"fmt"
	"runtime"
)

// Sandbox wraps command execution in an OS-level sandbox.
type Sandbox struct {
	mapper *Mapper
}

// New creates a new Sandbox instance.
func New(mapper *Mapper) *Sandbox {
	return &Sandbox{
		mapper: mapper,
	}
}

// Wrap executes a command inside the sandbox.
// Returns the exit code and any error.
func (s *Sandbox) Wrap(command []string) (int, error) {
	if len(command) == 0 {
		return 1, fmt.Errorf("no command specified")
	}

	return s.execute(command)
}

// IsHelperInstalled returns true if the bakelens-sandbox binary is found.
func IsHelperInstalled() bool {
	_, err := findBakelensSandbox()
	return err == nil
}

// IsSupported returns whether sandbox is supported on this platform.
func IsSupported() bool {
	switch runtime.GOOS {
	case "darwin":
		return true
	case "linux":
		return isLandlockSupported()
	default:
		return false
	}
}

// Platform returns the sandbox mechanism for the current platform.
func Platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "bakelens-sandbox (Seatbelt)"
	case "linux":
		abi := detectLandlockABI()
		if abi >= 3 {
			return fmt.Sprintf("Landlock ABI v%d (files + network)", abi)
		} else if abi >= 1 {
			return fmt.Sprintf("Landlock ABI v%d (files only)", abi)
		}
		return "Landlock not available"
	default:
		return "not supported"
	}
}
