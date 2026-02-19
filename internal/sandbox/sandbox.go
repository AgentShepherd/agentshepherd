package sandbox

import (
	"errors"
	"runtime"
)

// Sandbox wraps command execution in an OS-level sandbox.
type Sandbox struct{}

// New creates a new Sandbox instance.
func New() *Sandbox {
	return &Sandbox{}
}

// Wrap executes a command inside the sandbox.
// Returns the exit code and any error.
func (s *Sandbox) Wrap(command []string) (int, error) {
	if len(command) == 0 {
		return 1, errors.New("no command specified")
	}

	return s.execute(command)
}

// IsSupported returns whether sandbox is supported on this platform.
// Checks that the helper binary exists — Rust validates
// kernel capabilities at runtime.
func IsSupported() bool {
	_, err := findBakelensSandbox()
	return err == nil
}

// helperPathOverride allows tests to override the helper binary path.
var helperPathOverride string

// Platform returns the sandbox platform name.
// Rust determines which enforcement mechanisms to use at runtime.
func Platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "bakelens-sandbox (macOS)"
	case "linux":
		return "bakelens-sandbox (Linux)"
	case "freebsd":
		return "bakelens-sandbox (FreeBSD)"
	case "windows":
		return "bakelens-sandbox (Windows)"
	default:
		return "not supported"
	}
}

// BuildPolicy builds a rules-mode JSON policy for the given command.
// Exported for callers that need the raw policy (e.g., dry-run preview).
func BuildPolicy(command []string) ([]byte, error) {
	return buildPolicy(command)
}
