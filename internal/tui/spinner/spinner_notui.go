//go:build notui

package spinner

// RunWithSpinner runs fn directly without animation when TUI is disabled.
func RunWithSpinner(message string, successMsg string, fn func() error) error {
	return RunPlain(message, successMsg, fn)
}
