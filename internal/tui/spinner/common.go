package spinner

import (
	"github.com/BakeLens/crust/internal/tui"
)

// RunPlain runs fn with simple text output (no animation).
func RunPlain(message string, successMsg string, fn func() error) error {
	tui.PrintInfo(message + "...")
	if err := fn(); err != nil {
		tui.PrintError(err.Error())
		return err
	}
	tui.PrintSuccess(successMsg)
	return nil
}
