package progress

import (
	"github.com/BakeLens/crust/internal/tui"
)

// Step represents a single step in a multi-step operation.
type Step struct {
	Label      string       // displayed while running
	SuccessMsg string       // displayed on success
	Fn         func() error // the work to perform
}

// RunStepsPlain executes steps sequentially with simple text output (no animation).
func RunStepsPlain(steps []Step) error {
	for _, step := range steps {
		tui.PrintInfo(step.Label + "...")
		if err := step.Fn(); err != nil {
			tui.PrintError(err.Error())
			return err
		}
		msg := step.SuccessMsg
		if msg == "" {
			msg = step.Label
		}
		tui.PrintSuccess(msg)
	}
	return nil
}
