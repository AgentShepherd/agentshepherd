//go:build notui

package progress

// RunSteps executes steps sequentially with simple text output.
func RunSteps(steps []Step) error {
	return RunStepsPlain(steps)
}
