//go:build notui

package logview

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/BakeLens/crust/internal/tui"
)

// View displays logs using system tail (no TUI in notui build).
func View(logFile string, lines int, follow bool) error {
	if follow {
		tui.PrintInfo(fmt.Sprintf("Following %s (Ctrl+C to stop)...", logFile))
		fmt.Println()
		cmd := exec.CommandContext(context.Background(), "tail", "-f", logFile) //nolint:gosec
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	cmd := exec.CommandContext(context.Background(), "tail", "-n", strconv.Itoa(lines), logFile) //nolint:gosec
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		tui.PrintError("No logs found. Is crust running?")
		return err
	}
	return nil
}
