package tui

import (
	"fmt"
	"os"
)

// PrintSuccess prints a styled success message with the [crust] prefix.
func PrintSuccess(msg string) {
	if IsPlainMode() {
		fmt.Printf("[crust] OK: %s\n", msg)
		return
	}
	fmt.Printf("%s %s %s\n", Prefix(), StyleSuccess.Render(IconCheck), msg)
}

// PrintError prints a styled error message with the [crust] prefix.
func PrintError(msg string) {
	if IsPlainMode() {
		fmt.Fprintf(os.Stderr, "[crust] ERROR: %s\n", msg)
		return
	}
	fmt.Fprintf(os.Stderr, "%s %s %s\n", Prefix(), StyleError.Render(IconCross), msg)
}

// PrintWarning prints a styled warning message with the [crust] prefix.
func PrintWarning(msg string) {
	if IsPlainMode() {
		fmt.Printf("[crust] WARNING: %s\n", msg)
		return
	}
	fmt.Printf("%s %s %s\n", Prefix(), StyleWarning.Render(IconWarning), msg)
}

// PrintInfo prints a styled info message with the [crust] prefix.
func PrintInfo(msg string) {
	if IsPlainMode() {
		fmt.Printf("[crust] %s\n", msg)
		return
	}
	fmt.Printf("%s %s %s\n", Prefix(), StyleInfo.Render(IconInfo), msg)
}
