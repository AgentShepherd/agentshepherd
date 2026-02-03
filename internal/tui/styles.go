//go:build tui

package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	primaryColor = lipgloss.Color("#7C3AED") // Purple
	mutedColor   = lipgloss.Color("#6B7280") // Gray
	warningColor = lipgloss.Color("#F59E0B") // Amber/Yellow
	successColor = lipgloss.Color("#10B981") // Green

	// Title style
	titleStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	// Subtitle style
	subtitleStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	// Label style
	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#D1D5DB")).
			Bold(true)

	// Input style (focused)
	focusedInputStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(primaryColor).
				Padding(0, 1).
				Width(44)

	// Input style (blurred)
	blurredInputStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(mutedColor).
				Padding(0, 1).
				Width(44)

	// Button style (focused)
	focusedButtonStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#FFFFFF")).
				Background(primaryColor).
				Padding(0, 2).
				Bold(true).
				MarginTop(1)

	// Button style (blurred)
	blurredButtonStyle = lipgloss.NewStyle().
				Foreground(mutedColor).
				Background(lipgloss.Color("#374151")).
				Padding(0, 2).
				MarginTop(1)

	// Help style
	helpStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(1)

	// Container style
	containerStyle = lipgloss.NewStyle().
			Padding(1, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151"))

	// Hint style (for optional fields)
	hintStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	// Tab styles
	tabActiveStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primaryColor).
			Padding(0, 2).
			Bold(true)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(mutedColor).
				Background(lipgloss.Color("#374151")).
				Padding(0, 2)

	// Toggle styles
	toggleOnStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true)

	toggleOffStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	// Warning style
	warningStyle = lipgloss.NewStyle().
			Foreground(warningColor).
			Italic(true)
)
