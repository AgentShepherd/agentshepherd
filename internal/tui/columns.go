package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// AlignColumns renders rows of two-column data with the left column
// padded to the widest entry, producing aligned output.
// Each row is [left, right]. styleLeft and styleRight are applied to
// the raw text of each column. indent is prepended to every line.
// gap is the number of spaces between columns.
func AlignColumns(rows [][2]string, indent string, gap int, styleLeft, styleRight lipgloss.Style) string {
	if len(rows) == 0 {
		return ""
	}

	// Find the widest left column (using visual width, not byte length)
	maxWidth := 0
	for _, row := range rows {
		w := lipgloss.Width(row[0])
		if w > maxWidth {
			maxWidth = w
		}
	}

	gapStr := strings.Repeat(" ", gap)
	var sb strings.Builder
	for _, row := range rows {
		left := styleLeft.Render(row[0])
		// Pad the styled left column to align right columns.
		// lipgloss.Width handles ANSI escape codes correctly.
		pad := maxWidth - lipgloss.Width(row[0])
		right := styleRight.Render(row[1])
		sb.WriteString(indent)
		sb.WriteString(left)
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(gapStr)
		sb.WriteString(right)
		sb.WriteByte('\n')
	}
	return sb.String()
}
