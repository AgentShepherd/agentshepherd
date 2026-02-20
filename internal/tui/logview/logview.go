//go:build !notui

package logview

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

// fileCheckMsg triggers a file size check for follow mode.
type fileCheckMsg time.Time

// model is the bubbletea model for the log viewer.
type model struct {
	viewport viewport.Model
	logFile  string
	maxLines int
	follow   bool
	lastSize int64
	ready    bool
	width    int
	height   int
	shimmer  tui.ShimmerState // sweeps across BLOCKED lines when new blocks arrive
}

// View displays logs in a scrollable viewport with syntax highlighting.
// In follow mode, new content is appended and auto-scrolled.
// In plain mode, falls back to printing raw text.
func View(logFile string, lines int, follow bool) error {
	if tui.IsPlainMode() {
		return viewPlain(logFile, lines, follow)
	}

	shimCfg := tui.SubtleShimmerConfig()
	shimCfg.TickInterval = 30 * time.Millisecond // coarser for viewport redraws
	shimCfg.Factor = 0.6

	m := model{
		logFile:  logFile,
		maxLines: lines,
		follow:   follow,
		shimmer:  tui.NewShimmer(shimCfg),
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	var cmds []tea.Cmd
	if m.follow {
		cmds = append(cmds, checkFile())
	}
	return tea.Batch(cmds...)
}

func checkFile() tea.Cmd {
	return tea.Tick(200*time.Millisecond, func(t time.Time) tea.Msg {
		return fileCheckMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		headerHeight := 2
		footerHeight := 1
		verticalMarginHeight := headerHeight + footerHeight

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)

			// Load initial content
			content, err := readLastLines(m.logFile, m.maxLines)
			if err == nil {
				m.viewport.SetContent(highlightLogContent(content, m.shimmer))
				m.viewport.GotoBottom()
			}

			// Track file size for follow mode
			if info, err := os.Stat(m.logFile); err == nil {
				m.lastSize = info.Size()
			}

			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
		}

	case fileCheckMsg:
		if m.follow {
			newContent, newSize := checkForNewContent(m.logFile, m.lastSize)
			m.lastSize = newSize
			if newContent != "" {
				hasBlocked := strings.Contains(newContent, "BLOCKED")
				if hasBlocked {
					m.shimmer.Start(m.width)
					cmds = append(cmds, m.shimmer.Tick())
				}
				// Read the full file again and re-highlight
				content, err := readLastLines(m.logFile, m.maxLines)
				if err == nil {
					m.viewport.SetContent(highlightLogContent(content, m.shimmer))
					m.viewport.GotoBottom()
				}
			}
			cmds = append(cmds, checkFile())
		}

	case tui.ShimmerTickMsg:
		if !m.shimmer.Advance() {
			cmds = append(cmds, m.shimmer.Tick())
		}
		// Re-render with updated shimmer position
		content, err := readLastLines(m.logFile, m.maxLines)
		if err == nil {
			m.viewport.SetContent(highlightLogContent(content, m.shimmer))
		}

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func checkForNewContent(logFile string, lastSize int64) (string, int64) {
	info, err := os.Stat(logFile)
	if err != nil {
		return "", lastSize
	}
	currentSize := info.Size()
	if currentSize <= lastSize {
		if currentSize < lastSize {
			// File was truncated (log rotation) — reset
			return "", 0
		}
		return "", lastSize
	}

	// Read new bytes
	f, err := os.Open(logFile)
	if err != nil {
		return "", lastSize
	}
	defer f.Close()

	buf := make([]byte, currentSize-lastSize)
	_, err = f.ReadAt(buf, lastSize)
	if err != nil {
		return "", lastSize
	}
	return string(buf), currentSize
}

func (m model) View() string {
	if !m.ready {
		return "\n  Loading..."
	}

	// Header
	title := tui.BrandGradient("crust", true) + " " + tui.StyleTitle.Render("logs")
	mode := ""
	if m.follow {
		mode = tui.StyleSuccess.Render(" (following)")
	}
	header := title + mode + "\n"

	// Footer
	scrollPct := fmt.Sprintf("%3.f%%", m.viewport.ScrollPercent()*100)
	footer := lipgloss.NewStyle().Foreground(tui.ColorMuted).Render(
		"  ↑↓ scroll  q quit  " + scrollPct,
	)

	return header + m.viewport.View() + "\n" + footer
}

// highlightLogContent applies syntax highlighting to log lines.
// When shimmer is active, BLOCKED lines get a shimmer sweep effect.
func highlightLogContent(content string, shimmer tui.ShimmerState) string {
	lines := strings.Split(content, "\n")
	var highlighted []string

	for _, line := range lines {
		highlighted = append(highlighted, highlightLine(line, shimmer))
	}

	return strings.Join(highlighted, "\n")
}

// highlightLine applies color to a single log line based on level.
// When shimmer is active, BLOCKED lines get a shimmer sweep effect.
func highlightLine(line string, shimmer tui.ShimmerState) string {
	if line == "" {
		return line
	}

	// Detect log level and apply color
	switch {
	case strings.Contains(line, "[ERROR]"):
		return tui.StyleError.Render(line)
	case strings.Contains(line, "[WARN]"):
		return tui.StyleWarning.Render(line)
	case strings.Contains(line, "[DEBUG]"):
		return tui.StyleInfo.Render(line)
	case strings.Contains(line, "[TRACE]"):
		return lipgloss.NewStyle().Foreground(tui.ColorPrimary).Render(line)
	case strings.Contains(line, "BLOCKED"):
		if shimmer.Active {
			// Render each character with shimmer-adjusted red
			runes := []rune(line)
			var b strings.Builder
			for i, r := range runes {
				color := shimmer.ShimmerColor("#E05A3A", i)
				style := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
				b.WriteString(style.Render(string(r)))
			}
			return b.String()
		}
		return tui.StyleError.Render(line)
	default:
		// Dim the timestamp portion (HH:MM:SS)
		if len(line) > 8 && line[2] == ':' && line[5] == ':' {
			timestamp := tui.Faint(line[:8])
			return timestamp + line[8:]
		}
		return line
	}
}

// readLastLines reads the last N lines from a file.
func readLastLines(filePath string, n int) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot read log file: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	return strings.Join(lines, "\n"), nil
}

// viewPlain handles plain mode log viewing (delegates to tail).
func viewPlain(logFile string, lines int, follow bool) error {
	// In plain mode, just read and print the file
	content, err := readLastLines(logFile, lines)
	if err != nil {
		return err
	}
	fmt.Print(content)
	if follow {
		tui.PrintInfo("Follow mode requires an interactive terminal. Use: tail -f " + logFile)
	}
	return nil
}
