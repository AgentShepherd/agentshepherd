//go:build !notui

package banner

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/BakeLens/crust/internal/tui"
)

// ASCII art lines for the CRUST logo.
// Uses solid block characters (█ ▀ ▄) for a filled pixel-art style.
var logoLines = []string{
	`▄███▄  ████▄  █   █  ▄███▄  █████`,
	`█      █   █  █   █  █        █`,
	`█      ████▀  █   █  ▀███▄    █`,
	`█      █  █   █   █      █    █`,
	`▀███▀  █   █  ▀███▀  ▀███▀    █`,
}

// logoWidth is the rune count of the widest logo line (for consistent gradient mapping).
var logoWidth int

func init() {
	for _, line := range logoLines {
		if w := utf8.RuneCountInString(line); w > logoWidth {
			logoWidth = w
		}
	}
}

// gradientHex holds the expanded per-character gradient colors (gold → amber → bright rust).
var gradientHex = []string{
	"#FFE4A0", "#FFD98C", "#FFCE78", "#FFC364", "#FFB850",
	"#FFAD3C", "#FFA228", "#FF9714", "#FF8C00", "#F58400",
	"#EB7C00", "#E17400", "#F5A623", "#F59B1A", "#F59011",
	"#F58508", "#F57A00", "#EE7235", "#E76A4A", "#E0625F",
	"#E8734A", "#E56B42", "#E2633A", "#DF5B32", "#DC532A",
}

// renderGradientLine colors each visible rune using a column-aligned gradient.
func renderGradientLine(line string, bold bool) string {
	runes := []rune(line)
	if len(runes) == 0 {
		return ""
	}
	width := logoWidth
	if width <= 1 {
		width = len(runes)
	}

	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		idx := i * (len(gradientHex) - 1) / max(width-1, 1)
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradientHex[idx]))
		if bold {
			style = style.Bold(true)
		}
		b.WriteString(style.Render(string(r)))
	}
	return b.String()
}

// renderGradientLineShimmer renders a gradient line with a bright shimmer sweep.
func renderGradientLineShimmer(line string, bold bool, shimmer tui.ShimmerState) string {
	runes := []rune(line)
	if len(runes) == 0 {
		return ""
	}
	width := logoWidth
	if width <= 1 {
		width = len(runes)
	}

	var b strings.Builder
	for i, r := range runes {
		if r == ' ' {
			b.WriteRune(r)
			continue
		}
		idx := i * (len(gradientHex) - 1) / max(width-1, 1)
		color := shimmer.ShimmerColor(gradientHex[idx], i)

		style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
		if bold {
			style = style.Bold(true)
		}
		b.WriteString(style.Render(string(r)))
	}
	return b.String()
}

// renderTagline builds the styled version + subtitle line.
func renderTagline(version string) string {
	indent := "       "
	if version != "" {
		return indent + tui.StyleMuted.Render("v"+version) + "  " + tui.StyleSubtitle.Render("Secure Gateway for AI Agents")
	}
	return indent + tui.StyleSubtitle.Render("Secure Gateway for AI Agents")
}

// renderBannerContent builds the full static banner content (gradient, no shimmer).
func renderBannerContent(version string) string {
	var coloredLines []string
	for _, line := range logoLines {
		coloredLines = append(coloredLines, renderGradientLine(line, true))
	}
	inner := strings.Join(coloredLines, "\n")
	inner += "\n\n" + renderTagline(version)
	return inner
}

// renderBannerContentWithShimmer builds banner content with a shimmer overlay on the logo.
func renderBannerContentWithShimmer(version string, shimmer tui.ShimmerState) string {
	var coloredLines []string
	for _, line := range logoLines {
		coloredLines = append(coloredLines, renderGradientLineShimmer(line, true, shimmer))
	}
	inner := strings.Join(coloredLines, "\n")
	inner += "\n\n" + renderTagline(version)
	return inner
}

// ─── Animated banner (bubbletea) ────────────────────────────────────────────

// Animation phases.
const (
	phaseReveal  = 0
	phaseShimmer = 1
)

type bannerRevealMsg struct{}

type bannerModel struct {
	version   string
	logoChars int // total visible runes across all logo lines
	revealed  int // visible chars revealed so far
	phase     int
	shimmer   tui.ShimmerState
	done      bool
}

func newBannerModel(version string) bannerModel {
	total := 0
	for _, line := range logoLines {
		total += utf8.RuneCountInString(line)
	}
	return bannerModel{
		version:   version,
		logoChars: total,
		shimmer:   tui.NewShimmer(tui.DefaultShimmerConfig()),
	}
}

func (m bannerModel) Init() tea.Cmd {
	return revealTick()
}

func revealTick() tea.Cmd {
	return tea.Tick(12*time.Millisecond, func(_ time.Time) tea.Msg {
		return bannerRevealMsg{}
	})
}

func (m bannerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg.(type) {
	case bannerRevealMsg:
		m.revealed += 6
		if m.revealed >= m.logoChars {
			m.revealed = m.logoChars
			m.phase = phaseShimmer
			m.shimmer.Start(logoWidth)
			return m, m.shimmer.Tick()
		}
		return m, revealTick()
	case tui.ShimmerTickMsg:
		if m.shimmer.Advance() {
			m.done = true
			return m, tea.Quit
		}
		return m, m.shimmer.Tick()
	case tea.KeyMsg:
		// Any key press skips animation
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m bannerModel) View() string {
	if m.done {
		return tui.StyleBox.Render(renderBannerContent(m.version)) + "\n"
	}

	if m.phase == phaseShimmer {
		return tui.StyleBox.Render(renderBannerContentWithShimmer(m.version, m.shimmer)) + "\n"
	}

	// Reveal phase: render visible chars with gradient, pad unrevealed with spaces.
	remaining := m.revealed
	var renderedLines []string

	for _, rawLine := range logoLines {
		runes := []rune(rawLine)
		// Pad to logoWidth for stable box dimensions during animation
		for len(runes) < logoWidth {
			runes = append(runes, ' ')
		}

		var b strings.Builder
		for i, r := range runes {
			if remaining > 0 {
				if r == ' ' {
					b.WriteRune(' ')
				} else {
					idx := i * (len(gradientHex) - 1) / max(logoWidth-1, 1)
					style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradientHex[idx])).Bold(true)
					b.WriteString(style.Render(string(r)))
				}
				remaining--
			} else {
				b.WriteRune(' ')
			}
		}
		renderedLines = append(renderedLines, b.String())
	}

	inner := strings.Join(renderedLines, "\n")
	// Tagline appears only when logo is fully revealed (transition to shimmer shows it)
	inner += "\n\n"
	return tui.StyleBox.Render(inner) + "\n"
}

// PrintBanner renders the gradient CRUST banner in a bordered box.
// If interactive, plays a reveal animation followed by a shimmer sweep.
// In plain mode, prints a simple text banner with no colors or boxes.
func PrintBanner(version string) {
	if tui.IsPlainMode() {
		PrintBannerPlain(version)
		return
	}

	// Try animated version if we have a TTY
	if isTerminal() {
		m := newBannerModel(version)
		p := tea.NewProgram(m, tea.WithOutput(os.Stderr))
		if _, err := p.Run(); err == nil {
			return
		}
		// Fall through to static on error
	}

	// Static fallback
	box := tui.StyleBox.Render(renderBannerContent(version))
	fmt.Println(box)
}

// PrintBannerCompact renders a compact one-line banner for smaller contexts.
func PrintBannerCompact() {
	if tui.IsPlainMode() {
		PrintBannerCompactPlain()
		return
	}
	name := tui.BrandGradient("Crust", true)
	desc := tui.StyleMuted.Render("Secure Gateway for AI Agents")
	fmt.Printf("  %s  %s\n", name, desc)
}

// isTerminal checks if stderr is a terminal (for animation support).
// Uses golang.org/x/term for portable detection across Linux, macOS, and Windows.
func isTerminal() bool {
	return term.IsTerminal(int(os.Stderr.Fd())) //nolint:gosec // Fd() fits in int on all supported platforms
}

// RevealLines prints styled lines one at a time with a cascading reveal effect.
// Each line appears after a brief delay, giving a "typing" feel to output.
// In plain mode or non-TTY, all lines print instantly.
func RevealLines(lines []string) {
	if tui.IsPlainMode() || !isTerminal() {
		RevealLinesPlain(lines)
		return
	}
	for _, line := range lines {
		fmt.Println(line)
		time.Sleep(40 * time.Millisecond)
	}
}
