//go:build !notui

package progress

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
)

// stepDoneMsg signals a step completed.
type stepDoneMsg struct {
	err error
}

// settleMsg fires after all steps complete, giving the bar time to show 100%.
type settleMsg struct{}

// model drives the multi-step progress animation.
type model struct {
	steps    []Step
	current  int
	progress progress.Model
	spinner  spinner.Model
	done     bool
	settling bool // true while showing 100% bar before quitting
	err      error

	// completed steps' messages for display
	completed []string

	// shimmer sweep on "Done" text at 100%
	shimmer     tui.ShimmerState
	settleReady bool // true after settle timer fires

	mu *sync.Mutex
}

func newModel(steps []Step) model {
	p := progress.New(
		progress.WithGradient("#F5A623", "#E05A3A"),
		progress.WithWidth(30),
	)
	p.EmptyColor = "#3D3228"

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(tui.ColorPrimary)

	return model{
		steps:    steps,
		progress: p,
		spinner:  s,
		shimmer:  tui.NewShimmer(tui.SubtleShimmerConfig()),
		mu:       &sync.Mutex{},
	}
}

func (m model) Init() tea.Cmd {
	// Start spinner, run first step, and animate bar to initial position
	initialPct := 1.0 / float64(len(m.steps)+1)
	return tea.Batch(m.spinner.Tick, m.runCurrentStep(), m.progress.SetPercent(initialPct))
}

func (m model) runCurrentStep() tea.Cmd {
	if m.current >= len(m.steps) {
		return nil
	}
	step := m.steps[m.current]
	return func() tea.Msg {
		err := step.Fn()
		return stepDoneMsg{err: err}
	}
}

func settle() tea.Cmd {
	return tea.Tick(400*time.Millisecond, func(_ time.Time) tea.Msg {
		return settleMsg{}
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case stepDoneMsg:
		m.mu.Lock()
		if msg.err != nil {
			m.err = msg.err
			m.done = true
			m.mu.Unlock()
			return m, tea.Quit
		}

		// Record completed step
		step := m.steps[m.current]
		successMsg := step.SuccessMsg
		if successMsg == "" {
			successMsg = step.Label
		}
		m.completed = append(m.completed, successMsg)
		m.current++

		if m.current >= len(m.steps) {
			// All done — animate bar to 100%, start shimmer on "Done" label, and settle
			m.settling = true
			m.shimmer.Start(len([]rune("Done"))) // sweep across "Done" label only
			m.mu.Unlock()
			return m, tea.Batch(m.progress.SetPercent(1.0), settle(), m.shimmer.Tick())
		}
		m.mu.Unlock()

		// Animate bar to next position and start next step
		pct := float64(m.current+1) / float64(len(m.steps)+1)
		return m, tea.Batch(m.runCurrentStep(), m.progress.SetPercent(pct))

	case settleMsg:
		m.settleReady = true
		if !m.shimmer.Active {
			m.done = true
			return m, tea.Quit
		}
		return m, nil

	case tui.ShimmerTickMsg:
		if m.shimmer.Advance() {
			if m.settleReady {
				m.done = true
				return m, tea.Quit
			}
			return m, nil
		}
		return m, m.shimmer.Tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case progress.FrameMsg:
		pm, cmd := m.progress.Update(msg)
		m.progress = pm.(progress.Model)
		return m, cmd

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			m.done = true
			m.err = errors.New("interrupted")
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) View() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	prefix := tui.Prefix()
	var sb strings.Builder

	// Show completed steps
	for _, msg := range m.completed {
		icon := tui.StyleSuccess.Render(tui.IconCheck)
		fmt.Fprintf(&sb, "%s %s %s\n", prefix, icon, msg)
	}

	if m.done && !m.settling {
		if m.err != nil {
			icon := tui.StyleError.Render(tui.IconCross)
			fmt.Fprintf(&sb, "%s %s %s\n", prefix, icon, m.err.Error())
		}
		return sb.String()
	}

	// Settling: show the 100% bar with a "done" label + shimmer
	if m.settling {
		bar := m.progress.View()
		doneText := "Done"
		if m.shimmer.Active {
			runes := []rune(doneText)
			var db strings.Builder
			for i, r := range runes {
				color := m.shimmer.ShimmerColor("#A8B545", i)
				style := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true)
				db.WriteString(style.Render(string(r)))
			}
			doneText = db.String()
		} else {
			doneText = tui.StyleSuccess.Render(doneText)
		}
		fmt.Fprintf(&sb, "%s %s %s  %s\n",
			prefix,
			tui.StyleSuccess.Render(tui.IconCheck),
			doneText,
			bar,
		)
		return sb.String()
	}

	// Show current step with spinner + progress bar
	if m.current < len(m.steps) {
		bar := m.progress.View()
		step := m.steps[m.current]
		fmt.Fprintf(&sb, "%s %s %s  %s\n",
			prefix,
			m.spinner.View(),
			tui.StyleMuted.Render(step.Label+"..."),
			bar,
		)
	}

	return sb.String()
}

// RunSteps executes steps sequentially with an animated progress display.
// Each step advances the bar. On failure, shows error and stops.
// In plain mode, falls back to simple text output.
func RunSteps(steps []Step) error {
	if len(steps) == 0 {
		return nil
	}

	if tui.IsPlainMode() {
		return RunStepsPlain(steps)
	}

	m := newModel(steps)
	p := tea.NewProgram(m)
	finalModel, err := p.Run()
	if err != nil {
		// Bubbletea itself failed — run plain
		return RunStepsPlain(steps)
	}

	if fm, ok := finalModel.(model); ok && fm.err != nil {
		return fm.err
	}
	return nil
}
