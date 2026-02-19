//go:build !notui

package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ─── Shimmer animation ──────────────────────────────────────────────────────

// ShimmerTickMsg is sent on each animation frame.
// All components using shimmer handle this same message type.
type ShimmerTickMsg struct{}

// ShimmerConfig controls sweep behavior.
type ShimmerConfig struct {
	Radius       int           // highlight band half-width in character positions
	Step         int           // positions advanced per tick
	TickInterval time.Duration // time between ticks
	HighlightTo  string        // color to interpolate toward (e.g. "#FFFFFF")
	Factor       float64       // max interpolation strength at center (0.0–1.0)
}

// DefaultShimmerConfig returns settings tuned for the banner (bold sweep).
func DefaultShimmerConfig() ShimmerConfig {
	return ShimmerConfig{
		Radius:       4,
		Step:         2,
		TickInterval: 15 * time.Millisecond,
		HighlightTo:  "#FFF5E0", // warm white
		Factor:       0.9,
	}
}

// SubtleShimmerConfig returns softer settings for non-banner components.
// Uses Step=1 and 50ms ticks so that each shimmer position persists for at least
// one GIF frame (40ms at 25fps), making the sweep clearly visible in recordings.
// The highlight color is warm cream (#FFE4A0) to match the amber/gold palette.
func SubtleShimmerConfig() ShimmerConfig {
	return ShimmerConfig{
		Radius:       3,
		Step:         1,
		TickInterval: 50 * time.Millisecond,
		HighlightTo:  "#FFE4A0", // warm cream
		Factor:       0.95,
	}
}

// ShimmerState tracks a single left-to-right sweep animation.
type ShimmerState struct {
	Config ShimmerConfig
	Pos    int  // current center position of the highlight band
	Width  int  // total distance to sweep (content width)
	Active bool // true while sweep is in progress
}

// NewShimmer creates a ShimmerState with the given config.
func NewShimmer(cfg ShimmerConfig) ShimmerState {
	return ShimmerState{Config: cfg}
}

// Start begins a sweep across the given width.
// If already active, resets and restarts.
func (s *ShimmerState) Start(width int) {
	s.Width = width
	s.Pos = -s.Config.Radius
	s.Active = true
}

// Advance moves the highlight band forward by Config.Step positions.
// Returns true when the sweep is complete.
func (s *ShimmerState) Advance() bool {
	if !s.Active {
		return true
	}
	s.Pos += s.Config.Step
	if s.Pos > s.Width+s.Config.Radius {
		s.Active = false
		return true
	}
	return false
}

// ShimmerColor returns the shimmer-adjusted color for a character at charPos.
// Uses smoothstep falloff for natural 3-stop gradient (transparent → bright → transparent).
func (s *ShimmerState) ShimmerColor(base string, charPos int) string {
	if !s.Active {
		return base
	}
	dist := charPos - s.Pos
	if dist < 0 {
		dist = -dist
	}
	if dist > s.Config.Radius {
		return base
	}
	// Smoothstep: t² × (3 − 2t) produces softer edges than linear falloff
	t := 1.0 - float64(dist)/float64(s.Config.Radius+1)
	t = t * t * (3 - 2*t)
	return InterpolateColor(base, s.Config.HighlightTo, t*s.Config.Factor)
}

// Tick returns a tea.Cmd that fires a ShimmerTickMsg after the configured interval.
func (s *ShimmerState) Tick() tea.Cmd {
	return tea.Tick(s.Config.TickInterval, func(_ time.Time) tea.Msg {
		return ShimmerTickMsg{}
	})
}
