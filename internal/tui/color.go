package tui

import (
	"fmt"
	"strings"
)

// ─── Color utilities ─────────────────────────────────────────────────────────

// HexToRGB parses a "#RRGGBB" hex string into its components.
func HexToRGB(hex string) (uint8, uint8, uint8) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 0, 0, 0
	}
	var r, g, b uint8
	fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b) //nolint:errcheck // invalid hex returns 0,0,0
	return r, g, b
}

// InterpolateColor linearly interpolates between two hex colors.
// t ranges from 0.0 (from) to 1.0 (to).
func InterpolateColor(from, to string, t float64) string {
	r1, g1, b1 := HexToRGB(from)
	r2, g2, b2 := HexToRGB(to)
	r := uint8(float64(r1) + t*(float64(r2)-float64(r1)))
	g := uint8(float64(g1) + t*(float64(g2)-float64(g1)))
	b := uint8(float64(b1) + t*(float64(b2)-float64(b1)))
	return fmt.Sprintf("#%02X%02X%02X", r, g, b)
}

// GenerateGradient creates n hex colors interpolated between two endpoints.
func GenerateGradient(from, to string, n int) []string {
	if n <= 0 {
		return []string{}
	}
	if n == 1 {
		return []string{from}
	}
	colors := make([]string, n)
	for i := range n {
		t := float64(i) / float64(n-1)
		colors[i] = InterpolateColor(from, to, t)
	}
	return colors
}
