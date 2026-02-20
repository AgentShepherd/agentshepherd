//go:build notui

package banner

// PrintBanner prints a plain text banner when TUI is disabled.
func PrintBanner(version string) {
	PrintBannerPlain(version)
}

// PrintBannerCompact prints a compact one-line banner when TUI is disabled.
func PrintBannerCompact() {
	PrintBannerCompactPlain()
}

// RevealLines prints lines without animation when TUI is disabled.
func RevealLines(lines []string) {
	RevealLinesPlain(lines)
}
