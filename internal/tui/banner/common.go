package banner

import "fmt"

// PrintBannerPlain prints a plain text banner (no colors, no box).
func PrintBannerPlain(version string) {
	if version != "" {
		fmt.Printf("CRUST v%s - Secure Gateway for AI Agents\n", version)
	} else {
		fmt.Println("CRUST - Secure Gateway for AI Agents")
	}
}

// PrintBannerCompactPlain prints a compact one-line banner (no colors).
func PrintBannerCompactPlain() {
	fmt.Println("  Crust - Secure Gateway for AI Agents")
}

// RevealLinesPlain prints lines without animation.
func RevealLinesPlain(lines []string) {
	for _, line := range lines {
		fmt.Println(line)
	}
}
