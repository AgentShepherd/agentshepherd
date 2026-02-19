//go:build notui

package startup

import "fmt"

// RunStartupWithPort runs the startup prompts with a custom default proxy port (plain text, no TUI).
func RunStartupWithPort(defaultEndpoint string, defaultProxyPort int) (Config, error) {
	fmt.Println()
	fmt.Println("CRUST - Secure Gateway for AI Agents")
	fmt.Println()
	return runStartupReader(defaultEndpoint, defaultProxyPort)
}
