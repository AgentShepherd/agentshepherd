//go:build !tui

package tui

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"
)

// StartupConfig holds the configuration collected from the startup prompts
type StartupConfig struct {
	// Basic
	EndpointURL   string
	APIKey        string
	EncryptionKey string
	// Advanced - Telemetry
	TelemetryEnabled bool
	RetentionDays    int
	// Advanced - Rules
	DisableBuiltinRules bool
	// Advanced - Ports
	ProxyPort int
	APIPort   int
	// State
	Canceled bool
}

// Validate validates the startup configuration
func (c *StartupConfig) Validate() error {
	if c.EndpointURL == "" {
		return fmt.Errorf("endpoint URL is required")
	}
	if _, err := url.Parse(c.EndpointURL); err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}
	if c.APIKey == "" {
		return fmt.Errorf("API key is required")
	}
	if c.EncryptionKey != "" && len(c.EncryptionKey) < 16 {
		return fmt.Errorf("encryption key must be at least 16 characters")
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return fmt.Errorf("proxy port must be between 1 and 65535")
	}
	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("API port must be between 1 and 65535")
	}
	if c.RetentionDays < 0 || c.RetentionDays > 36500 {
		return fmt.Errorf("retention days must be between 0 and 36500")
	}
	return nil
}

// ValidationErrors returns human-readable validation errors
func (c *StartupConfig) ValidationErrors() []string {
	err := c.Validate()
	if err == nil {
		return nil
	}
	return []string{err.Error()}
}

// Default ports (should match config.DefaultConfig)
const (
	DefaultProxyPort = 9090
	DefaultAPIPort   = 9091
)

// RunStartup runs the startup prompts and returns the configuration
func RunStartup(defaultEndpoint string) (StartupConfig, error) {
	return RunStartupWithPorts(defaultEndpoint, DefaultProxyPort, DefaultAPIPort)
}

// RunStartupWithPorts runs the startup prompts with custom default ports
func RunStartupWithPorts(defaultEndpoint string, defaultProxyPort, defaultAPIPort int) (StartupConfig, error) {
	reader := bufio.NewReader(os.Stdin)
	config := StartupConfig{
		ProxyPort:     defaultProxyPort,
		APIPort:       defaultAPIPort,
		RetentionDays: 7,
	}

	fmt.Println()
	fmt.Println("AgentShepherd - Agent Secure Gateway")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println()

	// Endpoint URL
	fmt.Printf("Endpoint URL [%s]: ", defaultEndpoint)
	endpoint, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("failed to read endpoint: %w", err)
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	config.EndpointURL = endpoint

	// API Key (hidden input)
	fmt.Print("API Key: ")
	apiKey, err := readPassword()
	if err != nil {
		return config, fmt.Errorf("failed to read API key: %w", err)
	}
	config.APIKey = apiKey
	fmt.Println()

	// DB Encryption Key (optional, hidden input)
	fmt.Print("DB Encryption Key (optional, press Enter to skip): ")
	dbKey, err := readPassword()
	if err != nil {
		return config, fmt.Errorf("failed to read DB key: %w", err)
	}
	config.EncryptionKey = dbKey
	fmt.Println()

	// Advanced options prompt
	fmt.Print("\nConfigure advanced options? [y/N]: ")
	advAnswer, _ := reader.ReadString('\n')
	advAnswer = strings.TrimSpace(strings.ToLower(advAnswer))

	if advAnswer == "y" || advAnswer == "yes" {
		fmt.Println()

		// Telemetry
		fmt.Print("Enable telemetry? [y/N]: ")
		telAnswer, _ := reader.ReadString('\n')
		telAnswer = strings.TrimSpace(strings.ToLower(telAnswer))
		config.TelemetryEnabled = telAnswer == "y" || telAnswer == "yes"

		// Retention days
		fmt.Printf("Retention days (0=forever) [%d]: ", config.RetentionDays)
		retStr, _ := reader.ReadString('\n')
		retStr = strings.TrimSpace(retStr)
		if retStr != "" {
			if days, err := strconv.Atoi(retStr); err == nil && days >= 0 && days <= 36500 {
				config.RetentionDays = days
			}
		}

		// Builtin rules
		fmt.Print("Disable builtin rules? [y/N]: ")
		rulesAnswer, _ := reader.ReadString('\n')
		rulesAnswer = strings.TrimSpace(strings.ToLower(rulesAnswer))
		config.DisableBuiltinRules = rulesAnswer == "y" || rulesAnswer == "yes"

		// Proxy port
		fmt.Printf("Proxy port [%d]: ", config.ProxyPort)
		proxyStr, _ := reader.ReadString('\n')
		proxyStr = strings.TrimSpace(proxyStr)
		if proxyStr != "" {
			if port, err := strconv.Atoi(proxyStr); err == nil && port >= 1 && port <= 65535 {
				config.ProxyPort = port
			}
		}

		// API port
		fmt.Printf("API port [%d]: ", config.APIPort)
		apiPortStr, _ := reader.ReadString('\n')
		apiPortStr = strings.TrimSpace(apiPortStr)
		if apiPortStr != "" {
			if port, err := strconv.Atoi(apiPortStr); err == nil && port >= 1 && port <= 65535 {
				config.APIPort = port
			}
		}
	}

	fmt.Println()

	return config, nil
}

// readPassword reads a password from the terminal without echoing
func readPassword() (string, error) {
	// Try to read without echo if we have a terminal
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(password), nil
	}

	// Fallback for non-terminal (piped input)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}
