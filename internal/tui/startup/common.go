package startup

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/BakeLens/crust/internal/tui"
)

// Config holds the configuration collected from the startup prompts
type Config struct {
	// Mode
	AutoMode bool // auto mode: resolve provider from model name (per-provider keys or client auth)
	// Basic
	EndpointURL   string
	APIKey        string //nolint:gosec // not a hardcoded credential, user-provided config field
	EncryptionKey string
	// Advanced - Telemetry
	TelemetryEnabled bool
	RetentionDays    int
	// Advanced - Rules
	DisableBuiltinRules bool
	// Advanced - Ports
	ProxyPort int
	// State
	Canceled bool
}

// Validate validates the startup configuration
func (c *Config) Validate() error {
	if !c.AutoMode {
		if c.EndpointURL == "" {
			return errors.New("endpoint URL is required")
		}
		if _, err := url.Parse(c.EndpointURL); err != nil {
			return fmt.Errorf("invalid endpoint URL: %w", err)
		}
		if c.APIKey == "" {
			return errors.New("API key is required")
		}
	}
	if c.EncryptionKey != "" && len(c.EncryptionKey) < 16 {
		return errors.New("encryption key must be at least 16 characters")
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return errors.New("proxy port must be between 1 and 65535")
	}
	if c.RetentionDays < 0 || c.RetentionDays > 36500 {
		return errors.New("retention days must be between 0 and 36500")
	}
	return nil
}

// ValidationErrors returns human-readable validation errors
func (c *Config) ValidationErrors() []string {
	err := c.Validate()
	if err == nil {
		return nil
	}
	return []string{err.Error()}
}

// DefaultProxyPort should match config.DefaultConfig
const DefaultProxyPort = 9090

// RunStartup runs the startup prompts and returns the configuration
func RunStartup(defaultEndpoint string) (Config, error) {
	return RunStartupWithPort(defaultEndpoint, DefaultProxyPort)
}

// readPassword reads a password from the terminal without echoing.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // Fd() fits in int on all supported platforms
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

// runStartupReader runs plain text prompts using bufio.Reader.
// Used as fallback when plain mode is active (piped, NO_COLOR, etc.)
// and as the sole implementation in notui builds.
func runStartupReader(defaultEndpoint string, defaultProxyPort int) (Config, error) {
	reader := bufio.NewReader(os.Stdin)
	config := Config{
		ProxyPort:     defaultProxyPort,
		RetentionDays: 7,
	}

	fmt.Println(tui.Separator("Configuration"))
	fmt.Println()

	prompt := ">"
	fmt.Printf("  %s Use auto mode? (resolve provider from model name, per-provider keys or client auth) [Y/n]: ", prompt)
	modeAnswer, _ := reader.ReadString('\n')
	modeAnswer = strings.TrimSpace(strings.ToLower(modeAnswer))

	if modeAnswer == "" || modeAnswer == "y" || modeAnswer == "yes" { //nolint:goconst
		config.AutoMode = true
		fmt.Println()
		tui.PrintInfo("Auto mode enabled")
		tui.PrintInfo("Providers will be resolved from model names")
		tui.PrintInfo("Clients must provide their own auth headers")
		fmt.Println()
	} else {
		config.AutoMode = false

		fmt.Printf("  %s Endpoint URL [%s]: ", prompt, defaultEndpoint)
		endpoint, err := reader.ReadString('\n')
		if err != nil {
			return config, fmt.Errorf("failed to read endpoint: %w", err)
		}
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			endpoint = defaultEndpoint
		}
		config.EndpointURL = endpoint

		fmt.Printf("  %s API Key: ", prompt)
		apiKey, err := readPassword()
		if err != nil {
			return config, fmt.Errorf("failed to read API key: %w", err)
		}
		config.APIKey = apiKey
		fmt.Println()
	}

	fmt.Println(tui.Separator("Security"))
	fmt.Println()

	fmt.Printf("  %s DB Encryption Key (optional, press Enter to skip): ", prompt)
	dbKey, err := readPassword()
	if err != nil {
		return config, fmt.Errorf("failed to read DB key: %w", err)
	}
	config.EncryptionKey = dbKey
	fmt.Println()

	fmt.Println(tui.Separator("Advanced"))
	fmt.Println()
	fmt.Printf("  %s Configure advanced options? [y/N]: ", prompt)
	advAnswer, _ := reader.ReadString('\n')
	advAnswer = strings.TrimSpace(strings.ToLower(advAnswer))

	if advAnswer == "y" || advAnswer == "yes" {
		fmt.Println()

		fmt.Printf("  %s Enable telemetry? [y/N]: ", prompt)
		telAnswer, _ := reader.ReadString('\n')
		telAnswer = strings.TrimSpace(strings.ToLower(telAnswer))
		config.TelemetryEnabled = telAnswer == "y" || telAnswer == "yes"

		fmt.Printf("  %s Retention days (0=forever) [%d]: ", prompt, config.RetentionDays)
		retStr, _ := reader.ReadString('\n')
		retStr = strings.TrimSpace(retStr)
		if retStr != "" {
			if days, err := strconv.Atoi(retStr); err == nil && days >= 0 && days <= 36500 {
				config.RetentionDays = days
			}
		}

		fmt.Printf("  %s Disable builtin rules? [y/N]: ", prompt)
		rulesAnswer, _ := reader.ReadString('\n')
		rulesAnswer = strings.TrimSpace(strings.ToLower(rulesAnswer))
		config.DisableBuiltinRules = rulesAnswer == "y" || rulesAnswer == "yes"

		fmt.Printf("  %s Proxy port [%d]: ", prompt, config.ProxyPort)
		proxyStr, _ := reader.ReadString('\n')
		proxyStr = strings.TrimSpace(proxyStr)
		if proxyStr != "" {
			if port, err := strconv.Atoi(proxyStr); err == nil && port >= 1 && port <= 65535 {
				config.ProxyPort = port
			}
		}

	}

	fmt.Println()
	return config, nil
}
