//go:build !notui

package startup

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/BakeLens/crust/internal/tui"
	"github.com/BakeLens/crust/internal/tui/banner"
)

// RunStartupWithPort runs the startup prompts with a custom default proxy port.
// Uses huh forms for interactive input when a TTY is available.
// Falls back to plain mode for non-interactive contexts.
func RunStartupWithPort(defaultEndpoint string, defaultProxyPort int) (Config, error) {
	fmt.Println()
	banner.PrintBanner("")
	fmt.Println()

	if tui.IsPlainMode() {
		return runStartupReader(defaultEndpoint, defaultProxyPort)
	}
	return runStartupForm(defaultEndpoint, defaultProxyPort)
}

// crustTheme returns a huh theme using the Crust synthwave color palette.
func crustTheme() *huh.Theme {
	t := huh.ThemeBase()

	// Map Crust colors to huh theme
	t.Focused.Base = t.Focused.Base.BorderForeground(tui.ColorPrimary)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(tui.ColorPrimary).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(tui.ColorPrimary).Bold(true).MarginBottom(1)
	t.Focused.Description = t.Focused.Description.Foreground(tui.ColorMuted)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(tui.ColorError)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(tui.ColorError)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(tui.ColorAccent).SetString(tui.IconCheck + " ")
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(tui.ColorAccent)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(tui.ColorAccent)
	t.Focused.Option = t.Focused.Option.Foreground(lipgloss.AdaptiveColor{Light: "235", Dark: "252"})
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(tui.ColorSuccess)
	t.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(tui.ColorSuccess).SetString(tui.IconCheck + " ")
	t.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(tui.ColorMuted).SetString(tui.IconCircle + " ")
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.AdaptiveColor{Light: "#FFF5E0", Dark: "#1A1410"}).Background(tui.ColorAccent).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(lipgloss.AdaptiveColor{Light: "235", Dark: "252"}).Background(lipgloss.AdaptiveColor{Light: "252", Dark: "237"})
	t.Focused.Next = t.Focused.FocusedButton

	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(tui.ColorSuccess)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(tui.ColorMuted)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(tui.ColorAccent)

	// Blurred styles (when field is not focused)
	t.Blurred = t.Focused
	t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	// Group title/description
	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description

	return t
}

// runStartupForm runs the interactive huh form-based wizard.
func runStartupForm(defaultEndpoint string, defaultProxyPort int) (Config, error) {
	cfg := Config{
		ProxyPort:     defaultProxyPort,
		RetentionDays: 7,
	}

	// Form field values (huh binds to pointers)
	var mode = "auto"
	var endpointURL = defaultEndpoint
	var apiKey string
	var encryptionKey string
	var showAdvanced bool
	var telemetryEnabled bool
	var retentionStr = "7"
	var disableBuiltin bool
	var proxyPortStr = strconv.Itoa(defaultProxyPort)

	form := huh.NewForm(
		// Group 1: Mode selection
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Connection Mode").
				Description("How should Crust connect to LLM providers?").
				Options(
					huh.NewOption("Auto — resolve provider from model name, clients bring own auth", "auto"),
					huh.NewOption("Manual — specify endpoint URL and API key", "manual"),
				).
				Value(&mode),
		).Title("Configuration"),

		// Group 2: Manual mode settings (hidden in auto mode)
		huh.NewGroup(
			huh.NewInput().
				Title("Endpoint URL").
				Description("LLM API endpoint").
				Placeholder(defaultEndpoint).
				Value(&endpointURL).
				Validate(func(s string) error {
					if s == "" {
						return errors.New("endpoint URL is required")
					}
					if _, err := url.Parse(s); err != nil {
						return fmt.Errorf("invalid URL: %w", err)
					}
					return nil
				}),
			huh.NewInput().
				Title("API Key").
				Description("Authentication key for the endpoint").
				EchoMode(huh.EchoModePassword).
				Value(&apiKey).
				Validate(func(s string) error {
					if s == "" {
						return errors.New("API key is required")
					}
					return nil
				}),
		).Title("Endpoint").WithHideFunc(func() bool {
			return mode == "auto"
		}),

		// Group 3: Security
		huh.NewGroup(
			huh.NewInput().
				Title("DB Encryption Key").
				Description("Optional — protects telemetry database (min 16 chars, Enter to skip)").
				EchoMode(huh.EchoModePassword).
				Value(&encryptionKey).
				Validate(func(s string) error {
					if s != "" && len(s) < 16 {
						return errors.New("must be at least 16 characters")
					}
					return nil
				}),
		).Title("Security"),

		// Group 4: Advanced options toggle
		huh.NewGroup(
			huh.NewConfirm().
				Title("Configure advanced options?").
				Description("Telemetry, retention, rules, and port settings").
				Value(&showAdvanced),
		).Title("Advanced"),

		// Group 5: Advanced settings (hidden unless toggled)
		huh.NewGroup(
			huh.NewConfirm().
				Title("Enable telemetry?").
				Description("Record API traces and tool call logs").
				Value(&telemetryEnabled),
			huh.NewInput().
				Title("Retention days").
				Description("How long to keep telemetry data (0 = forever)").
				Placeholder("7").
				Value(&retentionStr).
				Validate(func(s string) error {
					if s == "" {
						return nil
					}
					days, err := strconv.Atoi(s)
					if err != nil {
						return errors.New("must be a number")
					}
					if days < 0 || days > 36500 {
						return errors.New("must be 0-36500")
					}
					return nil
				}),
			huh.NewConfirm().
				Title("Disable builtin rules?").
				Description("Only use user-defined security rules").
				Value(&disableBuiltin),
			huh.NewInput().
				Title("Proxy port").
				Description("Port for the proxy server").
				Placeholder(strconv.Itoa(defaultProxyPort)).
				Value(&proxyPortStr).
				Validate(validatePort),
		).Title("Advanced Settings").WithHideFunc(func() bool {
			return !showAdvanced
		}),
	).WithTheme(crustTheme())

	err := form.Run()
	if err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			cfg.Canceled = true
			return cfg, nil
		}
		return cfg, fmt.Errorf("startup form error: %w", err)
	}

	// Map form values to config
	cfg.AutoMode = mode == "auto"
	if !cfg.AutoMode {
		cfg.EndpointURL = endpointURL
		cfg.APIKey = apiKey
	}
	cfg.EncryptionKey = encryptionKey

	if showAdvanced {
		cfg.TelemetryEnabled = telemetryEnabled
		cfg.DisableBuiltinRules = disableBuiltin
		if days, err := strconv.Atoi(retentionStr); err == nil {
			cfg.RetentionDays = days
		}
		if port, err := strconv.Atoi(proxyPortStr); err == nil {
			cfg.ProxyPort = port
		}
	}

	// Print summary
	fmt.Println()
	if cfg.AutoMode {
		tui.PrintInfo("Auto mode — providers resolved from model names")
	} else {
		tui.PrintInfo("Manual mode — " + cfg.EndpointURL)
	}

	return cfg, nil
}

// validatePort validates a port number string.
func validatePort(s string) error {
	if s == "" {
		return nil
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return errors.New("must be a number")
	}
	if port < 1 || port > 65535 {
		return errors.New("must be 1-65535")
	}
	return nil
}
