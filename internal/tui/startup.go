//go:build tui

package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/go-playground/validator/v10"
)

// validate is the shared validator instance
var validate = validator.New()

// StartupConfig holds the configuration collected from the TUI
type StartupConfig struct {
	// Basic
	EndpointURL   string `validate:"required,url"`
	APIKey        string `validate:"required"`
	EncryptionKey string `validate:"omitempty,min=16"`
	// Advanced - Telemetry
	TelemetryEnabled bool
	RetentionDays    int `validate:"min=0,max=36500"`
	// Advanced - Rules
	DisableBuiltinRules bool
	// Advanced - Ports
	ProxyPort int `validate:"omitempty,min=1,max=65535"`
	APIPort   int `validate:"omitempty,min=1,max=65535"`
	// State
	Canceled bool
}

// Validate validates the startup configuration
func (c *StartupConfig) Validate() error {
	return validate.Struct(c)
}

// ValidationErrors returns human-readable validation errors
func (c *StartupConfig) ValidationErrors() []string {
	err := validate.Struct(c)
	if err == nil {
		return nil
	}

	var errors []string
	for _, err := range err.(validator.ValidationErrors) {
		switch err.Field() {
		case "EndpointURL":
			errors = append(errors, "Endpoint URL is required and must be a valid URL")
		case "APIKey":
			errors = append(errors, "API Key is required")
		case "EncryptionKey":
			errors = append(errors, "Encryption key must be at least 16 characters")
		case "ProxyPort", "APIPort":
			errors = append(errors, fmt.Sprintf("%s must be between 1 and 65535", err.Field()))
		case "RetentionDays":
			errors = append(errors, "Retention days must be between 0 and 36500")
		default:
			errors = append(errors, fmt.Sprintf("%s: %s", err.Field(), err.Tag()))
		}
	}
	return errors
}

// Default ports (should match config.DefaultConfig)
const (
	DefaultProxyPort = 9090
	DefaultAPIPort   = 9091
)

// Tab indices
const (
	tabBasic = iota
	tabAdvanced
)

// Special focus index for tab bar
const tabBarFocusIdx = -1

// Focus indices for Basic tab (0-based, content only)
const (
	basicEndpointIdx = iota
	basicAPIKeyIdx
	basicDBKeyIdx
	basicButtonIdx
)

// Focus indices for Advanced tab (0-based, content only)
const (
	advTelemetryToggleIdx = iota
	advRetentionIdx
	advBuiltinToggleIdx
	advProxyPortIdx
	advAPIPortIdx
	advButtonIdx
)

// StartupModel is the Bubble Tea model for the startup form
type StartupModel struct {
	// Inputs for Basic tab
	basicInputs []textinput.Model
	// Inputs for Advanced tab (text inputs only)
	advInputs []textinput.Model
	// Toggle states for Advanced tab
	telemetryEnabled    bool
	disableBuiltinRules bool
	// Tab and focus state
	activeTab  int
	focusIndex int // -1 = tab bar, 0+ = content
	// Config and state
	config StartupConfig
	width  int
	height int
	done   bool
	// Default values
	defaultProxyPort int
	defaultAPIPort   int
}

// NewStartupModel creates a new startup form model
func NewStartupModel(defaultEndpoint string, defaultProxyPort, defaultAPIPort int) StartupModel {
	// Basic tab inputs
	basicInputs := make([]textinput.Model, 3)

	// Endpoint URL input
	basicInputs[0] = textinput.New()
	basicInputs[0].Placeholder = "https://openrouter.ai/api"
	basicInputs[0].SetValue(defaultEndpoint)
	basicInputs[0].Focus()
	basicInputs[0].CharLimit = 256
	basicInputs[0].Width = 40

	// API Key input (password)
	basicInputs[1] = textinput.New()
	basicInputs[1].Placeholder = "sk-..."
	basicInputs[1].EchoMode = textinput.EchoPassword
	basicInputs[1].EchoCharacter = '•'
	basicInputs[1].CharLimit = 256
	basicInputs[1].Width = 40

	// DB Encryption Key input (password, optional)
	basicInputs[2] = textinput.New()
	basicInputs[2].Placeholder = "Enter to skip"
	basicInputs[2].EchoMode = textinput.EchoPassword
	basicInputs[2].EchoCharacter = '•'
	basicInputs[2].CharLimit = 256
	basicInputs[2].Width = 40

	// Advanced tab inputs
	advInputs := make([]textinput.Model, 3)

	// Retention days input
	advInputs[0] = textinput.New()
	advInputs[0].Placeholder = "7"
	advInputs[0].SetValue("7")
	advInputs[0].CharLimit = 4
	advInputs[0].Width = 10

	// Proxy port input
	advInputs[1] = textinput.New()
	advInputs[1].Placeholder = strconv.Itoa(defaultProxyPort)
	advInputs[1].SetValue(strconv.Itoa(defaultProxyPort))
	advInputs[1].CharLimit = 5
	advInputs[1].Width = 10

	// API port input
	advInputs[2] = textinput.New()
	advInputs[2].Placeholder = strconv.Itoa(defaultAPIPort)
	advInputs[2].SetValue(strconv.Itoa(defaultAPIPort))
	advInputs[2].CharLimit = 5
	advInputs[2].Width = 10

	return StartupModel{
		basicInputs:         basicInputs,
		advInputs:           advInputs,
		telemetryEnabled:    false, // default off
		disableBuiltinRules: false, // default off (builtin rules enabled)
		activeTab:           tabBasic,
		focusIndex:          0, // start at first content item
		defaultProxyPort:    defaultProxyPort,
		defaultAPIPort:      defaultAPIPort,
	}
}

// Init implements tea.Model
func (m StartupModel) Init() tea.Cmd {
	return textinput.Blink
}

// maxFocusIndex returns the maximum focus index for the current tab
func (m StartupModel) maxFocusIndex() int {
	if m.activeTab == tabBasic {
		return basicButtonIdx
	}
	return advButtonIdx
}

// isOnTabBar returns true if focus is on the tab bar
func (m StartupModel) isOnTabBar() bool {
	return m.focusIndex == tabBarFocusIdx
}

// Update implements tea.Model
func (m StartupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.config.Canceled = true
			m.done = true
			return m, tea.Quit

		case "left":
			if m.isOnTabBar() {
				// Switch to previous tab
				if m.activeTab > tabBasic {
					m.activeTab--
				}
				return m, nil
			}
			// Let text input handle left arrow

		case "right":
			if m.isOnTabBar() {
				// Switch to next tab
				if m.activeTab < tabAdvanced {
					m.activeTab++
				}
				return m, nil
			}
			// Let text input handle right arrow

		case "up", "shift+tab":
			if m.isOnTabBar() {
				// Wrap to bottom
				m.focusIndex = m.maxFocusIndex()
			} else if m.focusIndex == 0 {
				// Go to tab bar
				m.focusIndex = tabBarFocusIdx
			} else {
				m.focusIndex--
			}
			m.updateFocus()
			return m, nil

		case "down", "tab":
			if m.isOnTabBar() {
				// Go to first content item
				m.focusIndex = 0
			} else if m.focusIndex >= m.maxFocusIndex() {
				// Wrap to tab bar
				m.focusIndex = tabBarFocusIdx
			} else {
				m.focusIndex++
			}
			m.updateFocus()
			return m, nil

		case " ":
			// Space toggles for toggle controls in Advanced tab
			if m.activeTab == tabAdvanced && !m.isOnTabBar() {
				switch m.focusIndex {
				case advTelemetryToggleIdx:
					m.telemetryEnabled = !m.telemetryEnabled
					return m, nil
				case advBuiltinToggleIdx:
					m.disableBuiltinRules = !m.disableBuiltinRules
					return m, nil
				}
			}

		case "enter":
			if m.isOnTabBar() {
				// Move to first content item
				m.focusIndex = 0
				m.updateFocus()
				return m, nil
			}

			// Handle button press
			if m.activeTab == tabBasic && m.focusIndex == basicButtonIdx {
				return m.submit()
			}
			if m.activeTab == tabAdvanced && m.focusIndex == advButtonIdx {
				return m.submit()
			}

			// Move to next field
			m.focusIndex++
			if m.focusIndex > m.maxFocusIndex() {
				m.focusIndex = m.maxFocusIndex()
			}
			m.updateFocus()
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	// Handle input updates based on active tab (only if not on tab bar)
	if !m.isOnTabBar() {
		cmd := m.updateInputs(msg)
		return m, cmd
	}

	return m, nil
}

func (m *StartupModel) updateFocus() {
	// Blur all inputs first
	for i := range m.basicInputs {
		m.basicInputs[i].Blur()
	}
	for i := range m.advInputs {
		m.advInputs[i].Blur()
	}

	// If on tab bar, nothing to focus
	if m.isOnTabBar() {
		return
	}

	// Focus the appropriate input
	if m.activeTab == tabBasic {
		if m.focusIndex < len(m.basicInputs) {
			m.basicInputs[m.focusIndex].Focus()
		}
	} else {
		// Map focus index to advInputs
		switch m.focusIndex {
		case advRetentionIdx:
			m.advInputs[0].Focus()
		case advProxyPortIdx:
			m.advInputs[1].Focus()
		case advAPIPortIdx:
			m.advInputs[2].Focus()
		}
	}
}

func (m *StartupModel) updateInputs(msg tea.Msg) tea.Cmd {
	var cmds []tea.Cmd

	if m.activeTab == tabBasic {
		for i := range m.basicInputs {
			var cmd tea.Cmd
			m.basicInputs[i], cmd = m.basicInputs[i].Update(msg)
			cmds = append(cmds, cmd)
		}
	} else {
		// Filter numeric input for port and retention fields
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			key := keyMsg.String()
			// Only allow numeric input for these fields
			if m.focusIndex == advRetentionIdx || m.focusIndex == advProxyPortIdx || m.focusIndex == advAPIPortIdx {
				if len(key) == 1 && (key[0] < '0' || key[0] > '9') && key != "backspace" {
					return nil
				}
			}
		}

		for i := range m.advInputs {
			var cmd tea.Cmd
			m.advInputs[i], cmd = m.advInputs[i].Update(msg)
			cmds = append(cmds, cmd)
		}
	}

	return tea.Batch(cmds...)
}

func (m StartupModel) submit() (tea.Model, tea.Cmd) {
	// Collect all configuration
	m.config.EndpointURL = m.basicInputs[0].Value()
	m.config.APIKey = m.basicInputs[1].Value()
	m.config.EncryptionKey = m.basicInputs[2].Value()

	m.config.TelemetryEnabled = m.telemetryEnabled
	m.config.DisableBuiltinRules = m.disableBuiltinRules

	// Parse numeric values with defaults and validation
	// SECURITY: Validate bounds to prevent integer overflow and invalid configurations
	if days, err := strconv.Atoi(m.advInputs[0].Value()); err == nil && days >= 0 && days <= 36500 {
		m.config.RetentionDays = days
	} else {
		m.config.RetentionDays = 7
	}

	if port, err := strconv.Atoi(m.advInputs[1].Value()); err == nil && port >= 1 && port <= 65535 {
		m.config.ProxyPort = port
	} else {
		m.config.ProxyPort = m.defaultProxyPort
	}

	if port, err := strconv.Atoi(m.advInputs[2].Value()); err == nil && port >= 1 && port <= 65535 {
		m.config.APIPort = port
	} else {
		m.config.APIPort = m.defaultAPIPort
	}

	m.done = true
	return m, tea.Quit
}

// View implements tea.Model
func (m StartupModel) View() string {
	var b strings.Builder

	// Title line
	b.WriteString(titleStyle.Render("🐑 AgentShepherd"))
	b.WriteString("  ")
	b.WriteString(subtitleStyle.Render("Agent Secure Gateway"))
	b.WriteString("\n\n")

	// Tab bar (focusable)
	b.WriteString(m.renderTabs())
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", 46))
	b.WriteString("\n\n")

	// Tab content (fixed height for both tabs)
	content := ""
	if m.activeTab == tabBasic {
		content = m.renderBasicTab()
	} else {
		content = m.renderAdvancedTab()
	}
	// Fixed size content area to prevent layout shift
	contentStyle := lipgloss.NewStyle().Height(14).Width(46)
	b.WriteString(contentStyle.Render(content))

	// Help
	help := "↑/↓: navigate • "
	if m.isOnTabBar() {
		help += "←/→: switch tab • "
	}
	help += "space: toggle • enter: select • esc: quit"
	b.WriteString(helpStyle.Render(help))

	// Wrap in container
	box := containerStyle.Render(b.String())

	// Center if we have window size
	if m.width > 0 {
		box = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	}

	return box
}

func (m StartupModel) renderTabs() string {
	basicTab := " Basic "
	advTab := " Advanced "

	// Style based on active tab and focus
	var basicStyle, advStyle lipgloss.Style

	if m.activeTab == tabBasic {
		basicStyle = tabActiveStyle
		advStyle = tabInactiveStyle
	} else {
		basicStyle = tabInactiveStyle
		advStyle = tabActiveStyle
	}

	// Add focus indicator
	prefix := "  "
	if m.isOnTabBar() {
		prefix = "▸ "
	}

	return prefix + basicStyle.Render(basicTab) + " " + advStyle.Render(advTab)
}

func (m StartupModel) renderBasicTab() string {
	var b strings.Builder

	// Endpoint URL
	b.WriteString(labelStyle.Render("Endpoint URL"))
	b.WriteString("\n")
	b.WriteString(m.renderBasicInput(0, basicEndpointIdx))
	b.WriteString("\n")

	// API Key
	b.WriteString(labelStyle.Render("API Key"))
	b.WriteString("\n")
	b.WriteString(m.renderBasicInput(1, basicAPIKeyIdx))
	b.WriteString("\n")

	// DB Encryption Key
	b.WriteString(labelStyle.Render("DB Key "))
	b.WriteString(hintStyle.Render("(optional)"))
	b.WriteString("\n")
	b.WriteString(m.renderBasicInput(2, basicDBKeyIdx))
	b.WriteString("\n\n")

	// Start button
	if !m.isOnTabBar() && m.focusIndex == basicButtonIdx {
		b.WriteString(focusedButtonStyle.Render("▶ Start"))
	} else {
		b.WriteString(blurredButtonStyle.Render("  Start"))
	}

	return b.String()
}

func (m StartupModel) renderBasicInput(inputIdx, focusIdx int) string {
	if !m.isOnTabBar() && m.focusIndex == focusIdx {
		return focusedInputStyle.Render(m.basicInputs[inputIdx].View())
	}
	return blurredInputStyle.Render(m.basicInputs[inputIdx].View())
}

func (m StartupModel) renderAdvancedTab() string {
	var b strings.Builder

	// Row 1: Telemetry toggle
	b.WriteString(m.renderRow("Telemetry", m.renderToggle(m.telemetryEnabled, advTelemetryToggleIdx)))
	b.WriteString("\n\n")

	// Row 2: Retention days
	b.WriteString(m.renderRow("Retention", m.renderInlineInput(0, advRetentionIdx)+" "+hintStyle.Render("days (0=forever)")))
	b.WriteString("\n\n")

	// Row 3: Builtin rules toggle
	b.WriteString(m.renderRow("Builtin Rules", m.renderToggle(!m.disableBuiltinRules, advBuiltinToggleIdx)))
	b.WriteString("\n")
	if m.disableBuiltinRules {
		b.WriteString(warningStyle.Render("                 ⚠ Removes default security protections"))
	}
	b.WriteString("\n")

	// Row 4: Proxy port
	b.WriteString(m.renderRow("Proxy Port", m.renderInlineInput(1, advProxyPortIdx)))
	b.WriteString("\n\n")

	// Row 5: API port
	b.WriteString(m.renderRow("API Port", m.renderInlineInput(2, advAPIPortIdx)))
	b.WriteString("\n\n")

	// Start button
	if !m.isOnTabBar() && m.focusIndex == advButtonIdx {
		b.WriteString(focusedButtonStyle.Render("▶ Start"))
	} else {
		b.WriteString(blurredButtonStyle.Render("  Start"))
	}

	return b.String()
}

func (m StartupModel) renderRow(label, value string) string {
	// Fixed width label for alignment
	labelWidth := 17
	paddedLabel := label + strings.Repeat(" ", labelWidth-len(label))
	return labelStyle.Render(paddedLabel) + value
}

func (m StartupModel) renderToggle(isOn bool, focusIdx int) string {
	var content string
	if isOn {
		content = toggleOnStyle.Render("[x] On ") + toggleOffStyle.Render("[ ] Off")
	} else {
		content = toggleOffStyle.Render("[ ] On ") + toggleOnStyle.Render("[x] Off")
	}

	if !m.isOnTabBar() && m.focusIndex == focusIdx {
		return "▸ " + content
	}
	return "  " + content
}

func (m StartupModel) renderInlineInput(inputIdx, focusIdx int) string {
	value := m.advInputs[inputIdx].View()
	if !m.isOnTabBar() && m.focusIndex == focusIdx {
		// Focused: show with brackets and highlight
		return lipgloss.NewStyle().Foreground(primaryColor).Render("[" + value + "]")
	}
	// Blurred: just show value
	return lipgloss.NewStyle().Foreground(mutedColor).Render("[" + value + "]")
}

// GetConfig returns the collected configuration
func (m StartupModel) GetConfig() StartupConfig {
	return m.config
}

// IsDone returns true if the form is complete
func (m StartupModel) IsDone() bool {
	return m.done
}

// RunStartupWithPorts runs the startup TUI with custom default ports
func RunStartupWithPorts(defaultEndpoint string, defaultProxyPort, defaultAPIPort int) (StartupConfig, error) {
	model := NewStartupModel(defaultEndpoint, defaultProxyPort, defaultAPIPort)
	p := tea.NewProgram(model, tea.WithAltScreen())

	finalModel, err := p.Run()
	if err != nil {
		return StartupConfig{}, fmt.Errorf("failed to run TUI: %w", err)
	}

	m, ok := finalModel.(StartupModel)
	if !ok {
		return StartupConfig{}, fmt.Errorf("unexpected model type")
	}

	return m.GetConfig(), nil
}
