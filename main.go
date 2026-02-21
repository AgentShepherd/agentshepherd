package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BakeLens/crust/internal/earlyinit" // must be first: prevents terminal queries before bubbletea init

	"github.com/BakeLens/crust/internal/completion"
	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/proxy"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/tui"
	"github.com/BakeLens/crust/internal/tui/banner"
	"github.com/BakeLens/crust/internal/tui/dashboard"
	"github.com/BakeLens/crust/internal/tui/logview"
	tuiprogress "github.com/BakeLens/crust/internal/tui/progress"
	"github.com/BakeLens/crust/internal/tui/rulelist"
	"github.com/BakeLens/crust/internal/tui/spinner"
	"github.com/BakeLens/crust/internal/tui/startup"
	"github.com/BakeLens/crust/internal/types"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Version is set at build time via ldflags: -X main.Version=x.y.z
var Version = "2.1.0"

// =============================================================================
// API Client (inlined from internal/cli)
// =============================================================================

// apiClient provides API access for CLI commands
type apiClient struct {
	cfg    *config.Config
	client *http.Client // uses Unix socket / named pipe transport (or TCP for remote)
	remote string       // non-empty when connecting to a remote daemon
}

// newAPIClient creates a CLI API client.
// If remoteAddr is empty, connects via local Unix socket / named pipe.
// If remoteAddr is set (e.g., "localhost:9090"), connects over TCP.
func newAPIClient(remoteAddr ...string) *apiClient {
	cfg, err := config.Load(config.DefaultConfigPath())
	if err != nil {
		cfg = config.DefaultConfig()
	}
	if len(remoteAddr) > 0 && remoteAddr[0] != "" {
		return &apiClient{
			cfg:    cfg,
			client: &http.Client{},
			remote: remoteAddr[0],
		}
	}
	socketPath := cfg.API.SocketPath
	if socketPath == "" {
		socketPath = daemon.SocketFile(cfg.Server.Port)
	}
	return &apiClient{
		cfg:    cfg,
		client: &http.Client{Transport: security.APITransport(socketPath)},
	}
}

// apiURL returns the base URL for the management API.
// For local: dummy host routed via socket/pipe.
// For remote: TCP address of the daemon.
func (c *apiClient) apiURL() string {
	if c.remote != "" {
		return "http://" + c.remote
	}
	return dashboard.DefaultAPIBase
}

// proxyBaseURL returns the proxy base URL
func (c *apiClient) proxyBaseURL() string {
	if c.remote != "" {
		return "http://" + c.remote
	}
	return fmt.Sprintf("http://localhost:%d", c.cfg.Server.Port)
}

// checkHealth checks if the proxy server is healthy (still uses TCP for the proxy)
func (c *apiClient) checkHealth() (bool, error) {
	url := c.proxyBaseURL() + "/health"
	resp, err := http.Get(url) //nolint:gosec,noctx // URL is from trusted config
	if err != nil || resp == nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// isServerRunning checks if the Crust management API is reachable
func (c *apiClient) isServerRunning() bool {
	url := c.apiURL() + "/api/crust/rules/reload"
	resp, err := c.client.Post(url, "application/json", nil) //nolint:noctx
	if err != nil || resp == nil {
		return false
	}
	resp.Body.Close()
	return true
}

// reloadRules triggers a hot reload of rules
func (c *apiClient) reloadRules() ([]byte, error) {
	url := c.apiURL() + "/api/crust/rules/reload"
	resp, err := c.client.Post(url, "application/json", nil) //nolint:noctx
	if err != nil || resp == nil {
		return nil, errors.New("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// getRules fetches all rules from the server
func (c *apiClient) getRules() ([]byte, error) {
	url := c.apiURL() + "/api/crust/rules"
	resp, err := c.client.Get(url) //nolint:noctx
	if err != nil || resp == nil {
		return nil, errors.New("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// rulesResponse represents the API response for rules listing
type rulesResponse struct {
	Rules []rules.Rule `json:"rules"`
	Total int          `json:"total"`
}

// rulesResponse uses rules.Rule directly — no mirrored structs needed
// since the daemon API already serializes rules.Rule as JSON.

// getRulesParsed fetches and parses rules from the server
func (c *apiClient) getRulesParsed() (*rulesResponse, error) {
	body, err := c.getRules()
	if err != nil {
		return nil, err
	}

	var rulesResp rulesResponse
	if err := json.Unmarshal(body, &rulesResp); err != nil {
		return nil, err
	}
	return &rulesResp, nil
}

var log = logger.New("main")

func main() {
	// Shell worker subprocess mode: if invoked with _CRUST_SHELL_WORKER=1,
	// enter the worker loop for crash-isolated shell interpretation.
	if rules.RunShellWorkerMain() {
		return
	}

	// Shell completion: if invoked for tab-completion, output completions and exit
	if completion.Run() {
		return
	}

	// Check for subcommands first
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "start":
			runStart(os.Args[2:])
			return
		case "stop":
			runStop()
			return
		case "status":
			runStatus(os.Args[2:])
			return
		case "logs":
			runLogs(os.Args[2:])
			return
		case "add-rule":
			runAddRule(os.Args[2:])
			return
		case "remove-rule":
			runRemoveRule(os.Args[2:])
			return
		case "list-rules":
			runListRules(os.Args[2:])
			return
		case "reload-rules":
			runReloadRules(os.Args[2:])
			return
		case "lint-rules":
			runLintRules(os.Args[2:])
			return
		case "uninstall":
			runUninstall()
			return
		case "completion":
			runCompletion(os.Args[2:])
			return
		case "help", "-h", "--help":
			printUsage()
			return
		case "version", "-v", "--version":
			runVersion(os.Args[2:])
			return
		}
	}

	// No subcommand - show help
	printUsage()
}

// runStart handles the start subcommand
func runStart(args []string) {
	// Foreground mode: if earlyinit suppressed TERM (no real TTY), restore
	// the original TERM and set fallback color config. If a real TTY was
	// present, bubbletea already auto-detected background color and profile.
	if earlyinit.Foreground {
		if earlyinit.Suppressed {
			os.Setenv("TERM", earlyinit.OrigTERM)
			lipgloss.SetHasDarkBackground(true)
			lipgloss.SetColorProfile(colorProfileFromTERM(earlyinit.OrigTERM))
		}

		// Enable styled TUI output when stdout is a TTY and TERM supports
		// colors. Docker containers may lack terminal-specific env vars, so
		// auto-detection falls back to CapNone → plain mode. Override that
		// here since the TTY + color profile are sufficient.
		_, noColor := os.LookupEnv("NO_COLOR")
		isTTY := term.IsTerminal(int(os.Stdout.Fd())) //nolint:gosec // Fd() fits int
		if !noColor && isTTY && earlyinit.OrigTERM != "" && earlyinit.OrigTERM != "dumb" {
			tui.SetPlainMode(false)
		}
	}

	tui.WindowTitle("crust setup")

	// Check if already running
	if running, pid := daemon.IsRunning(); running {
		tui.PrintWarning(fmt.Sprintf("Crust is already running [PID %d]", pid))
		os.Exit(1)
	}

	// Parse flags
	startFlags := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := startFlags.String("config", config.DefaultConfigPath(), "Path to configuration file")
	logLevel := startFlags.String("log-level", "", "Log level: trace, debug, info, warn, error")
	noColor := startFlags.Bool("no-color", false, "Disable colored log output")
	disableBuiltin := startFlags.Bool("disable-builtin", false, "Disable builtin security rules")
	daemonMode := startFlags.Bool("daemon-mode", false, "Internal: indicates running as daemon")
	foreground := startFlags.Bool("foreground", false, "Run in foreground (don't daemonize); useful for containers")

	// Allow passing secrets via flags (for scripting)
	// SECURITY: Environment variables are preferred over CLI flags for secrets
	endpoint := startFlags.String("endpoint", "", "LLM API endpoint URL")
	apiKey := startFlags.String("api-key", "", "API key for the endpoint (prefer LLM_API_KEY env var)")
	dbKey := startFlags.String("db-key", "", "Database encryption key (prefer DB_KEY env var)")
	autoMode := startFlags.Bool("auto", false, "Auto mode: resolve providers from model names (per-provider keys or client auth)")

	// Advanced options
	proxyPort := startFlags.Int("proxy-port", 0, "Proxy server port (default from config)")
	listenAddr := startFlags.String("listen-address", "", "Bind address for the proxy server (default 127.0.0.1)")
	telemetryEnabled := startFlags.Bool("telemetry", false, "Enable telemetry")
	retentionDays := startFlags.Int("retention-days", 0, "Telemetry retention in days (0=use config default)")
	blockMode := startFlags.String("block-mode", "", "Block mode: remove (delete tool calls) or replace (substitute with echo)")

	_ = startFlags.Parse(args)

	// Wire --no-color to TUI plain mode
	if *noColor {
		tui.SetPlainMode(true)
	}

	// SECURITY: Load secrets from environment variables using envconfig
	// Environment variables are preferred over CLI flags (visible in ps auxww)
	secrets, err := config.LoadSecretsWithDefaults(*apiKey, *dbKey)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to load secrets: %v", err))
		os.Exit(1)
	}

	// Use secrets from envconfig (overrides CLI flags if set)
	if secrets.LLMAPIKey != "" {
		*apiKey = secrets.LLMAPIKey
	}
	if secrets.DBKey != "" {
		*dbKey = secrets.DBKey
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to load configuration: %v", err))
		os.Exit(1)
	}

	// Check if we're in daemon mode (re-executed process)
	if *daemonMode || daemon.IsDaemonMode() {
		// We're the daemon process - run the server
		runDaemon(cfg, *logLevel, *disableBuiltin, *endpoint, *apiKey, *dbKey,
			*proxyPort, *listenAddr, *telemetryEnabled, *retentionDays, *blockMode, *autoMode)
		return
	}

	// Foreground mode - run server directly without daemonizing (for Docker/containers).
	// If detached (non-interactive), TUI was already disabled by earlyinit.
	// If interactive (docker run -it), full TUI is available.
	if *foreground {
		runDaemon(cfg, *logLevel, *disableBuiltin, *endpoint, *apiKey, *dbKey,
			*proxyPort, *listenAddr, *telemetryEnabled, *retentionDays, *blockMode, *autoMode)
		return
	}

	// Interactive mode - collect configuration via TUI
	var startupCfg startup.Config

	if *autoMode || (*endpoint != "" && *apiKey != "") {
		// Flags provided — skip interactive prompts, but still show the banner
		fmt.Println()
		banner.PrintBanner(Version)
		fmt.Println()
		startupCfg = startup.Config{
			AutoMode:            *autoMode,
			EndpointURL:         *endpoint,
			APIKey:              *apiKey,
			EncryptionKey:       *dbKey,
			TelemetryEnabled:    *telemetryEnabled,
			RetentionDays:       *retentionDays,
			DisableBuiltinRules: *disableBuiltin,
			ProxyPort:           *proxyPort,
		}
	} else {
		// Run interactive prompts (asks auto vs manual mode first)
		startupCfg, err = startup.RunStartupWithPort(cfg.Upstream.URL, cfg.Server.Port)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Startup error: %v", err))
			os.Exit(1)
		}

		if startupCfg.Canceled {
			tui.PrintInfo("Startup canceled")
			os.Exit(0)
		}
	}

	// Build args for daemon process
	// SECURITY: Secrets (API key, DB key) are passed via environment variables only,
	// not CLI args, to avoid exposure in ps/proc. See Daemonize() for env propagation.
	daemonArgs := []string{
		"start",
		"--config", *configPath,
	}
	if startupCfg.EndpointURL != "" {
		daemonArgs = append(daemonArgs, "--endpoint", startupCfg.EndpointURL)
	}
	if startupCfg.AutoMode {
		daemonArgs = append(daemonArgs, "--auto")
	}
	if *logLevel != "" {
		daemonArgs = append(daemonArgs, "--log-level", *logLevel)
	}
	if *noColor {
		daemonArgs = append(daemonArgs, "--no-color")
	}
	if startupCfg.DisableBuiltinRules {
		daemonArgs = append(daemonArgs, "--disable-builtin")
	}
	// Pass advanced options
	if startupCfg.ProxyPort > 0 {
		daemonArgs = append(daemonArgs, "--proxy-port", strconv.Itoa(startupCfg.ProxyPort))
	}
	if *listenAddr != "" {
		daemonArgs = append(daemonArgs, "--listen-address", *listenAddr)
	}
	if startupCfg.TelemetryEnabled {
		daemonArgs = append(daemonArgs, "--telemetry=true")
	}
	if startupCfg.RetentionDays > 0 {
		daemonArgs = append(daemonArgs, "--retention-days", strconv.Itoa(startupCfg.RetentionDays))
	}
	if *blockMode != "" {
		daemonArgs = append(daemonArgs, "--block-mode", *blockMode)
	}

	// SECURITY: Set secrets as env vars so Daemonize() can propagate them
	// This handles the case where secrets came from CLI flags rather than env vars
	if startupCfg.APIKey != "" {
		os.Setenv("LLM_API_KEY", startupCfg.APIKey)
	}
	if startupCfg.EncryptionKey != "" {
		os.Setenv("DB_KEY", startupCfg.EncryptionKey)
	}

	// Launch daemon with progress steps
	var pid int
	launchErr := tuiprogress.RunSteps([]tuiprogress.Step{
		{
			Label:      "Launching daemon",
			SuccessMsg: "Daemon launched",
			Fn: func() error {
				var err error
				pid, err = daemon.Daemonize(daemonArgs, cfg.ProviderEnvKeys)
				if err != nil {
					return fmt.Errorf("failed to start daemon: %w", err)
				}
				return nil
			},
		},
		{
			Label:      "Verifying health",
			SuccessMsg: "Health check passed",
			Fn: func() error {
				// Wait for daemon to start, then verify
				time.Sleep(500 * time.Millisecond)
				if running, _ := daemon.IsRunning(); !running {
					return fmt.Errorf("daemon failed to start — check logs: %s", daemon.LogFile())
				}
				return nil
			},
		},
	})
	if launchErr != nil {
		tui.PrintError(launchErr.Error())
		os.Exit(1)
	}

	// Build success content
	fmt.Println()
	if tui.IsPlainMode() {
		tui.PrintSuccess("Started")
		fmt.Printf("  PID     %d\n", pid)
		fmt.Printf("  Logs    %s\n", daemon.LogFileDisplay())
		fmt.Println()
		fmt.Println("  Commands")
		fmt.Println("    crust status   Check status")
		fmt.Println("    crust logs     View logs")
		fmt.Println("    crust stop     Stop crust")
	} else {
		banner.RevealLines([]string{
			tui.StyleSuccess.Render(tui.IconCheck) + " " + tui.StyleBold.Render("Started"),
			"",
			"  PID     " + tui.StyleBold.Render(strconv.Itoa(pid)),
			"  Logs    " + tui.Hyperlink("file://"+daemon.LogFile(), daemon.LogFileDisplay()),
			"",
			tui.StyleMuted.Render("  Commands"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust status"), tui.StyleMuted.Render("──"), "Check status"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust logs  "), tui.StyleMuted.Render("──"), "View logs"),
			fmt.Sprintf("    %s  %s  %s", tui.StyleCommand.Render("crust stop  "), tui.StyleMuted.Render("──"), "Stop crust"),
		})
	}
}

// runDaemon runs the actual server (called in daemon process)
func runDaemon(cfg *config.Config, logLevel string, disableBuiltin bool, endpoint, apiKey, dbKey string,
	proxyPort int, listenAddr string, telemetryEnabled bool, retentionDays int, blockMode string, autoMode bool) {
	// Write PID file
	if err := daemon.WritePID(); err != nil {
		tui.PrintError(fmt.Sprintf("Failed to write PID file: %v", err))
		os.Exit(1)
	}
	defer daemon.CleanupPID()

	// Configure logger
	if logLevel != "" {
		logger.SetGlobalLevelFromString(logLevel)
	} else {
		logger.SetGlobalLevelFromString(string(cfg.Server.LogLevel))
	}
	// Enable logger colors in foreground mode when stderr is a TTY.
	// Daemon mode (re-executed process) writes to log files — no colors.
	if !earlyinit.Foreground || !term.IsTerminal(int(os.Stderr.Fd())) { //nolint:gosec // Fd() fits int
		logger.SetColored(false)
	}

	// Apply command-line overrides
	if endpoint != "" {
		cfg.Upstream.URL = endpoint
	}
	if apiKey != "" {
		cfg.Upstream.APIKey = apiKey
	}
	if dbKey != "" {
		cfg.Storage.EncryptionKey = dbKey
	}
	if disableBuiltin {
		cfg.Rules.DisableBuiltin = true
	}
	// Apply advanced options
	if proxyPort > 0 {
		cfg.Server.Port = proxyPort
	}
	cfg.Telemetry.Enabled = telemetryEnabled
	if retentionDays > 0 {
		cfg.Telemetry.RetentionDays = retentionDays
	}
	if blockMode != "" {
		cfg.Security.BlockMode = types.BlockMode(blockMode)
	}

	// Validate config AFTER all CLI overrides have been applied
	if err := cfg.Validate(); err != nil {
		tui.PrintError(fmt.Sprintf("Configuration error:\n%v", err))
		os.Exit(1)
	}

	// Write port file so `crust wrap` can discover the proxy port
	if err := daemon.WritePort(cfg.Server.Port); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write port file: %v\n", err)
		os.Exit(1)
	}

	log.Info("Starting Crust daemon...")

	// Initialize rules engine
	var ruleWatcher *rules.Watcher
	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	if cfg.Rules.Enabled {
		engineCfg := rules.EngineConfig{
			UserRulesDir:        rulesDir,
			DisableBuiltin:      cfg.Rules.DisableBuiltin,
			SubprocessIsolation: true,
		}

		ruleEngine, err := rules.NewEngine(engineCfg)
		if err != nil {
			log.Error("Failed to initialize rules engine: %v", err)
			os.Exit(1)
		}

		rules.SetGlobalEngine(ruleEngine)
		log.Info("Rules engine: %d rules loaded", ruleEngine.RuleCount())

		if cfg.Rules.Watch {
			ruleWatcher, err = rules.NewWatcher(ruleEngine)
			if err != nil {
				log.Warn("Failed to create rule watcher: %v", err)
			} else {
				if err := ruleWatcher.Start(); err != nil {
					log.Warn("Failed to start rule watcher: %v", err)
				}
			}
		}

	}

	// Derive socket path for management API (unique per proxy port for multi-session)
	socketPath := cfg.API.SocketPath
	if socketPath == "" {
		socketPath = daemon.SocketFile(cfg.Server.Port)
	}

	// Initialize manager
	managerCfg := security.Config{
		DBPath:          cfg.Storage.DBPath,
		DBKey:           cfg.Storage.EncryptionKey,
		SocketPath:      socketPath,
		SecurityEnabled: cfg.Security.Enabled,
		RetentionDays:   cfg.Telemetry.RetentionDays,
		BufferStreaming: cfg.Security.BufferStreaming,
		MaxBufferEvents: cfg.Security.MaxBufferEvents,
		BufferTimeout:   cfg.Security.BufferTimeout,
		BlockMode:       cfg.Security.BlockMode,
	}

	manager, err := security.Init(managerCfg)
	if err != nil {
		log.Error("Failed to initialize manager: %v", err)
		os.Exit(1)
	}
	defer func() {
		if ruleWatcher != nil {
			_ = ruleWatcher.Stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Shutdown(ctx)
	}()

	// Initialize telemetry
	if cfg.Telemetry.Enabled {
		telemetryCfg := telemetry.Config{
			Enabled:     cfg.Telemetry.Enabled,
			ServiceName: cfg.Telemetry.ServiceName,
			SampleRate:  cfg.Telemetry.SampleRate,
		}
		tp, err := telemetry.Init(context.Background(), telemetryCfg)
		if err != nil {
			log.Error("Failed to initialize telemetry: %v", err)
			os.Exit(1)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(ctx)
		}()
	}

	// Create proxy
	proxyHandler, err := proxy.NewProxy(cfg.Upstream.URL, cfg.Upstream.APIKey, time.Duration(cfg.Upstream.Timeout)*time.Second, cfg.Upstream.Providers, autoMode)
	if err != nil {
		log.Error("Failed to create proxy: %v", err)
		os.Exit(1)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	if listenAddr != "" && listenAddr != "127.0.0.1" && listenAddr != "localhost" {
		// Expose management API on proxy port for remote access (Docker/container mode).
		// On localhost, the Unix socket is used instead (more secure).
		mux.Handle("/api/", manager.APIHandler())
	}
	mux.Handle("/", proxyHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	bindAddr := "127.0.0.1"
	if listenAddr != "" {
		bindAddr = listenAddr
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", bindAddr, cfg.Server.Port),
		Handler: loggingMiddleware(mux),
		// SECURITY FIX: Add ReadHeaderTimeout to prevent Slowloris attacks
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.Upstream.Timeout) * time.Second,
		WriteTimeout:      0, // Must be 0 for SSE streaming (it's a deadline, not idle timeout)
	}

	log.Info("Crust listening on %s:%d", bindAddr, cfg.Server.Port)
	if autoMode {
		log.Info("  Mode: auto (provider resolved from model name)")
		if cfg.Upstream.URL != "" {
			log.Info("  Fallback upstream: %s", cfg.Upstream.URL)
		}
	} else {
		log.Info("  Upstream: %s", cfg.Upstream.URL)
	}
	log.Info("  API: %s", socketPath)

	// Start server
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Server error: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal (os.Interrupt is portable across Unix and Windows)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown: %v", err)
		os.Exit(1)
	}

	log.Info("Crust stopped")
}

// runStop handles the stop subcommand
func runStop() {
	running, _ := daemon.IsRunning()
	if !running {
		tui.PrintInfo("Crust is not running")
		return
	}

	err := spinner.RunWithSpinner("Stopping crust", "Stopped", daemon.Stop)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Failed to stop: %v", err))
		os.Exit(1)
	}
}

// runStatus handles the status subcommand
func runStatus(args []string) {
	tui.WindowTitle("crust status")
	statusFlags := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOutput := statusFlags.Bool("json", false, "Output as JSON")
	live := statusFlags.Bool("live", false, "Live dashboard with auto-refresh")
	apiAddr := statusFlags.String("api-addr", "", "Remote daemon address (host:port)")
	_ = statusFlags.Parse(args)

	// Resolve client, PID, and log file based on local vs remote
	var client *apiClient
	var pid int
	var logFile string

	if *apiAddr != "" {
		client = newAPIClient(*apiAddr)
	} else {
		running, localPID := daemon.IsRunning()
		if *jsonOutput {
			status := map[string]any{"running": running, "pid": localPID}
			if running {
				c := newAPIClient()
				healthy, _ := c.checkHealth() //nolint:errcheck // error means unhealthy
				status["healthy"] = healthy
				status["log_file"] = daemon.LogFile()
			}
			out, _ := json.MarshalIndent(status, "", "  ") //nolint:errcheck // marshal of map[string]any won't fail
			fmt.Println(string(out))
			return
		}
		if !running {
			tui.PrintInfo("Crust is not running")
			return
		}
		client = newAPIClient()
		pid = localPID
		logFile = daemon.LogFileDisplay()
	}

	if *live {
		if err := dashboard.Run(client.client, client.apiURL(), client.proxyBaseURL(), pid, logFile); err != nil {
			tui.PrintError(fmt.Sprintf("Dashboard error: %v", err))
		}
		return
	}

	data := dashboard.FetchStatus(client.client, client.apiURL(), client.proxyBaseURL(), pid, logFile)
	if *jsonOutput {
		out, _ := json.MarshalIndent(data, "", "  ") //nolint:errcheck // marshal won't fail
		fmt.Println(string(out))
		return
	}
	fmt.Println(dashboard.RenderStatic(data))
}

// runVersion handles the version subcommand
func runVersion(args []string) {
	versionFlags := flag.NewFlagSet("version", flag.ExitOnError)
	jsonOutput := versionFlags.Bool("json", false, "Output as JSON")
	_ = versionFlags.Parse(args)

	if *jsonOutput {
		out, _ := json.MarshalIndent(map[string]string{"version": Version}, "", "  ") //nolint:errcheck // marshal of map won't fail
		fmt.Println(string(out))
		return
	}

	banner.PrintBanner(Version)
}

// runLogs handles the logs subcommand
func runLogs(args []string) {
	tui.WindowTitle("crust logs")
	logsFlags := flag.NewFlagSet("logs", flag.ExitOnError)
	follow := logsFlags.Bool("f", false, "Follow log output")
	lines := logsFlags.Int("n", 50, "Number of lines to show")
	_ = logsFlags.Parse(args)

	// SECURITY: Validate lines is in valid range
	if *lines < 1 {
		*lines = 50
	} else if *lines > 10000 {
		*lines = 10000
	}

	logFile := daemon.LogFile()

	if err := logview.View(logFile, *lines, *follow); err != nil {
		tui.PrintError("No logs found. Is crust running?")
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	httpLog := logger.New("http")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		next.ServeHTTP(w, r)
		httpLog.Debug("%s %s from %s (%v)", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}

func printUsage() {
	banner.PrintBanner(Version)
	fmt.Println()

	fmt.Println(tui.Separator("Usage"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust start [flags]", "Start crust (interactive or with flags)"},
		{"crust stop", "Stop crust"},
		{"crust status [--json] [--live] [--api-addr]", "Check if crust is running"},
		{"crust logs [-f] [-n N]", "View logs (-f to follow, -n for line count)"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Rule Management"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust add-rule <file.yaml>", "Add a rule file to user rules"},
		{"crust remove-rule <filename>", "Remove a user rule file"},
		{"crust list-rules [--json]", "List all active rules"},
		{"crust reload-rules", "Trigger hot reload of rules"},
		{"crust lint-rules [file.yaml]", "Validate rule syntax and patterns"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Other"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust completion [--install]", "Install shell completion (bash/zsh/fish)"},
		{"crust uninstall", "Uninstall crust completely"},
		{"crust help", "Show this help message"},
		{"crust version [--json]", "Show version"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Start Flags"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"--config string", "Path to configuration file (default \"~/.crust/config.yaml\")"},
		{"--endpoint string", "LLM API endpoint URL (skip interactive prompt)"},
		{"--api-key string", "API key for the endpoint (skip interactive prompt)"},
		{"--auto", "Auto mode: resolve providers from model names"},
		{"--db-key string", "Database encryption key (optional)"},
		{"--log-level string", "Log level: trace, debug, info, warn, error"},
		{"--no-color", "Disable colored log output"},
		{"--disable-builtin", "Disable builtin security rules"},
		{"--proxy-port int", "Proxy server port (default from config)"},
		{"--listen-address string", "Bind address (default 127.0.0.1, use 0.0.0.0 for Docker)"},
		{"--foreground", "Run in foreground (don't daemonize); for Docker/containers"},
		{"--block-mode string", "Block mode: remove (delete tool calls) or replace (echo)"},
		{"--telemetry", "Enable/disable telemetry (default false)"},
		{"--retention-days int", "Telemetry retention in days (0=forever)"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Environment Variables"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"LLM_API_KEY", "API key for the LLM endpoint"},
		{"DB_KEY", "Database encryption key"},
		{"NO_COLOR", "Disable colored output (any value)"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
	fmt.Println()

	fmt.Println(tui.Separator("Examples"))
	fmt.Print(tui.AlignColumns([][2]string{
		{"crust start", "Interactive setup"},
		{"LLM_API_KEY=sk-xxx crust start --endpoint https://openrouter.ai/api/v1", ""},
		{"crust start --auto", "Auto mode"},
		{"crust start --foreground --auto --listen-address 0.0.0.0", "Docker/container mode"},
		{"crust logs -f", "Follow logs"},
		{"crust stop", "Stop crust"},
	}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
}

// notifyRulesReload triggers a hot reload if the server is running,
// or prints an info message with the given offline hint.
func notifyRulesReload(client *apiClient, running bool, offlineHint string) {
	if running {
		if _, err := client.reloadRules(); err == nil {
			tui.PrintSuccess("Hot reload triggered")
		}
	} else {
		tui.PrintInfo(offlineHint)
	}
}

// exitNotRunning prints a "not running" error and exits.
func exitNotRunning() {
	tui.PrintError("Crust is not running")
	if tui.IsPlainMode() {
		fmt.Fprintln(os.Stderr, "  Start it first with: crust start")
	} else {
		fmt.Fprintf(os.Stderr, "  Start it first with: %s\n", tui.StyleCommand.Render("crust start"))
	}
	os.Exit(1)
}

// runAddRule handles the add-rule subcommand
func runAddRule(args []string) {
	if len(args) == 0 {
		tui.PrintError("Usage: crust add-rule <file.yaml>")
		os.Exit(1)
	}

	filePath := args[0]
	client := newAPIClient()
	serverRunning := client.isServerRunning()

	// Read and validate rule file
	data, err := os.ReadFile(filePath) //nolint:gosec // filePath is a user-provided CLI argument, validated by loader.ValidateYAML below
	if err != nil {
		tui.PrintError(fmt.Sprintf("Error reading file: %v", err))
		os.Exit(1)
	}

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.ValidateYAML(data); err != nil {
		tui.PrintError(fmt.Sprintf("Validation error: %v", err))
		os.Exit(1)
	}

	destPath, err := loader.AddRuleFile(filePath)
	if err != nil {
		tui.PrintError(fmt.Sprintf("Error adding rule file: %v", err))
		os.Exit(1)
	}

	tui.PrintSuccess("Rule file added: " + destPath)
	notifyRulesReload(client, serverRunning, "Crust is not running. Rules will be loaded on next start.")
}

// runRemoveRule handles the remove-rule subcommand
func runRemoveRule(args []string) {
	if len(args) == 0 {
		tui.PrintError("Usage: crust remove-rule <filename>")
		fmt.Fprintln(os.Stderr, "  Remove a user rule file from ~/.crust/rules.d/")
		if tui.IsPlainMode() {
			fmt.Fprintln(os.Stderr, "  Use crust list-rules to see available rules.")
		} else {
			fmt.Fprintf(os.Stderr, "  Use %s to see available rules.\n", tui.StyleCommand.Render("crust list-rules"))
		}
		os.Exit(1)
	}

	filename := args[0]
	client := newAPIClient()
	serverRunning := client.isServerRunning()

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.RemoveRuleFile(filename); err != nil {
		tui.PrintError(fmt.Sprintf("Error removing rule file: %v", err))
		os.Exit(1)
	}

	tui.PrintSuccess("Rule file removed: " + filename)
	notifyRulesReload(client, serverRunning, "Crust is not running. Rules will be updated on next start.")
}

// runListRules handles the list-rules subcommand
func runListRules(args []string) {
	tui.WindowTitle("crust rules")
	listFlags := flag.NewFlagSet("list-rules", flag.ExitOnError)
	jsonOutput := listFlags.Bool("json", false, "Output as JSON")
	apiAddr := listFlags.String("api-addr", "", "Remote daemon address (host:port)")
	_ = listFlags.Parse(args)

	client := newAPIClient(*apiAddr)
	body, err := client.getRules()
	if err != nil {
		exitNotRunning()
	}

	if *jsonOutput {
		fmt.Println(string(body))
		return
	}

	// Parse and render
	rulesResp, err := client.getRulesParsed()
	if err != nil {
		fmt.Println(string(body))
		return
	}

	if err := rulelist.Render(rulesResp.Rules, rulesResp.Total); err != nil {
		tui.PrintError(fmt.Sprintf("Failed to render rules: %v", err))
	}
}

// runReloadRules handles the reload-rules subcommand
func runReloadRules(_ []string) {
	client := newAPIClient()
	body, err := client.reloadRules()
	if err != nil {
		exitNotRunning()
	}
	fmt.Println(string(body))
}

// runUninstall handles the uninstall subcommand
func runUninstall() {
	binaryPath := "/usr/local/bin/crust"
	dataDir := daemon.DataDir()

	tui.PrintWarning("This will remove:")
	fmt.Printf("  - %s\n", binaryPath)
	fmt.Printf("  - %s/ (logs, rules, database)\n", dataDir)
	fmt.Println()

	// Prompt for confirmation
	prompt := tui.StyleAccent.Render("▸")
	if tui.IsPlainMode() {
		prompt = ">"
	}
	fmt.Printf("  %s Continue? [y/N] ", prompt)
	var response string
	_, _ = fmt.Scanln(&response) //nolint:errcheck // empty input means no

	if response != "y" && response != "Y" {
		tui.PrintInfo("Uninstall canceled")
		return
	}

	// Stop crust if running
	if running, pid := daemon.IsRunning(); running {
		tui.PrintInfo(fmt.Sprintf("Stopping crust [PID %d]...", pid))
		if err := daemon.Stop(); err != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to stop crust: %v", err))
		}
	}

	// Remove binary
	tui.PrintInfo("Removing binary...")
	if err := os.Remove(binaryPath); err != nil {
		if os.IsPermission(err) {
			// Try with sudo
			cmd := exec.CommandContext(context.Background(), "sudo", "rm", "-f", binaryPath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			if err := cmd.Run(); err != nil {
				tui.PrintError(fmt.Sprintf("Failed to remove binary: %v", err))
			}
		} else if !os.IsNotExist(err) {
			tui.PrintError(fmt.Sprintf("Failed to remove binary: %v", err))
		}
	}

	// Remove data directory
	tui.PrintInfo("Removing data directory...")
	if err := os.RemoveAll(dataDir); err != nil {
		tui.PrintError(fmt.Sprintf("Failed to remove data directory: %v", err))
	}

	fmt.Println()
	tui.PrintSuccess("Crust uninstalled")
}

// runLintRules handles the lint-rules subcommand - validates rule syntax and patterns
func runLintRules(args []string) {
	lintFlags := flag.NewFlagSet("lint-rules", flag.ExitOnError)
	showInfo := lintFlags.Bool("info", false, "Show informational messages")
	_ = lintFlags.Parse(args)

	linter := rules.NewLinter()
	var result rules.LintResult
	var err error

	remainingArgs := lintFlags.Args()
	if len(remainingArgs) > 0 {
		// Lint specific file
		filePath := remainingArgs[0]
		tui.PrintInfo(fmt.Sprintf("Linting %s...", filePath))
		fmt.Println()
		result, err = linter.LintFile(filePath)
	} else {
		// Lint all rules (builtin + user)
		tui.PrintInfo("Linting all rules...")

		// Load configuration
		cfg, cfgErr := config.Load(config.DefaultConfigPath())
		if cfgErr != nil {
			cfg = config.DefaultConfig()
		}

		rulesDir := cfg.Rules.UserDir
		if rulesDir == "" {
			rulesDir = rules.DefaultUserRulesDir()
		}

		// Load builtin rules
		loader := rules.NewLoader(rulesDir)
		builtinRules, loadErr := loader.LoadBuiltin()
		if loadErr != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to load builtin rules: %v", loadErr))
		}
		tui.PrintInfo(fmt.Sprintf("Builtin rules: %d", len(builtinRules)))

		// Load user rules
		userRules, loadErr := loader.LoadUser()
		if loadErr != nil {
			tui.PrintWarning(fmt.Sprintf("Failed to load user rules: %v", loadErr))
		}
		tui.PrintInfo(fmt.Sprintf("User rules: %d", len(userRules)))
		fmt.Println()

		allRules := slices.Concat(builtinRules, userRules)
		result = linter.LintRules(allRules)
	}

	if err != nil {
		tui.PrintError(err.Error())
		os.Exit(1)
	}

	// Print results
	fmt.Print(result.FormatIssues(*showInfo))

	// Summary
	fmt.Println()
	if result.Errors > 0 {
		tui.PrintError(fmt.Sprintf("%d error(s), %d warning(s)", result.Errors, result.Warns))
		os.Exit(1)
	} else if result.Warns > 0 {
		tui.PrintWarning(fmt.Sprintf("%d warning(s)", result.Warns))
	} else {
		tui.PrintSuccess("All rules valid")
	}
}

// runCompletion handles the completion subcommand
func runCompletion(args []string) {
	compFlags := flag.NewFlagSet("completion", flag.ExitOnError)
	doInstall := compFlags.Bool("install", false, "Install shell completion")
	doUninstall := compFlags.Bool("uninstall", false, "Remove shell completion")
	_ = compFlags.Parse(args)

	switch {
	case *doInstall:
		if completion.IsInstalled() {
			tui.PrintInfo("Shell completion is already installed")
			return
		}
		err := spinner.RunWithSpinner(
			"Installing shell completion",
			"Shell completion installed",
			completion.Install,
		)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Install failed: %v", err))
			os.Exit(1)
		}
		tui.PrintInfo("Restart your shell or source your profile to activate")

	case *doUninstall:
		err := spinner.RunWithSpinner(
			"Removing shell completion",
			"Shell completion removed",
			completion.Uninstall,
		)
		if err != nil {
			tui.PrintError(fmt.Sprintf("Uninstall failed: %v", err))
			os.Exit(1)
		}

	default:
		fmt.Println(tui.Separator("Shell Completion"))
		fmt.Println()
		status := tui.StyleError.Render("not installed")
		if completion.IsInstalled() {
			status = tui.StyleSuccess.Render("installed")
		}
		fmt.Printf("  %s  %s\n\n", tui.Faint("Status"), status)
		fmt.Print(tui.AlignColumns([][2]string{
			{"crust completion --install", "Install for detected shells (bash/zsh/fish)"},
			{"crust completion --uninstall", "Remove shell completion"},
		}, "  ", 2, tui.StyleCommand, tui.StyleMuted))
		fmt.Println()
	}
}

// colorProfileFromTERM maps a TERM value to a termenv color profile.
// Mirrors termenv's ColorProfile() logic for the common cases.
func colorProfileFromTERM(term string) termenv.Profile {
	switch term {
	case "":
		return termenv.Ascii
	case "dumb":
		return termenv.Ascii
	case "linux", "xterm":
		return termenv.ANSI
	}
	switch {
	case strings.Contains(term, "256color"):
		return termenv.ANSI256
	case strings.Contains(term, "color"), strings.Contains(term, "ansi"):
		return termenv.ANSI
	}
	// xterm-kitty, xterm-ghostty, alacritty, etc.
	return termenv.TrueColor
}
