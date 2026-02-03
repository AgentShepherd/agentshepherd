package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/AgentShepherd/agentshepherd/internal/config"
	"github.com/AgentShepherd/agentshepherd/internal/daemon"
	"github.com/AgentShepherd/agentshepherd/internal/logger"
	"github.com/AgentShepherd/agentshepherd/internal/proxy"
	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/sandbox"
	"github.com/AgentShepherd/agentshepherd/internal/security"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/tui"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// Version is set at build time via ldflags: -X main.Version=x.y.z
var Version = "1.0.0"

// =============================================================================
// API Client (inlined from internal/cli)
// =============================================================================

// apiClient provides API access for CLI commands
type apiClient struct {
	cfg     *config.Config
	baseURL string
}

// newAPIClient creates a new CLI API client
func newAPIClient(configPath string) *apiClient {
	cfg, err := config.Load(configPath)
	if err != nil {
		cfg = config.DefaultConfig()
	}
	return &apiClient{
		cfg:     cfg,
		baseURL: fmt.Sprintf("http://localhost:%d", cfg.API.Port),
	}
}

// proxyBaseURL returns the proxy base URL
func (c *apiClient) proxyBaseURL() string {
	return fmt.Sprintf("http://localhost:%d", c.cfg.Server.Port)
}

// checkHealth checks if the server is healthy
func (c *apiClient) checkHealth() (bool, error) {
	url := fmt.Sprintf("%s/health", c.proxyBaseURL())
	resp, err := http.Get(url) //nolint:gosec,noctx // URL is from trusted config
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// isServerRunning checks if the AgentShepherd server is running
func (c *apiClient) isServerRunning() bool {
	url := fmt.Sprintf("%s/api/agentshepherd/rules/reload", c.baseURL)
	resp, err := http.Post(url, "application/json", nil) //nolint:gosec,noctx // URL is from trusted config
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// reloadRules triggers a hot reload of rules
func (c *apiClient) reloadRules() ([]byte, error) {
	url := fmt.Sprintf("%s/api/agentshepherd/rules/reload", c.baseURL)
	resp, err := http.Post(url, "application/json", nil) //nolint:gosec,noctx // URL is from trusted config
	if err != nil {
		return nil, fmt.Errorf("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// getRules fetches all rules from the server
func (c *apiClient) getRules() ([]byte, error) {
	url := fmt.Sprintf("%s/api/agentshepherd/rules", c.baseURL)
	resp, err := http.Get(url) //nolint:gosec,noctx // URL is from trusted config
	if err != nil {
		return nil, fmt.Errorf("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// rulesResponse represents the API response for rules listing
type rulesResponse struct {
	Rules []ruleInfo `json:"rules"`
	Total int        `json:"total"`
}

// ruleInfo represents a single rule in the response (matches rules.Rule schema)
type ruleInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Operations  []string `json:"operations"`
	Message     string   `json:"message"`
	Source      string   `json:"source,omitempty"`
	FilePath    string   `json:"file_path,omitempty"`
	HitCount    int      `json:"hit_count,omitempty"`

	// Block patterns (simple rules)
	Block ruleBlock `json:"block"`

	// Advanced match (Level 4)
	Match *ruleMatch `json:"match,omitempty"`

	// Composite conditions (Level 5)
	AllConditions []ruleMatch `json:"all_conditions,omitempty"`
	AnyConditions []ruleMatch `json:"any_conditions,omitempty"`
}

// ruleBlock defines what paths/hosts to block
type ruleBlock struct {
	Paths  []string `json:"paths,omitempty"`
	Except []string `json:"except,omitempty"`
	Hosts  []string `json:"hosts,omitempty"`
}

// ruleMatch represents a single match condition
type ruleMatch struct {
	Path    string   `json:"path,omitempty"`
	Command string   `json:"command,omitempty"`
	Host    string   `json:"host,omitempty"`
	Content string   `json:"content,omitempty"`
	Tools   []string `json:"tools,omitempty"`
}

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
			runStatus()
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
		case "wrap":
			runWrap(os.Args[2:])
			return
		case "check-sandbox":
			runCheckSandbox()
			return
		case "repair-sandbox":
			runRepairSandbox()
			return
		case "help", "-h", "--help":
			printUsage()
			return
		case "version", "-v", "--version":
			fmt.Printf("agentshepherd version %s\n", Version)
			return
		}
	}

	// No subcommand - show help
	printUsage()
}

// runStart handles the start subcommand
func runStart(args []string) {
	// Check if already running
	if running, pid := daemon.IsRunning(); running {
		fmt.Printf("AgentShepherd is already running [PID %d]\n", pid)
		os.Exit(1)
	}

	// Parse flags
	startFlags := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := startFlags.String("config", "config.yaml", "Path to configuration file")
	logLevel := startFlags.String("log-level", "", "Log level: trace, debug, info, warn, error")
	noColor := startFlags.Bool("no-color", false, "Disable colored log output")
	disableBuiltin := startFlags.Bool("disable-builtin", false, "Disable builtin security rules")
	daemonMode := startFlags.Bool("daemon-mode", false, "Internal: indicates running as daemon")

	// Allow passing secrets via flags (for scripting)
	// SECURITY: Environment variables are preferred over CLI flags for secrets
	endpoint := startFlags.String("endpoint", "", "LLM API endpoint URL")
	apiKey := startFlags.String("api-key", "", "API key for the endpoint (prefer LLM_API_KEY env var)")
	dbKey := startFlags.String("db-key", "", "Database encryption key (prefer DB_KEY env var)")

	// Advanced options
	proxyPort := startFlags.Int("proxy-port", 0, "Proxy server port (default from config)")
	apiPort := startFlags.Int("api-port", 0, "API server port (default from config)")
	telemetryEnabled := startFlags.Bool("telemetry", false, "Enable telemetry")
	retentionDays := startFlags.Int("retention-days", 0, "Telemetry retention in days (0=use config default)")
	blockMode := startFlags.String("block-mode", "", "Block mode: remove (delete tool calls) or replace (substitute with echo)")

	_ = startFlags.Parse(args)

	// SECURITY: Load secrets from environment variables using envconfig
	// Environment variables are preferred over CLI flags (visible in ps auxww)
	secrets, err := config.LoadSecretsWithDefaults(*apiKey, *dbKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load secrets: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Check if we're in daemon mode (re-executed process)
	if *daemonMode || daemon.IsDaemonMode() {
		// We're the daemon process - run the server
		runDaemon(cfg, *logLevel, *noColor, *disableBuiltin, *endpoint, *apiKey, *dbKey,
			*proxyPort, *apiPort, *telemetryEnabled, *retentionDays, *blockMode)
		return
	}

	// Interactive mode - collect configuration via TUI
	var startupCfg tui.StartupConfig

	if *endpoint != "" && *apiKey != "" {
		// All required params provided via flags - skip TUI
		startupCfg = tui.StartupConfig{
			EndpointURL:         *endpoint,
			APIKey:              *apiKey,
			EncryptionKey:       *dbKey,
			TelemetryEnabled:    *telemetryEnabled,
			RetentionDays:       *retentionDays,
			DisableBuiltinRules: *disableBuiltin,
			ProxyPort:           *proxyPort,
			APIPort:             *apiPort,
		}
	} else {
		// Run TUI for configuration
		startupCfg, err = tui.RunStartupWithPorts(cfg.Upstream.URL, cfg.Server.Port, cfg.API.Port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}

		if startupCfg.Canceled {
			fmt.Println("Startup canceled.")
			os.Exit(0)
		}
	}

	// Build args for daemon process
	daemonArgs := []string{
		"start",
		"--config", *configPath,
		"--endpoint", startupCfg.EndpointURL,
		"--api-key", startupCfg.APIKey,
	}
	if startupCfg.EncryptionKey != "" {
		daemonArgs = append(daemonArgs, "--db-key", startupCfg.EncryptionKey)
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
		daemonArgs = append(daemonArgs, "--proxy-port", fmt.Sprintf("%d", startupCfg.ProxyPort))
	}
	if startupCfg.APIPort > 0 {
		daemonArgs = append(daemonArgs, "--api-port", fmt.Sprintf("%d", startupCfg.APIPort))
	}
	if startupCfg.TelemetryEnabled {
		daemonArgs = append(daemonArgs, "--telemetry=true")
	}
	if startupCfg.RetentionDays > 0 {
		daemonArgs = append(daemonArgs, "--retention-days", fmt.Sprintf("%d", startupCfg.RetentionDays))
	}
	if *blockMode != "" {
		daemonArgs = append(daemonArgs, "--block-mode", *blockMode)
	}

	// Daemonize
	pid, err := daemon.Daemonize(daemonArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %v\n", err)
		os.Exit(1)
	}

	// Wait a moment for the daemon to start
	time.Sleep(500 * time.Millisecond)

	// Verify it started
	if running, _ := daemon.IsRunning(); !running {
		fmt.Fprintln(os.Stderr, "Failed to start agentshepherd. Check logs:")
		fmt.Fprintf(os.Stderr, "  %s\n", daemon.LogFile())
		os.Exit(1)
	}

	fmt.Println()
	fmt.Printf("✓ AgentShepherd started [PID %d]\n", pid)
	fmt.Printf("  Logs: %s\n", daemon.LogFile())
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  agentshepherd status  - Check status")
	fmt.Println("  agentshepherd logs    - View logs")
	fmt.Println("  agentshepherd stop    - Stop agentshepherd")
}

// runDaemon runs the actual server (called in daemon process)
func runDaemon(cfg *config.Config, logLevel string, noColor, disableBuiltin bool, endpoint, apiKey, dbKey string,
	proxyPort, apiPort int, telemetryEnabled bool, retentionDays int, blockMode string) {
	// Write PID file
	if err := daemon.WritePID(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write PID file: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = daemon.RemovePID() }()

	// Configure logger
	if logLevel != "" {
		logger.SetGlobalLevelFromString(logLevel)
	} else {
		logger.SetGlobalLevelFromString(cfg.Server.LogLevel)
	}
	// Always disable color in daemon mode (no terminal)
	logger.SetColored(false)

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
	if apiPort > 0 {
		cfg.API.Port = apiPort
	}
	cfg.Telemetry.Enabled = telemetryEnabled
	if retentionDays > 0 {
		cfg.Telemetry.RetentionDays = retentionDays
	}
	if blockMode != "" {
		cfg.Security.BlockMode = types.BlockMode(blockMode)
	}

	log.Info("Starting AgentShepherd daemon...")

	// Initialize rules engine
	var ruleWatcher *rules.Watcher
	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	if cfg.Rules.Enabled {
		engineCfg := rules.EngineConfig{
			UserRulesDir:   rulesDir,
			DisableBuiltin: cfg.Rules.DisableBuiltin,
			APIPort:        cfg.API.Port,
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

		// Initialize sandbox mapper and sync with rules (if enabled)
		if cfg.Sandbox.Enabled {
			if !sandbox.IsSupported() {
				log.Warn("Sandbox enabled but not supported on this platform: %s", sandbox.Platform())
			} else {
				sandboxMapper := sandbox.NewMapper(sandbox.DefaultProfilePath())
				allRules := ruleEngine.GetAllRules()
				if err := sandboxMapper.Sync(allRules); err != nil {
					log.Warn("Failed to sync sandbox profile: %v", err)
				} else {
					log.Info("Sandbox profile synced: %d rules mapped", sandboxMapper.RuleCount())
				}

				// Register callback to sync sandbox on rule reload
				ruleEngine.OnReload(func(reloadedRules []rules.Rule) {
					if err := sandboxMapper.Sync(reloadedRules); err != nil {
						log.Warn("Failed to sync sandbox profile on reload: %v", err)
					} else {
						log.Debug("Sandbox profile synced after reload: %d rules", sandboxMapper.RuleCount())
					}
				})
			}
		} else {
			log.Debug("Sandbox disabled (set sandbox.enabled=true to enable)")
		}
	}

	// Initialize manager
	managerCfg := security.Config{
		DBPath:          cfg.Storage.DBPath,
		DBKey:           cfg.Storage.EncryptionKey,
		APIPort:         cfg.API.Port,
		SecurityEnabled: cfg.Security.Enabled,
		RetentionDays:   cfg.Telemetry.RetentionDays,
		BufferStreaming: cfg.Security.BufferStreaming,
		MaxBufferSize:   cfg.Security.MaxBufferSize,
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
	proxyHandler, err := proxy.NewProxy(cfg.Upstream.URL, cfg.Upstream.APIKey, time.Duration(cfg.Upstream.Timeout)*time.Second)
	if err != nil {
		log.Error("Failed to create proxy: %v", err)
		os.Exit(1)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/", proxyHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: loggingMiddleware(mux),
		// SECURITY FIX: Add ReadHeaderTimeout to prevent Slowloris attacks
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.Upstream.Timeout) * time.Second,
		WriteTimeout:      time.Duration(cfg.Upstream.Timeout) * time.Second,
	}

	log.Info("AgentShepherd listening on :%d", cfg.Server.Port)
	log.Info("  Upstream: %s", cfg.Upstream.URL)
	log.Info("  API: :%d", cfg.API.Port)

	// Start server
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Server error: %v", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown: %v", err)
		os.Exit(1)
	}

	log.Info("AgentShepherd stopped")
}

// runStop handles the stop subcommand
func runStop() {
	running, pid := daemon.IsRunning()
	if !running {
		fmt.Println("AgentShepherd is not running")
		return
	}

	fmt.Printf("Stopping agentshepherd [PID %d]...\n", pid)

	if err := daemon.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("AgentShepherd stopped")
}

// runStatus handles the status subcommand
func runStatus() {
	running, pid := daemon.IsRunning()
	if !running {
		fmt.Println("AgentShepherd is not running")
		return
	}

	fmt.Printf("AgentShepherd is running [PID %d]\n", pid)

	// Try to get health from API
	client := newAPIClient("config.yaml")
	if healthy, _ := client.checkHealth(); healthy { //nolint:errcheck // error means unhealthy
		fmt.Println("  Status: healthy")
	}

	// Show log file location
	fmt.Printf("  Logs: %s\n", daemon.LogFile())
}

// runLogs handles the logs subcommand
func runLogs(args []string) {
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

	if *follow {
		// Use tail -f
		fmt.Printf("Following %s (Ctrl+C to stop)...\n\n", logFile)
		cmd := exec.Command("tail", "-f", logFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run() //nolint:errcheck // user will see tail output/errors
	} else {
		// Show last N lines
		cmd := exec.Command("tail", "-n", fmt.Sprintf("%d", *lines), logFile) //nolint:gosec // G204: args are from trusted flag parsing
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "No logs found. Is agentshepherd running?\n")
		}
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
	fmt.Println(`AgentShepherd - Secure gateway for AI agents

Usage:
  agentshepherd start [flags]        Start agentshepherd (interactive or with flags)
  agentshepherd stop                 Stop agentshepherd
  agentshepherd status               Check if agentshepherd is running
  agentshepherd logs [-f] [-n N]     View logs (-f to follow, -n for line count)

  agentshepherd add-rule <file.yaml>    Add a rule file to user rules
  agentshepherd remove-rule <filename>  Remove a user rule file
  agentshepherd list-rules [--json]     List all active rules
  agentshepherd reload-rules            Trigger hot reload of rules
  agentshepherd lint-rules [file.yaml]  Validate rule syntax and patterns

  agentshepherd wrap [--dry-run] <cmd>  Run command in OS sandbox
  agentshepherd check-sandbox           Verify rule-sandbox consistency
  agentshepherd repair-sandbox          Regenerate sandbox profile from rules

  agentshepherd uninstall            Uninstall agentshepherd completely
  agentshepherd help                 Show this help message
  agentshepherd version              Show version

Start Flags:
  --config string       Path to configuration file (default "config.yaml")
  --endpoint string     LLM API endpoint URL (skip interactive prompt)
  --api-key string      API key for the endpoint (skip interactive prompt)
  --db-key string       Database encryption key (optional)
  --log-level string    Log level: trace, debug, info, warn, error
  --no-color            Disable colored log output
  --disable-builtin     Disable builtin security rules
  --proxy-port int      Proxy server port (default from config)
  --api-port int        API server port (default from config)
  --telemetry           Enable/disable telemetry (default false)
  --retention-days int  Telemetry retention in days (0=forever)

Environment Variables (preferred for secrets):
  LLM_API_KEY    API key for the LLM endpoint
  DB_KEY         Database encryption key

Examples:
  agentshepherd start                              Interactive setup
  LLM_API_KEY=sk-xxx agentshepherd start --endpoint https://openrouter.ai/api/v1
  agentshepherd logs -f                            Follow logs
  agentshepherd stop                               Stop agentshepherd`)
}

// runAddRule handles the add-rule subcommand
func runAddRule(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentshepherd add-rule <file.yaml>")
		os.Exit(1)
	}

	filePath := args[0]
	client := newAPIClient("config.yaml")
	serverRunning := client.isServerRunning()

	// Read and validate rule file
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.ValidateYAML(data); err != nil {
		fmt.Fprintf(os.Stderr, "Validation error: %v\n", err)
		os.Exit(1)
	}

	destPath, err := loader.AddRuleFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error adding rule file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Rule file added: %s\n", destPath)

	if serverRunning {
		if _, err := client.reloadRules(); err == nil {
			fmt.Println("Hot reload triggered successfully")
		}
	} else {
		fmt.Println("Note: AgentShepherd is not running. Rules will be loaded on next start.")
	}
}

// runRemoveRule handles the remove-rule subcommand
func runRemoveRule(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentshepherd remove-rule <filename>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Remove a user rule file from ~/.agentshepherd/rules.d/")
		fmt.Fprintln(os.Stderr, "Use 'agentshepherd list-rules' to see available rules.")
		os.Exit(1)
	}

	filename := args[0]
	client := newAPIClient("config.yaml")
	serverRunning := client.isServerRunning()

	loader := rules.NewLoader(rules.DefaultUserRulesDir())
	if err := loader.RemoveRuleFile(filename); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing rule file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Rule file removed: %s\n", filename)

	if serverRunning {
		if _, err := client.reloadRules(); err == nil {
			fmt.Println("Hot reload triggered successfully")
		}
	} else {
		fmt.Println("Note: AgentShepherd is not running. Rules will be updated on next start.")
	}
}

// runListRules handles the list-rules subcommand
func runListRules(args []string) {
	listFlags := flag.NewFlagSet("list-rules", flag.ExitOnError)
	jsonOutput := listFlags.Bool("json", false, "Output as JSON")
	_ = listFlags.Parse(args)

	client := newAPIClient("config.yaml")
	body, err := client.getRules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: AgentShepherd is not running")
		fmt.Fprintln(os.Stderr, "Start it first with: agentshepherd start")
		os.Exit(1)
	}

	if *jsonOutput {
		fmt.Println(string(body))
		return
	}

	// Parse and format output
	rulesResp, err := client.getRulesParsed()
	if err != nil {
		fmt.Println(string(body))
		return
	}

	// Colors
	green := "\033[32m"
	yellow := "\033[33m"
	red := "\033[31m"
	cyan := "\033[36m"
	gray := "\033[90m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Printf("%s%sAgentShepherd Rules%s (%d total)\n\n", bold, cyan, reset, rulesResp.Total)

	// Group by source
	builtinRules := []ruleInfo{}
	userRulesByFile := make(map[string][]ruleInfo)
	for _, r := range rulesResp.Rules {
		if r.Source == "builtin" {
			builtinRules = append(builtinRules, r)
		} else {
			filename := filepath.Base(r.FilePath)
			if filename == "" || filename == "." {
				filename = "(unknown)"
			}
			userRulesByFile[filename] = append(userRulesByFile[filename], r)
		}
	}

	printRule := func(r ruleInfo, prefix string) {
		// Severity color
		sevColor := gray
		sev := r.Severity
		if sev == "" {
			sev = "critical"
		}
		switch sev {
		case "critical":
			sevColor = red
		case "warning":
			sevColor = yellow
		case "info":
			sevColor = cyan
		}

		// Status (Enabled is a pointer, nil means true)
		enabled := r.Enabled == nil || *r.Enabled
		status := green + "✓" + reset
		if !enabled {
			status = gray + "○" + reset
		}

		// Format operations
		ops := strings.Join(r.Operations, ",")
		if ops == "" {
			ops = "all"
		}

		fmt.Printf("%s%s %s%s%s\n", prefix, status, bold, r.Name, reset)

		// Show description or message
		desc := r.Description
		if desc == "" {
			desc = r.Message
		}
		if desc != "" {
			fmt.Printf("%s  %s%s%s\n", prefix, gray, desc, reset)
		}

		// Show what's being blocked
		var targets []string
		targets = append(targets, r.Block.Paths...)
		for _, h := range r.Block.Hosts {
			targets = append(targets, "host:"+h)
		}
		if r.Match != nil {
			if r.Match.Path != "" {
				targets = append(targets, r.Match.Path)
			}
			if r.Match.Command != "" {
				targets = append(targets, "cmd:"+r.Match.Command)
			}
			if r.Match.Host != "" {
				targets = append(targets, "host:"+r.Match.Host)
			}
		}
		if len(r.AllConditions) > 0 {
			targets = append(targets, fmt.Sprintf("all(%d conditions)", len(r.AllConditions)))
		}
		if len(r.AnyConditions) > 0 {
			targets = append(targets, fmt.Sprintf("any(%d conditions)", len(r.AnyConditions)))
		}

		// Truncate targets display if too long
		targetStr := ""
		if len(targets) > 0 {
			targetStr = targets[0]
			if len(targets) > 1 {
				targetStr = fmt.Sprintf("%s (+%d more)", targets[0], len(targets)-1)
			}
			// Truncate long patterns
			if len(targetStr) > 40 {
				targetStr = targetStr[:37] + "..."
			}
		}

		fmt.Printf("%s  %s%-8s%s  ⊘ %-12s  %s%s%s  hits: %d\n",
			prefix, sevColor, sev, reset,
			ops,
			gray, targetStr, reset,
			r.HitCount)

		// Show exceptions if any
		if len(r.Block.Except) > 0 {
			fmt.Printf("%s  %sexcept: %s%s\n", prefix, gray, strings.Join(r.Block.Except, ", "), reset)
		}
	}

	// Print builtin rules
	if len(builtinRules) > 0 {
		fmt.Printf("%sBuiltin Rules:%s\n\n", bold, reset)
		for _, r := range builtinRules {
			printRule(r, "  ")
			fmt.Println()
		}
	}

	// Print user rules grouped by file
	fmt.Printf("%sUser Rules:%s\n", bold, reset)
	if len(userRulesByFile) == 0 {
		fmt.Printf("  %s(none)%s\n", gray, reset)
		fmt.Printf("  Add rules with: agentshepherd add-rule <file.yaml>\n")
	} else {
		// Sort filenames for consistent output
		filenames := make([]string, 0, len(userRulesByFile))
		for f := range userRulesByFile {
			filenames = append(filenames, f)
		}
		sort.Strings(filenames)

		for _, filename := range filenames {
			rules := userRulesByFile[filename]
			fmt.Printf("\n  %s[%s]%s\n", cyan, filename, reset)
			for i, r := range rules {
				prefix := "    ├─ "
				if i == len(rules)-1 {
					prefix = "    └─ "
				}
				printRule(r, prefix)
			}
		}
	}
	fmt.Println()
}

// runReloadRules handles the reload-rules subcommand
func runReloadRules(_ []string) {
	client := newAPIClient("config.yaml")
	body, err := client.reloadRules()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: AgentShepherd is not running")
		fmt.Fprintln(os.Stderr, "Start it first with: agentshepherd start")
		os.Exit(1)
	}
	fmt.Println(string(body))
}

// runUninstall handles the uninstall subcommand
func runUninstall() {
	binaryPath := "/usr/local/bin/agentshepherd"
	dataDir := daemon.DataDir()

	fmt.Println("This will remove:")
	fmt.Printf("  - %s\n", binaryPath)
	fmt.Printf("  - %s/ (logs, rules, database)\n", dataDir)
	fmt.Println()

	// Prompt for confirmation
	fmt.Print("Continue? [y/N] ")
	var response string
	_, _ = fmt.Scanln(&response) //nolint:errcheck // empty input means no

	if response != "y" && response != "Y" {
		fmt.Println("Uninstall canceled.")
		return
	}

	// Stop agentshepherd if running
	if running, pid := daemon.IsRunning(); running {
		fmt.Printf("Stopping agentshepherd [PID %d]...\n", pid)
		if err := daemon.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to stop agentshepherd: %v\n", err)
		}
	}

	// Remove binary
	fmt.Println("Removing binary...")
	if err := os.Remove(binaryPath); err != nil {
		if os.IsPermission(err) {
			// Try with sudo
			cmd := exec.Command("sudo", "rm", "-f", binaryPath)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Stdin = os.Stdin
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to remove binary: %v\n", err)
			}
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Failed to remove binary: %v\n", err)
		}
	}

	// Remove data directory
	fmt.Println("Removing data directory...")
	if err := os.RemoveAll(dataDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to remove data directory: %v\n", err)
	}

	fmt.Println()
	fmt.Println("AgentShepherd uninstalled.")
}

// runWrap handles the wrap subcommand - runs a command in OS sandbox
func runWrap(args []string) {
	wrapFlags := flag.NewFlagSet("wrap", flag.ExitOnError)
	dryRun := wrapFlags.Bool("dry-run", false, "Preview sandbox profile without executing")
	_ = wrapFlags.Parse(args)

	remainingArgs := wrapFlags.Args()
	if len(remainingArgs) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: agentshepherd wrap [--dry-run] <command> [args...]")
		os.Exit(1)
	}

	// Check platform support - AgentShepherd requires Linux 5.13+ (Landlock) or macOS
	if !sandbox.IsSupported() {
		fmt.Fprintf(os.Stderr, "FATAL: Sandbox not supported on this platform\n")
		fmt.Fprintf(os.Stderr, "Platform info: %s\n", sandbox.Platform())
		fmt.Fprintf(os.Stderr, "AgentShepherd requires Linux 5.13+ with Landlock or macOS.\n")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	// Initialize sandbox mapper
	profilePath := sandbox.DefaultProfilePath()
	mapper := sandbox.NewMapper(profilePath)

	// Load all path-based rules and generate sandbox profile
	loader := rules.NewLoader(rulesDir)
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load builtin rules: %v\n", err)
	}

	userRules, err := loader.LoadUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load user rules: %v\n", err)
	}

	allRules := append(builtinRules, userRules...)

	// Add rules to mapper
	for _, rule := range allRules {
		if rule.IsEnabled() {
			if err := mapper.AddRule(rule); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Failed to map rule %s: %v\n", rule.Name, err)
			}
		}
	}

	if *dryRun {
		// Preview mode - show profile and exit
		fmt.Printf("Sandbox Platform: %s\n\n", sandbox.Platform())
		profile, err := mapper.GetProfile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading profile: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Generated Sandbox Profile:")
		fmt.Println("---")
		fmt.Print(string(profile))
		fmt.Println("---")
		fmt.Printf("\nWould execute: %v\n", remainingArgs)
		return
	}

	// Create sandbox and execute
	sb := sandbox.New(mapper)
	exitCode, err := sb.Wrap(remainingArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sandbox error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(exitCode)
}

// runCheckSandbox handles the check-sandbox subcommand - verifies rule-sandbox consistency
func runCheckSandbox() {
	// Load configuration first to check if sandbox is enabled
	cfg, err := config.Load("config.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Skip check if sandbox is disabled
	if !cfg.Sandbox.Enabled {
		fmt.Println("Sandbox is disabled in config - skipping consistency check")
		return
	}

	if !sandbox.IsSupported() {
		fmt.Fprintf(os.Stderr, "FATAL: Sandbox not supported (%s). Requires Linux 5.13+ or macOS.\n", sandbox.Platform())
		os.Exit(1)
	}

	fmt.Printf("Checking sandbox consistency...\n")
	fmt.Printf("Platform: %s\n\n", sandbox.Platform())

	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	// Load all path-based rules
	loader := rules.NewLoader(rulesDir)
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load builtin rules: %v\n", err)
	}

	userRules, err := loader.LoadUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load user rules: %v\n", err)
	}

	allRules := append(builtinRules, userRules...)

	// Load sandbox mapper
	profilePath := sandbox.DefaultProfilePath()
	mapper := sandbox.NewMapper(profilePath)
	if err := mapper.LoadFromFile(); err != nil {
		// Profile doesn't exist - that's OK, we'll create it
		fmt.Printf("Note: No sandbox profile found at %s\n", profilePath)
		fmt.Printf("Run 'agentshepherd repair-sandbox' to generate one.\n")
		return
	}

	// Check consistency
	if err := mapper.CheckConsistency(allRules); err != nil {
		fmt.Fprintf(os.Stderr, "Inconsistency detected: %v\n\n", err)
		fmt.Println("Run 'agentshepherd repair-sandbox' to fix")
		os.Exit(1)
	}

	fmt.Println("✓ Rules and sandbox mappings are consistent")
}

// runRepairSandbox handles the repair-sandbox subcommand - regenerates sandbox profile from rules
func runRepairSandbox() {
	// Load configuration first to check if sandbox is enabled
	cfg, err := config.Load("config.yaml")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Skip repair if sandbox is disabled
	if !cfg.Sandbox.Enabled {
		fmt.Println("Sandbox is disabled in config - skipping repair")
		return
	}

	if !sandbox.IsSupported() {
		fmt.Fprintf(os.Stderr, "FATAL: Sandbox not supported (%s). Requires Linux 5.13+ or macOS.\n", sandbox.Platform())
		os.Exit(1)
	}

	fmt.Printf("Repairing sandbox profile...\n")
	fmt.Printf("Platform: %s\n\n", sandbox.Platform())

	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	// Load all path-based rules
	loader := rules.NewLoader(rulesDir)
	builtinRules, err := loader.LoadBuiltin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load builtin rules: %v\n", err)
	}

	userRules, err := loader.LoadUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load user rules: %v\n", err)
	}

	allRules := append(builtinRules, userRules...)

	// Create new sandbox mapper and repair
	profilePath := sandbox.DefaultProfilePath()
	mapper := sandbox.NewMapper(profilePath)

	if err := mapper.Repair(allRules); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to repair sandbox: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Sandbox profile regenerated at %s\n", profilePath)
	fmt.Printf("  Mapped %d rules\n", len(allRules))
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
		fmt.Printf("Linting %s...\n\n", filePath)
		result, err = linter.LintFile(filePath)
	} else {
		// Lint all rules (builtin + user)
		fmt.Println("Linting all rules...")

		// Load configuration
		cfg, cfgErr := config.Load("config.yaml")
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
			fmt.Fprintf(os.Stderr, "Warning: Failed to load builtin rules: %v\n", loadErr)
		}
		fmt.Printf("Builtin rules: %d\n", len(builtinRules))

		// Load user rules
		userRules, loadErr := loader.LoadUser()
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load user rules: %v\n", loadErr)
		}
		fmt.Printf("User rules: %d\n", len(userRules))
		fmt.Println()

		allRules := append(builtinRules, userRules...)
		result = linter.LintRules(allRules)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Print(result.FormatIssues(*showInfo))

	// Summary
	fmt.Println()
	if result.Errors > 0 {
		fmt.Printf("✗ %d error(s), %d warning(s)\n", result.Errors, result.Warns)
		os.Exit(1)
	} else if result.Warns > 0 {
		fmt.Printf("⚠ %d warning(s)\n", result.Warns)
	} else {
		fmt.Println("✓ All rules valid")
	}
}
