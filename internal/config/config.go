package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/types"
	"gopkg.in/yaml.v3"
)

var cfgLog = logger.New("config")

// Config represents the crust configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Storage   StorageConfig   `yaml:"storage"`
	API       APIConfig       `yaml:"api"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Security  SecurityConfig  `yaml:"security"`
	Rules     RulesConfig     `yaml:"rules"`
	Sandbox   SandboxConfig   `yaml:"sandbox"`
}

// SandboxConfig holds OS sandbox settings
type SandboxConfig struct {
	Enabled   bool   `yaml:"enabled"`    // enable OS-level sandbox (Landlock/Seatbelt)
	BPFHelper string `yaml:"bpf_helper"` // path to BPF helper Unix socket (Linux-only, optional)
}

// APIConfig holds management API settings
type APIConfig struct {
	Port int `yaml:"port"`
}

// ServerConfig holds server settings
type ServerConfig struct {
	Port     int    `yaml:"port"`
	LogLevel string `yaml:"log_level"`
	NoColor  bool   `yaml:"no_color"`
}

// UpstreamConfig holds upstream (downstream target) settings
type UpstreamConfig struct {
	// URL is the target to forward requests to (e.g., router or provider)
	URL string `yaml:"url"`
	// Timeout in seconds for upstream requests
	Timeout int `yaml:"timeout"`
	// APIKey for upstream authentication (set at runtime, not from config file)
	APIKey string `yaml:"-"`
	// Providers maps user-defined model keywords to base URLs (e.g. "my-llama": "http://localhost:11434/v1")
	Providers map[string]string `yaml:"providers"`
}

// StorageConfig holds unified database settings
type StorageConfig struct {
	DBPath        string `yaml:"db_path"`
	EncryptionKey string `yaml:"encryption_key"` // SQLCipher encryption key (empty = no encryption)
}

// TelemetryConfig holds telemetry settings
type TelemetryConfig struct {
	Enabled       bool    `yaml:"enabled"`
	RetentionDays int     `yaml:"retention_days"` // Data retention in days, 0 = forever
	ServiceName   string  `yaml:"service_name"`
	SampleRate    float64 `yaml:"sample_rate"`
}

// SecurityConfig holds security module settings
type SecurityConfig struct {
	Enabled         bool            `yaml:"enabled"`          // enable security interception (uses rules engine)
	BufferStreaming bool            `yaml:"buffer_streaming"` // enable response buffering for streaming requests
	MaxBufferSize   int             `yaml:"max_buffer_size"`  // maximum number of SSE events to buffer (default: 1000)
	BufferTimeout   int             `yaml:"buffer_timeout"`   // buffer timeout in seconds (default: 60)
	BlockMode       types.BlockMode `yaml:"block_mode"`       // "remove" (default) or "replace" (substitute with echo command)
}

// Validate validates the SecurityConfig and sets defaults.
func (c *SecurityConfig) Validate() error {
	// Validate and default BlockMode
	if c.BlockMode == "" {
		c.BlockMode = types.BlockModeRemove
	} else if !c.BlockMode.Valid() {
		return fmt.Errorf("invalid block_mode %q: must be 'remove' or 'replace'", c.BlockMode)
	}

	// Warn when security is enabled but streaming bypass is active
	if c.Enabled && !c.BufferStreaming {
		cfgLog.Warn("buffer_streaming is disabled: streaming responses will bypass security interception")
	}

	// Validate buffer settings when buffering is enabled
	if c.BufferStreaming {
		if c.MaxBufferSize <= 0 {
			return fmt.Errorf("max_buffer_size must be positive when buffer_streaming is enabled, got %d", c.MaxBufferSize)
		}
		if c.BufferTimeout <= 0 {
			return fmt.Errorf("buffer_timeout must be positive when buffer_streaming is enabled, got %d", c.BufferTimeout)
		}
	}

	return nil
}

// RulesConfig holds rule engine settings
type RulesConfig struct {
	Enabled        bool   `yaml:"enabled"`
	UserDir        string `yaml:"user_dir"`        // directory for user rules (default: ~/.crust/rules.d)
	DisableBuiltin bool   `yaml:"disable_builtin"` // disable embedded builtin rules
	Watch          bool   `yaml:"watch"`           // enable file watching for hot reload
}

// defaultDBPath returns the default database path under ~/.crust/.
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./crust.db"
	}
	return filepath.Join(home, ".crust", "crust.db")
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:     9090,
			LogLevel: "info",
			NoColor:  false,
		},
		Upstream: UpstreamConfig{
			URL:     "https://openrouter.ai/api",
			Timeout: 300,
		},
		Storage: StorageConfig{
			DBPath: defaultDBPath(),
		},
		API: APIConfig{
			Port: 9091,
		},
		Telemetry: TelemetryConfig{
			Enabled:       false, // disabled by default
			RetentionDays: 7,
			ServiceName:   "crust",
			SampleRate:    1.0,
		},
		Security: SecurityConfig{
			Enabled:         true,
			BufferStreaming: true, // enabled by default for security
			MaxBufferSize:   1000,
			BufferTimeout:   60,
			BlockMode:       types.BlockModeRemove,
		},
		Rules: RulesConfig{
			Enabled:        true,
			UserDir:        "", // empty means use default ~/.crust/rules.d
			DisableBuiltin: false,
			Watch:          true,
		},
		Sandbox: SandboxConfig{
			Enabled: false, // disabled by default - requires explicit opt-in
		},
	}
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Validate defaults before returning
			if err := cfg.Security.Validate(); err != nil {
				return nil, fmt.Errorf("config validation: %w", err)
			}
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Validate configuration
	if err := cfg.Security.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}
