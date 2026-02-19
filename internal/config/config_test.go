package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/types"
)

func TestSecurityConfig_Validate_Defaults(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Security.Validate(); err != nil {
		t.Fatalf("default config validation failed: %v", err)
	}
	if !cfg.Security.BufferStreaming {
		t.Error("BufferStreaming should default to true")
	}
	if !cfg.Security.Enabled {
		t.Error("Security.Enabled should default to true")
	}
}

func TestSecurityConfig_Validate_BufferStreamingDisabled(t *testing.T) {
	cfg := SecurityConfig{
		Enabled:         true,
		BufferStreaming: false,
		BlockMode:       "remove",
	}
	err := cfg.Validate()
	// Should not fail (user choice to disable), but logs a warning
	if err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestSecurityConfig_Validate_InvalidBlockMode(t *testing.T) {
	cfg := SecurityConfig{
		Enabled:         true,
		BufferStreaming: true,
		MaxBufferEvents: 1000,
		BufferTimeout:   60,
		BlockMode:       "invalid",
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid block_mode")
	}
}

func TestSecurityConfig_Validate_BadBufferSettings(t *testing.T) {
	cfg := SecurityConfig{
		Enabled:         true,
		BufferStreaming: true,
		MaxBufferEvents: 0, // invalid
		BufferTimeout:   60,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero MaxBufferEvents")
	}

	cfg2 := SecurityConfig{
		Enabled:         true,
		BufferStreaming: true,
		MaxBufferEvents: 1000,
		BufferTimeout:   0, // invalid
	}
	if err := cfg2.Validate(); err == nil {
		t.Error("expected error for zero BufferTimeout")
	}
}

func TestSecurityConfig_Validate_SecurityDisabledNoBufferCheck(t *testing.T) {
	// When security is disabled, buffer_streaming doesn't matter
	cfg := SecurityConfig{
		Enabled:         false,
		BufferStreaming: false,
		BlockMode:       "remove",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error when security disabled: %v", err)
	}
}

func TestDefaultConfig_Values(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.API.SocketPath != "" {
		t.Errorf("API.SocketPath should be empty (auto-derived), got %q", cfg.API.SocketPath)
	}
	if cfg.Sandbox.Enabled {
		t.Error("Sandbox should be disabled by default")
	}
	if cfg.Rules.DisableBuiltin {
		t.Error("Builtin rules should be enabled by default")
	}
}

// --- Config.Validate() tests ---

func TestValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should pass validation: %v", err)
	}
}

func TestValidate_PortRange(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Port = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "server.port") {
		t.Errorf("port 0 should fail: %v", err)
	}

	cfg = DefaultConfig()
	cfg.Server.Port = 99999
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "server.port") {
		t.Errorf("port 99999 should fail: %v", err)
	}

}

func TestValidate_LogLevel(t *testing.T) {
	cfg := DefaultConfig()

	// Valid levels
	for _, level := range []types.LogLevel{
		types.LogLevelTrace, types.LogLevelDebug, types.LogLevelInfo,
		types.LogLevelWarn, types.LogLevelError, "",
	} {
		cfg.Server.LogLevel = level
		if err := cfg.Validate(); err != nil {
			t.Errorf("log level %q should be valid: %v", level, err)
		}
	}

	// Invalid level
	cfg.Server.LogLevel = types.LogLevel("invalid")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Errorf("invalid log level should fail: %v", err)
	}
}

func TestValidate_UpstreamURL(t *testing.T) {
	cfg := DefaultConfig()

	// Empty is valid (auto mode)
	cfg.Upstream.URL = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty URL should be valid (auto mode): %v", err)
	}

	// http/https are valid
	cfg.Upstream.URL = "http://localhost:8080"
	if err := cfg.Validate(); err != nil {
		t.Errorf("http URL should be valid: %v", err)
	}
	cfg.Upstream.URL = "https://api.openai.com/v1"
	if err := cfg.Validate(); err != nil {
		t.Errorf("https URL should be valid: %v", err)
	}

	// ftp is invalid
	cfg.Upstream.URL = "ftp://bad"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "upstream.url") {
		t.Errorf("ftp URL should fail: %v", err)
	}
}

func TestValidate_Timeout(t *testing.T) {
	cfg := DefaultConfig()

	// 0 is valid (no timeout)
	cfg.Upstream.Timeout = 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("timeout 0 should be valid: %v", err)
	}

	// Negative is invalid
	cfg.Upstream.Timeout = -1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "upstream.timeout") {
		t.Errorf("negative timeout should fail: %v", err)
	}
}

func TestValidate_SampleRate(t *testing.T) {
	cfg := DefaultConfig()

	// Boundaries
	for _, rate := range []float64{0, 0.5, 1.0} {
		cfg.Telemetry.SampleRate = rate
		if err := cfg.Validate(); err != nil {
			t.Errorf("sample_rate %g should be valid: %v", rate, err)
		}
	}

	// Out of range
	cfg.Telemetry.SampleRate = -0.1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sample_rate") {
		t.Errorf("sample_rate -0.1 should fail: %v", err)
	}

	cfg.Telemetry.SampleRate = 1.5
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "sample_rate") {
		t.Errorf("sample_rate 1.5 should fail: %v", err)
	}
}

func TestValidate_RetentionDays(t *testing.T) {
	cfg := DefaultConfig()

	cfg.Telemetry.RetentionDays = -1
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "retention_days") {
		t.Errorf("retention_days -1 should fail: %v", err)
	}

	cfg.Telemetry.RetentionDays = 40000
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "retention_days") {
		t.Errorf("retention_days 40000 should fail: %v", err)
	}

	cfg.Telemetry.RetentionDays = 0 // 0 = forever, valid
	if err := cfg.Validate(); err != nil {
		t.Errorf("retention_days 0 should be valid: %v", err)
	}
}

func TestValidate_ProviderURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Upstream.Providers = map[string]string{
		"good": "http://localhost:11434/v1",
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid provider URL should pass: %v", err)
	}

	cfg.Upstream.Providers = map[string]string{
		"empty": "",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "upstream.providers.empty") {
		t.Errorf("empty provider URL should fail: %v", err)
	}

	cfg.Upstream.Providers = map[string]string{
		"bad": "ftp://nope",
	}
	err = cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "upstream.providers.bad") {
		t.Errorf("ftp provider URL should fail: %v", err)
	}
}

func TestValidate_BlockMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.BlockMode = types.BlockMode("garbage")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "block_mode") {
		t.Errorf("invalid block_mode should fail: %v", err)
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Port = 0
	cfg.Server.LogLevel = types.LogLevel("invalid")
	cfg.Upstream.Timeout = -1
	cfg.Telemetry.SampleRate = 5.0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected multiple errors")
	}
	errStr := err.Error()
	// Should collect all errors, not fail on first
	if !strings.Contains(errStr, "server.port") {
		t.Error("missing server.port error")
	}
	if !strings.Contains(errStr, "log_level") {
		t.Error("missing log_level error")
	}
	if !strings.Contains(errStr, "upstream.timeout") {
		t.Error("missing upstream.timeout error")
	}
	if !strings.Contains(errStr, "sample_rate") {
		t.Error("missing sample_rate error")
	}
}

func TestLoad_UnknownField(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// "servr" is a typo for "server"
	data := []byte("servr:\n  port: 8080\nserver:\n  port: 8080\n")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load with unknown field should warn, not fail: %v", err)
	}
	// The known "server.port" should still be parsed
	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
}

func TestDefaultConfigPath(t *testing.T) {
	p := DefaultConfigPath()
	if p == "" {
		t.Fatal("DefaultConfigPath should not be empty")
	}
	if !strings.HasSuffix(p, filepath.Join(".crust", "config.yaml")) {
		t.Errorf("DefaultConfigPath = %q, want suffix .crust/config.yaml", p)
	}
}

func TestLoad_FileNotExist(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("missing file should return defaults: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want default 9090", cfg.Server.Port)
	}
}
