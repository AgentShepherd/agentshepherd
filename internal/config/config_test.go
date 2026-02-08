package config

import (
	"testing"
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
		MaxBufferSize:   1000,
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
		MaxBufferSize:   0, // invalid
		BufferTimeout:   60,
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero MaxBufferSize")
	}

	cfg2 := SecurityConfig{
		Enabled:         true,
		BufferStreaming: true,
		MaxBufferSize:   1000,
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
	if cfg.API.Port != 9091 {
		t.Errorf("API.Port = %d, want 9091", cfg.API.Port)
	}
	if cfg.Sandbox.Enabled {
		t.Error("Sandbox should be disabled by default")
	}
	if cfg.Rules.DisableBuiltin {
		t.Error("Builtin rules should be enabled by default")
	}
}
