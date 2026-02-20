package config

import (
	"errors"
	"fmt"

	"github.com/kelseyhightower/envconfig"
)

// Secrets holds sensitive configuration loaded from environment variables
// SECURITY: Use environment variables instead of CLI flags for secrets
// CLI flags are visible in process listings (ps auxww)
type Secrets struct {
	// LLMAPIKey is the upstream LLM API key
	// Env: LLM_API_KEY
	LLMAPIKey string `envconfig:"LLM_API_KEY"`

	// DBKey is the SQLCipher database encryption key
	// Env: DB_KEY
	DBKey string `envconfig:"DB_KEY"`
}

// LoadSecrets loads secrets from environment variables
func LoadSecrets() (*Secrets, error) {
	var s Secrets
	if err := envconfig.Process("", &s); err != nil {
		return nil, fmt.Errorf("failed to load secrets from environment: %w", err)
	}
	return &s, nil
}

// LoadSecretsWithDefaults loads secrets, using provided defaults if env vars not set
func LoadSecretsWithDefaults(apiKey, dbKey string) (*Secrets, error) {
	s, err := LoadSecrets()
	if err != nil {
		return nil, err
	}

	// Use provided defaults if env vars not set
	if s.LLMAPIKey == "" {
		s.LLMAPIKey = apiKey
	}
	if s.DBKey == "" {
		s.DBKey = dbKey
	}

	return s, nil
}

// Validate validates that required secrets are set
func (s *Secrets) Validate() error {
	if s.LLMAPIKey == "" {
		return errors.New("LLM API key is required (set LLM_API_KEY or use --api-key flag)")
	}
	// Note: No minimum length validation - local LLM setups (vLLM, Ollama) may use dummy keys
	return nil
}

// ValidateDBKey validates the database encryption key if set
func (s *Secrets) ValidateDBKey() error {
	if s.DBKey != "" && len(s.DBKey) < 16 {
		return errors.New("database encryption key must be at least 16 characters")
	}
	return nil
}

// HasDBEncryption returns true if database encryption is configured
func (s *Secrets) HasDBEncryption() bool {
	return s.DBKey != ""
}

// MaskLLMAPIKey returns a masked version of the LLM API key for logging
func (s *Secrets) MaskLLMAPIKey() string {
	if s.LLMAPIKey == "" {
		return "(not set)"
	}
	if len(s.LLMAPIKey) <= 8 {
		return "****"
	}
	return s.LLMAPIKey[:4] + "****" + s.LLMAPIKey[len(s.LLMAPIKey)-4:]
}
