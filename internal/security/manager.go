package security

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// Manager manages the security and telemetry module components
type Manager struct {
	storage       *telemetry.Storage
	interceptor   *Interceptor
	apiServer     *APIServer
	retentionDays int

	// Streaming buffering settings
	bufferStreaming bool
	maxBufferSize   int
	bufferTimeout   int
	blockMode       types.BlockMode

	apiHTTPServer *http.Server
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

var globalManager *Manager

// Config holds manager configuration
type Config struct {
	DBPath          string
	DBKey           string // Encryption key for SQLCipher
	APIPort         int
	SecurityEnabled bool
	RetentionDays   int // Data retention in days, 0 = forever
	// Streaming buffering settings
	BufferStreaming bool            // Enable response buffering for streaming requests
	MaxBufferSize   int             // Maximum SSE events to buffer
	BufferTimeout   int             // Buffer timeout in seconds
	BlockMode       types.BlockMode // types.BlockModeRemove (default) or types.BlockModeReplace
}

// Init initializes the manager
func Init(cfg Config) (*Manager, error) {
	// Initialize storage (with optional encryption)
	storage, err := telemetry.NewStorage(cfg.DBPath, cfg.DBKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Set global storage for telemetry
	telemetry.SetGlobalStorage(storage)

	// Default block mode to "remove" if not specified
	blockMode := cfg.BlockMode
	if blockMode == "" {
		blockMode = types.BlockModeRemove
	}

	m := &Manager{
		storage:         storage,
		retentionDays:   cfg.RetentionDays,
		bufferStreaming: cfg.BufferStreaming,
		maxBufferSize:   cfg.MaxBufferSize,
		bufferTimeout:   cfg.BufferTimeout,
		blockMode:       blockMode,
		stopChan:        make(chan struct{}),
	}

	// Run initial cleanup
	if cfg.RetentionDays > 0 {
		if deleted, err := storage.CleanupOldData(cfg.RetentionDays); err != nil {
			log.Warn("Initial cleanup failed: %v", err)
		} else if deleted > 0 {
			log.Info("Initial cleanup: removed %d old records", deleted)
		}
	}

	// Initialize interceptor if security is enabled and rules engine exists
	if cfg.SecurityEnabled {
		ruleEngine := rules.GetGlobalEngine()
		if ruleEngine != nil {
			m.interceptor = NewInterceptor(ruleEngine, storage)
		}
	}

	// Initialize API server
	m.apiServer = NewAPIServer(storage, m.interceptor)
	m.apiHTTPServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.APIPort),
		Handler:           m.apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if err := m.apiHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("API server error: %v", err)
		}
	}()

	// Start periodic cleanup if retention is enabled
	if cfg.RetentionDays > 0 {
		m.wg.Add(1)
		go m.cleanupLoop()
	}

	globalManager = m
	return m, nil
}

// cleanupLoop runs periodic data cleanup
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	// Run cleanup every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if m.retentionDays > 0 {
				if _, err := m.storage.CleanupOldData(m.retentionDays); err != nil {
					log.Warn("Periodic cleanup failed: %v", err)
				}
			}
		}
	}
}

// Shutdown shuts down the manager
func (m *Manager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}

	close(m.stopChan)

	if m.apiHTTPServer != nil {
		if err := m.apiHTTPServer.Shutdown(ctx); err != nil {
			log.Error("API server shutdown error: %v", err)
		}
	}

	m.wg.Wait()

	if m.storage != nil {
		if err := m.storage.Close(); err != nil {
			log.Error("Storage close error: %v", err)
		}
	}

	return nil
}

// GetInterceptor returns the interceptor
func (m *Manager) GetInterceptor() *Interceptor {
	if m == nil {
		return nil
	}
	return m.interceptor
}

// GetStorage returns the storage
func (m *Manager) GetStorage() *telemetry.Storage {
	if m == nil {
		return nil
	}
	return m.storage
}

// GetGlobalManager returns the global manager
func GetGlobalManager() *Manager {
	return globalManager
}

// GetGlobalInterceptor returns the global interceptor (convenience function)
func GetGlobalInterceptor() *Interceptor {
	if globalManager == nil {
		return nil
	}
	return globalManager.interceptor
}

// InterceptionConfig holds configuration for security interception
// Used for both non-streaming and buffered streaming responses
type InterceptionConfig struct {
	// BufferStreaming enables buffered streaming mode for SSE responses
	BufferStreaming bool
	MaxBufferSize   int
	BufferTimeout   int             // seconds
	BlockMode       types.BlockMode // types.BlockModeRemove or types.BlockModeReplace
}

// GetInterceptionConfig returns the security interception configuration
func GetInterceptionConfig() InterceptionConfig {
	if globalManager == nil {
		return InterceptionConfig{BlockMode: types.BlockModeRemove}
	}
	return InterceptionConfig{
		BufferStreaming: globalManager.bufferStreaming,
		MaxBufferSize:   globalManager.maxBufferSize,
		BufferTimeout:   globalManager.bufferTimeout,
		BlockMode:       globalManager.blockMode,
	}
}
