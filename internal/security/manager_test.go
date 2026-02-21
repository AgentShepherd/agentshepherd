package security

import (
	"sync"
	"testing"

	"github.com/BakeLens/crust/internal/types"
)

func saveGlobalManager(t *testing.T) {
	t.Helper()
	orig := globalManager
	t.Cleanup(func() {
		globalManagerMu.Lock()
		globalManager = orig
		globalManagerMu.Unlock()
	})
}

func TestGetInterceptionConfig_RaceFree(t *testing.T) {
	saveGlobalManager(t)

	SetGlobalManager(nil)

	var wg sync.WaitGroup
	const goroutines = 100

	// Half the goroutines read the config
	for range goroutines / 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				cfg := GetInterceptionConfig()
				_ = cfg.BlockMode
			}
		}()
	}

	// Half the goroutines write the manager
	for range goroutines / 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				m := &Manager{
					bufferStreaming: true,
					maxBufferEvents: 500,
					bufferTimeout:   30,
					blockMode:       types.BlockModeReplace,
					stopChan:        make(chan struct{}),
				}
				SetGlobalManager(m)
				SetGlobalManager(nil)
			}
		}()
	}

	wg.Wait()
}

func TestGetInterceptionConfig_NilManager(t *testing.T) {
	saveGlobalManager(t)

	SetGlobalManager(nil)
	cfg := GetInterceptionConfig()
	if cfg.BlockMode != types.BlockModeRemove {
		t.Errorf("nil manager: BlockMode = %q, want %q", cfg.BlockMode, types.BlockModeRemove)
	}
	if cfg.BufferStreaming {
		t.Error("nil manager: BufferStreaming should be false")
	}
}

func TestGetInterceptionConfig_ReadsValues(t *testing.T) {
	saveGlobalManager(t)

	m := &Manager{
		bufferStreaming: true,
		maxBufferEvents: 42,
		bufferTimeout:   99,
		blockMode:       types.BlockModeReplace,
		stopChan:        make(chan struct{}),
	}
	SetGlobalManager(m)

	cfg := GetInterceptionConfig()
	if !cfg.BufferStreaming {
		t.Error("BufferStreaming should be true")
	}
	if cfg.MaxBufferEvents != 42 {
		t.Errorf("MaxBufferEvents = %d, want 42", cfg.MaxBufferEvents)
	}
	if cfg.BufferTimeout != 99 {
		t.Errorf("BufferTimeout = %d, want 99", cfg.BufferTimeout)
	}
	if cfg.BlockMode != types.BlockModeReplace {
		t.Errorf("BlockMode = %q, want %q", cfg.BlockMode, types.BlockModeReplace)
	}
}
