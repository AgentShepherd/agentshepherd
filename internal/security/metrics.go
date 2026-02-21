package security

import (
	"sync/atomic"
)

// BlockingMetrics tracks blocking statistics for all layers.
type BlockingMetrics struct {
	// Layer 0: Request-side blocking (blocks bad agents before LLM sees request)
	Layer0Blocks atomic.Int64 // Requests blocked due to dangerous tool_calls in history

	// Layer 1: Response-side blocking (blocks dangerous LLM-generated tool calls)
	Layer1Blocks  atomic.Int64 // Tool calls blocked by rules
	Layer1Allowed atomic.Int64 // Tool calls allowed by rules

	// Totals
	TotalToolCalls atomic.Int64
}

var globalMetrics = &BlockingMetrics{}

// GetMetrics returns the global blocking metrics.
func GetMetrics() *BlockingMetrics {
	return globalMetrics
}

// GetStats returns a copy of current metrics.
func (m *BlockingMetrics) GetStats() map[string]int64 {
	return map[string]int64{
		"layer0_blocks":    m.Layer0Blocks.Load(),
		"layer1_blocks":    m.Layer1Blocks.Load(),
		"layer1_allowed":   m.Layer1Allowed.Load(),
		"total_tool_calls": m.TotalToolCalls.Load(),
	}
}

// Layer1BlockRate returns the percentage of calls blocked at Layer 1.
func (m *BlockingMetrics) Layer1BlockRate() float64 {
	total := m.TotalToolCalls.Load()
	if total == 0 {
		return 0
	}
	return float64(m.Layer1Blocks.Load()) / float64(total) * 100
}

// Reset clears all metrics (for testing).
func (m *BlockingMetrics) Reset() {
	m.Layer0Blocks.Store(0)
	m.Layer1Blocks.Store(0)
	m.Layer1Allowed.Store(0)
	m.TotalToolCalls.Store(0)
}
