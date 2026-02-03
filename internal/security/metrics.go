package security

import (
	"sync/atomic"
)

// BlockingMetrics tracks blocking statistics for all layers.
type BlockingMetrics struct {
	// Layer 0: Request-side blocking (blocks bad agents before LLM sees request)
	Layer0Blocks int64 // Requests blocked due to dangerous tool_calls in history

	// Layer 1: Response-side blocking (blocks dangerous LLM-generated tool calls)
	Layer1Blocks  int64 // Tool calls blocked by rules
	Layer1Allowed int64 // Tool calls allowed by rules

	// Layer 2: Sandbox blocking (kernel-level backstop)
	Layer2Blocks int64 // Commands blocked by sandbox (indicates rule gap)

	// Totals
	TotalToolCalls int64
}

var globalMetrics = &BlockingMetrics{}

// GetMetrics returns the global blocking metrics.
func GetMetrics() *BlockingMetrics {
	return globalMetrics
}

// RecordLayer0Block records a block at Layer 0 (request-side scanning).
// This blocks requests with dangerous tool_calls in message history.
func RecordLayer0Block() {
	atomic.AddInt64(&globalMetrics.Layer0Blocks, 1)
}

// RecordLayer1Block records a block at Layer 1 (response-side).
func RecordLayer1Block() {
	atomic.AddInt64(&globalMetrics.Layer1Blocks, 1)
	atomic.AddInt64(&globalMetrics.TotalToolCalls, 1)
}

// RecordLayer1Allow records an allow at Layer 1 (rule-based).
func RecordLayer1Allow() {
	atomic.AddInt64(&globalMetrics.Layer1Allowed, 1)
	atomic.AddInt64(&globalMetrics.TotalToolCalls, 1)
}

// RecordLayer2Block records a block at Layer 2 (sandbox).
// This indicates a rule gap - the sandbox caught something rules missed.
func RecordLayer2Block() {
	atomic.AddInt64(&globalMetrics.Layer2Blocks, 1)
	log.Warn("[RULE GAP] Sandbox blocked a command that passed Layer 1 rules")
}

// GetStats returns a copy of current metrics.
func (m *BlockingMetrics) GetStats() map[string]int64 {
	return map[string]int64{
		"layer0_blocks":    atomic.LoadInt64(&m.Layer0Blocks),
		"layer1_blocks":    atomic.LoadInt64(&m.Layer1Blocks),
		"layer1_allowed":   atomic.LoadInt64(&m.Layer1Allowed),
		"layer2_blocks":    atomic.LoadInt64(&m.Layer2Blocks),
		"total_tool_calls": atomic.LoadInt64(&m.TotalToolCalls),
	}
}

// Layer1BlockRate returns the percentage of calls blocked at Layer 1.
func (m *BlockingMetrics) Layer1BlockRate() float64 {
	total := atomic.LoadInt64(&m.TotalToolCalls)
	if total == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&m.Layer1Blocks)) / float64(total) * 100
}

// RuleGapRate returns the percentage of blocks that happened at Layer 2.
// High value indicates rules need improvement.
func (m *BlockingMetrics) RuleGapRate() float64 {
	l1 := atomic.LoadInt64(&m.Layer1Blocks)
	l2 := atomic.LoadInt64(&m.Layer2Blocks)
	total := l1 + l2
	if total == 0 {
		return 0
	}
	return float64(l2) / float64(total) * 100
}

// Reset clears all metrics (for testing).
func (m *BlockingMetrics) Reset() {
	atomic.StoreInt64(&m.Layer0Blocks, 0)
	atomic.StoreInt64(&m.Layer1Blocks, 0)
	atomic.StoreInt64(&m.Layer1Allowed, 0)
	atomic.StoreInt64(&m.Layer2Blocks, 0)
	atomic.StoreInt64(&m.TotalToolCalls, 0)
}
