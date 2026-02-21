package security

import (
	"encoding/json"
	"testing"
)

func TestMetricsCountAccuracy(t *testing.T) {
	globalMetrics.Reset()

	// 3 Layer 0 blocked events
	for range 3 {
		RecordEvent(Event{
			Layer:      LayerL0,
			ToolName:   "Read",
			Arguments:  json.RawMessage(`{"path":"/etc/shadow"}`),
			WasBlocked: true,
			RuleName:   "test-rule",
		})
	}

	// 2 Layer 1 blocked events (one non-streaming, one buffered)
	RecordEvent(Event{
		Layer:      LayerL1,
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"rm -rf /"}`),
		WasBlocked: true,
		RuleName:   "test-rule",
	})
	RecordEvent(Event{
		Layer:      LayerL1Buffer,
		ToolName:   "Write",
		Arguments:  json.RawMessage(`{"path":"/etc/passwd"}`),
		WasBlocked: true,
		RuleName:   "test-rule",
	})

	// 1 Layer 1 allowed event
	RecordEvent(Event{
		Layer:      LayerL1,
		ToolName:   "Read",
		Arguments:  json.RawMessage(`{"path":"README.md"}`),
		WasBlocked: false,
	})

	m := GetMetrics()

	if got := m.Layer0Blocks.Load(); got != 3 {
		t.Errorf("Layer0Blocks = %d, want 3", got)
	}
	if got := m.Layer1Blocks.Load(); got != 2 {
		t.Errorf("Layer1Blocks = %d, want 2", got)
	}
	if got := m.Layer1Allowed.Load(); got != 1 {
		t.Errorf("Layer1Allowed = %d, want 1", got)
	}
	if got := m.TotalToolCalls.Load(); got != 6 {
		t.Errorf("TotalToolCalls = %d, want 6", got)
	}
}

func TestMetricsReset(t *testing.T) {
	m := GetMetrics()

	// Populate counters
	m.Layer0Blocks.Add(5)
	m.Layer1Blocks.Add(3)
	m.Layer1Allowed.Add(7)
	m.TotalToolCalls.Add(15)

	m.Reset()

	if got := m.Layer0Blocks.Load(); got != 0 {
		t.Errorf("Layer0Blocks after reset = %d, want 0", got)
	}
	if got := m.Layer1Blocks.Load(); got != 0 {
		t.Errorf("Layer1Blocks after reset = %d, want 0", got)
	}
	if got := m.Layer1Allowed.Load(); got != 0 {
		t.Errorf("Layer1Allowed after reset = %d, want 0", got)
	}
	if got := m.TotalToolCalls.Load(); got != 0 {
		t.Errorf("TotalToolCalls after reset = %d, want 0", got)
	}
}

func TestBlockedTotal(t *testing.T) {
	globalMetrics.Reset()

	// Record events at different layers
	RecordEvent(Event{Layer: LayerL0, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Bash", WasBlocked: true, RuleName: "r2"})
	RecordEvent(Event{Layer: LayerL1Stream, ToolName: "Write", WasBlocked: true, RuleName: "r3"})
	RecordEvent(Event{Layer: LayerL1Buffer, ToolName: "Edit", WasBlocked: true, RuleName: "r4"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Read", WasBlocked: false})

	m := GetMetrics()
	blocked := m.Layer0Blocks.Load() + m.Layer1Blocks.Load()

	if blocked != 4 {
		t.Errorf("total blocked = %d, want 4", blocked)
	}
	if got := m.TotalToolCalls.Load(); got != 5 {
		t.Errorf("TotalToolCalls = %d, want 5", got)
	}

	// Verify invariant: total = blocked + allowed
	allowed := m.Layer1Allowed.Load()
	if blocked+allowed != m.TotalToolCalls.Load() {
		t.Errorf("invariant broken: blocked(%d) + allowed(%d) != total(%d)", blocked, allowed, m.TotalToolCalls.Load())
	}
}

func TestGetStatsMap(t *testing.T) {
	globalMetrics.Reset()

	RecordEvent(Event{Layer: LayerL0, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Bash", WasBlocked: true, RuleName: "r2"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Read", WasBlocked: false})

	stats := GetMetrics().GetStats()

	if stats["total_tool_calls"] != 3 {
		t.Errorf("total_tool_calls = %d, want 3", stats["total_tool_calls"])
	}
	if stats["layer0_blocks"] != 1 {
		t.Errorf("layer0_blocks = %d, want 1", stats["layer0_blocks"])
	}
	if stats["layer1_blocks"] != 1 {
		t.Errorf("layer1_blocks = %d, want 1", stats["layer1_blocks"])
	}
	if stats["layer1_allowed"] != 1 {
		t.Errorf("layer1_allowed = %d, want 1", stats["layer1_allowed"])
	}
}

func TestLayer0NonBlockedDroppedFromMetrics(t *testing.T) {
	globalMetrics.Reset()

	// Non-blocked L0 events shouldn't happen in practice.
	// They are silently dropped to preserve the invariant:
	//   TotalToolCalls == Layer0Blocks + Layer1Blocks + Layer1Allowed
	RecordEvent(Event{Layer: LayerL0, ToolName: "Read", WasBlocked: false})

	m := GetMetrics()
	if got := m.Layer0Blocks.Load(); got != 0 {
		t.Errorf("Layer0Blocks = %d, want 0", got)
	}
	if got := m.TotalToolCalls.Load(); got != 0 {
		t.Errorf("TotalToolCalls = %d, want 0 (non-blocked L0 dropped)", got)
	}
}

func TestInvariantTotalEqualsSubcounters(t *testing.T) {
	globalMetrics.Reset()

	// Mix of all layer types
	RecordEvent(Event{Layer: LayerL0, ToolName: "Read", WasBlocked: true, RuleName: "r1"})
	RecordEvent(Event{Layer: LayerL0, ToolName: "Write", WasBlocked: true, RuleName: "r2"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Bash", WasBlocked: true, RuleName: "r3"})
	RecordEvent(Event{Layer: LayerL1, ToolName: "Read", WasBlocked: false})
	RecordEvent(Event{Layer: LayerL1Stream, ToolName: "Write", WasBlocked: true, RuleName: "r4"})
	RecordEvent(Event{Layer: LayerL1Stream, ToolName: "Edit", WasBlocked: false})
	RecordEvent(Event{Layer: LayerL1Buffer, ToolName: "Bash", WasBlocked: true, RuleName: "r5"})
	// Non-blocked L0 should be silently dropped:
	RecordEvent(Event{Layer: LayerL0, ToolName: "Read", WasBlocked: false})

	m := GetMetrics()
	sum := m.Layer0Blocks.Load() + m.Layer1Blocks.Load() + m.Layer1Allowed.Load()

	if m.TotalToolCalls.Load() != sum {
		t.Errorf("invariant broken: TotalToolCalls(%d) != L0(%d)+L1B(%d)+L1A(%d) = %d",
			m.TotalToolCalls.Load(), m.Layer0Blocks.Load(), m.Layer1Blocks.Load(),
			m.Layer1Allowed.Load(), sum)
	}
	if m.TotalToolCalls.Load() != 7 {
		t.Errorf("TotalToolCalls = %d, want 7 (1 non-blocked L0 dropped)", m.TotalToolCalls.Load())
	}
}
