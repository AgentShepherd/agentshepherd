package telemetry

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/telemetry/db"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	s, err := NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNewStorage_ForeignKeysEnabled(t *testing.T) {
	s := newTestStorage(t)

	var fk int
	if err := s.DB().QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}

func TestNewStorage_WALMode(t *testing.T) {
	s := newTestStorage(t)

	var mode string
	if err := s.DB().QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	// :memory: DBs may report "memory" instead of "wal", both are fine
	if mode != "wal" && mode != "memory" {
		t.Errorf("journal_mode = %q, want wal or memory", mode)
	}
}

func TestGetOrCreateTrace_NewTrace(t *testing.T) {
	s := newTestStorage(t)

	trace, err := s.GetOrCreateTrace("trace-1", "session-1")
	if err != nil {
		t.Fatalf("GetOrCreateTrace: %v", err)
	}
	if trace.TraceID != "trace-1" {
		t.Errorf("TraceID = %q, want trace-1", trace.TraceID)
	}
	if trace.SessionID != "session-1" {
		t.Errorf("SessionID = %q, want session-1", trace.SessionID)
	}
	if trace.ID == 0 {
		t.Error("trace ID should be > 0")
	}
}

func TestGetOrCreateTrace_ExistingTrace(t *testing.T) {
	s := newTestStorage(t)

	t1, err := s.GetOrCreateTrace("trace-1", "session-1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	t2, err := s.GetOrCreateTrace("trace-1", "session-1")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if t1.ID != t2.ID {
		t.Errorf("IDs differ: %d vs %d — should return same trace", t1.ID, t2.ID)
	}

	// Verify only 1 row in the table
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM traces WHERE trace_id = ?", "trace-1").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("trace count = %d, want 1", count)
	}
}

func TestGetOrCreateTrace_Concurrent(t *testing.T) {
	s := newTestStorage(t)

	const traceID = "concurrent-trace"
	const n = 3 // realistic: 1–3 sessions
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = s.GetOrCreateTrace(traceID, fmt.Sprintf("session-%d", idx))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Verify exactly 1 trace row
	var count int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM traces WHERE trace_id = ?", traceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("trace count = %d, want 1", count)
	}
}

func TestRecordSpanTx_Basic(t *testing.T) {
	s := newTestStorage(t)

	mainSpan := &Span{
		SpanID:    "span-1",
		Name:      "llm-call",
		SpanKind:  SpanKindLLM,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	toolSpan := &Span{
		SpanID:       "span-2",
		ParentSpanID: "span-1",
		Name:         "tool:Bash",
		SpanKind:     SpanKindTool,
		StartTime:    time.Now(),
		EndTime:      time.Now(),
		StatusCode:   "OK",
	}

	err := s.RecordSpanTx("trace-tx", "session-1", mainSpan, []*Span{toolSpan})
	if err != nil {
		t.Fatalf("RecordSpanTx: %v", err)
	}

	// Verify trace exists
	trace, err := s.GetOrCreateTrace("trace-tx", "session-1")
	if err != nil {
		t.Fatalf("GetOrCreateTrace after tx: %v", err)
	}
	if trace.EndTime.IsZero() {
		t.Error("trace end_time should be set after RecordSpanTx")
	}

	// Verify spans
	spans, err := s.GetTraceSpans("trace-tx")
	if err != nil {
		t.Fatalf("GetTraceSpans: %v", err)
	}
	if len(spans) != 2 {
		t.Errorf("span count = %d, want 2", len(spans))
	}
}

func TestRecordSpanTx_SetsTraceRowID(t *testing.T) {
	s := newTestStorage(t)

	mainSpan := &Span{
		SpanID:    "span-a",
		Name:      "test",
		SpanKind:  SpanKindLLM,
		StartTime: time.Now(),
		EndTime:   time.Now(),
	}

	if err := s.RecordSpanTx("trace-fk", "s1", mainSpan, nil); err != nil {
		t.Fatal(err)
	}

	// mainSpan.TraceRowID should be set by RecordSpanTx
	if mainSpan.TraceRowID == 0 {
		t.Error("mainSpan.TraceRowID should be set by RecordSpanTx")
	}
}

func TestForeignKeyCascade(t *testing.T) {
	s := newTestStorage(t)

	// Create trace + span
	trace, err := s.GetOrCreateTrace("cascade-test", "s1")
	if err != nil {
		t.Fatalf("GetOrCreateTrace: %v", err)
	}

	err = s.InsertSpan(&Span{
		TraceRowID: trace.ID,
		SpanID:     "span-1",
		Name:       "test-span",
		SpanKind:   SpanKindLLM,
		StartTime:  time.Now(),
		EndTime:    time.Now(),
	})
	if err != nil {
		t.Fatalf("InsertSpan: %v", err)
	}

	// Verify span exists
	var spanCount int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM spans WHERE trace_rowid = ?", trace.ID).Scan(&spanCount); err != nil {
		t.Fatal(err)
	}
	if spanCount != 1 {
		t.Fatalf("expected 1 span, got %d", spanCount)
	}

	// Delete the trace
	if _, err := s.DB().Exec("DELETE FROM traces WHERE trace_id = ?", "cascade-test"); err != nil {
		t.Fatalf("delete trace: %v", err)
	}

	// Span should be cascade-deleted
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM spans WHERE trace_rowid = ?", trace.ID).Scan(&spanCount); err != nil {
		t.Fatal(err)
	}
	if spanCount != 0 {
		t.Errorf("orphaned spans = %d, want 0 (CASCADE should delete them)", spanCount)
	}
}

func TestCleanupOldData_CascadesSpans(t *testing.T) {
	s := newTestStorage(t)

	// Insert a trace with old start_time
	oldTime := time.Now().Add(-48 * time.Hour)
	_, err := s.queries.CreateTrace(context.Background(), db.CreateTraceParams{
		TraceID:   "old-trace",
		SessionID: strPtr("s1"),
		StartTime: &oldTime,
	})
	if err != nil {
		t.Fatalf("CreateTrace: %v", err)
	}

	// Get trace to get its rowid
	trace, err := s.GetOrCreateTrace("old-trace", "s1")
	if err != nil {
		t.Fatal(err)
	}

	// Insert span linked to the old trace
	err = s.InsertSpan(&Span{
		TraceRowID: trace.ID,
		SpanID:     "old-span",
		Name:       "old-llm-call",
		SpanKind:   SpanKindLLM,
		StartTime:  oldTime,
		EndTime:    oldTime.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("InsertSpan: %v", err)
	}

	// Cleanup data older than 1 day
	deleted, err := s.CleanupOldData(1)
	if err != nil {
		t.Fatalf("CleanupOldData: %v", err)
	}
	if deleted == 0 {
		t.Error("expected some rows deleted")
	}

	// Both trace and span should be gone
	var traceCount, spanCount int
	_ = s.DB().QueryRow("SELECT COUNT(*) FROM traces WHERE trace_id = ?", "old-trace").Scan(&traceCount)
	_ = s.DB().QueryRow("SELECT COUNT(*) FROM spans WHERE span_id = ?", "old-span").Scan(&spanCount)

	if traceCount != 0 {
		t.Errorf("trace count = %d after cleanup, want 0", traceCount)
	}
	if spanCount != 0 {
		t.Errorf("span count = %d after cleanup, want 0 (CASCADE should delete)", spanCount)
	}
}

func TestConcurrentWriteAndRead(t *testing.T) {
	s := newTestStorage(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var writeErr, readErr error

	// Writer goroutine — simulates EndLLMSpan
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ctx.Err() == nil; i++ {
			traceID := fmt.Sprintf("trace-%d", i)
			mainSpan := &Span{
				SpanID:    fmt.Sprintf("s-%d", i),
				Name:      "llm",
				SpanKind:  SpanKindLLM,
				StartTime: time.Now(),
				EndTime:   time.Now(),
			}
			if err := s.RecordSpanTx(traceID, "session", mainSpan, nil); err != nil {
				writeErr = fmt.Errorf("write %d: %w", i, err)
				return
			}
		}
	}()

	// Reader goroutine — simulates dashboard polling
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			if _, err := s.GetTraceStats(); err != nil {
				readErr = fmt.Errorf("GetTraceStats: %w", err)
				return
			}
			if _, err := s.ListRecentTraces(10); err != nil {
				readErr = fmt.Errorf("ListRecentTraces: %w", err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	wg.Wait()

	if writeErr != nil {
		t.Errorf("writer error: %v", writeErr)
	}
	if readErr != nil {
		t.Errorf("reader error: %v", readErr)
	}
}

func TestGetSessions_GroupsBySessionID(t *testing.T) {
	s := newTestStorage(t)

	// Insert tool calls for two distinct sessions
	for i := range 3 {
		err := s.LogToolCall(ToolCallLog{
			TraceID:   fmt.Sprintf("trace-a-%d", i),
			SessionID: "session-alpha",
			ToolName:  "Read",
			Model:     "claude-opus-4-5",
		})
		if err != nil {
			t.Fatalf("LogToolCall session-alpha: %v", err)
		}
	}
	err := s.LogToolCall(ToolCallLog{
		TraceID:       "trace-b-0",
		SessionID:     "session-beta",
		ToolName:      "Bash",
		Model:         "gpt-4o",
		WasBlocked:    true,
		BlockedByRule: "protect-env",
	})
	if err != nil {
		t.Fatalf("LogToolCall session-beta: %v", err)
	}

	sessions, err := s.GetSessions(60, 50)
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("session count = %d, want 2", len(sessions))
	}

	// Sessions are ordered by last_seen DESC — both are recent so order may vary;
	// find each by SessionID.
	byID := make(map[string]SessionSummary, 2)
	for _, ss := range sessions {
		byID[ss.SessionID] = ss
	}

	alpha, ok := byID["session-alpha"]
	if !ok {
		t.Fatal("session-alpha not found")
	}
	if alpha.TotalCalls != 3 {
		t.Errorf("alpha.TotalCalls = %d, want 3", alpha.TotalCalls)
	}
	if alpha.BlockedCalls != 0 {
		t.Errorf("alpha.BlockedCalls = %d, want 0", alpha.BlockedCalls)
	}
	if alpha.Model != "claude-opus-4-5" {
		t.Errorf("alpha.Model = %q, want claude-opus-4-5", alpha.Model)
	}

	beta, ok := byID["session-beta"]
	if !ok {
		t.Fatal("session-beta not found")
	}
	if beta.TotalCalls != 1 {
		t.Errorf("beta.TotalCalls = %d, want 1", beta.TotalCalls)
	}
	if beta.BlockedCalls != 1 {
		t.Errorf("beta.BlockedCalls = %d, want 1", beta.BlockedCalls)
	}
}

func TestGetSessions_OrderedByLastSeenDesc(t *testing.T) {
	s := newTestStorage(t)

	// Insert with explicit timestamps so the ordering is deterministic.
	// session-old was active 30 minutes ago; session-new was just active.
	_, err := s.DB().Exec(`
		INSERT INTO tool_call_logs (trace_id, session_id, tool_name, timestamp)
		VALUES (?, ?, ?, datetime('now', '-30 minutes'))
	`, "trace-old", "session-old", "Read")
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB().Exec(`
		INSERT INTO tool_call_logs (trace_id, session_id, tool_name, timestamp)
		VALUES (?, ?, ?, datetime('now', '-1 minute'))
	`, "trace-new", "session-new", "Bash")
	if err != nil {
		t.Fatal(err)
	}

	sessions, err := s.GetSessions(60, 50)
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d", len(sessions))
	}
	// session-new has a later last_seen and should appear first.
	if sessions[0].SessionID != "session-new" {
		t.Errorf("first session = %q, want session-new (most recent)", sessions[0].SessionID)
	}
}

func TestGetSessions_ExcludesNullSessionID(t *testing.T) {
	s := newTestStorage(t)

	// Insert a log with no session_id (empty string → stored as NULL via strPtr)
	if err := s.LogToolCall(ToolCallLog{
		TraceID:  "trace-nosession",
		ToolName: "Read",
	}); err != nil {
		t.Fatal(err)
	}
	// Insert one with a real session
	if err := s.LogToolCall(ToolCallLog{
		TraceID:   "trace-with-session",
		SessionID: "real-session",
		ToolName:  "Write",
	}); err != nil {
		t.Fatal(err)
	}

	sessions, err := s.GetSessions(60, 50)
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	// Only the real session should appear
	if len(sessions) != 1 {
		t.Fatalf("session count = %d, want 1 (null session_id excluded)", len(sessions))
	}
	if sessions[0].SessionID != "real-session" {
		t.Errorf("session = %q, want real-session", sessions[0].SessionID)
	}
}

func TestGetSessionEvents_FiltersBySessionID(t *testing.T) {
	s := newTestStorage(t)

	// Insert events for two sessions
	for i := range 5 {
		if err := s.LogToolCall(ToolCallLog{
			TraceID:   fmt.Sprintf("trace-x-%d", i),
			SessionID: "session-x",
			ToolName:  "Read",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if err := s.LogToolCall(ToolCallLog{
			TraceID:   fmt.Sprintf("trace-y-%d", i),
			SessionID: "session-y",
			ToolName:  "Bash",
		}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := s.GetSessionEvents("session-x", 50)
	if err != nil {
		t.Fatalf("GetSessionEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("event count = %d, want 5", len(events))
	}
	for _, e := range events {
		if e.SessionID != "session-x" {
			t.Errorf("event SessionID = %q, want session-x", e.SessionID)
		}
	}
}

func TestGetSessionEvents_RespectsLimit(t *testing.T) {
	s := newTestStorage(t)

	for i := range 20 {
		if err := s.LogToolCall(ToolCallLog{
			TraceID:   fmt.Sprintf("trace-%d", i),
			SessionID: "session-limit",
			ToolName:  "Read",
		}); err != nil {
			t.Fatal(err)
		}
	}

	events, err := s.GetSessionEvents("session-limit", 5)
	if err != nil {
		t.Fatalf("GetSessionEvents: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("event count = %d, want 5 (limit enforced)", len(events))
	}
}

func TestGetSessionEvents_BlockedFieldPreserved(t *testing.T) {
	s := newTestStorage(t)

	if err := s.LogToolCall(ToolCallLog{
		TraceID:       "trace-blocked",
		SessionID:     "session-blocked",
		ToolName:      "Write",
		WasBlocked:    true,
		BlockedByRule: "my-rule",
		Layer:         "L1",
	}); err != nil {
		t.Fatal(err)
	}

	events, err := s.GetSessionEvents("session-blocked", 10)
	if err != nil {
		t.Fatalf("GetSessionEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, want 1", len(events))
	}
	e := events[0]
	if !e.WasBlocked {
		t.Error("WasBlocked = false, want true")
	}
	if e.BlockedByRule != "my-rule" {
		t.Errorf("BlockedByRule = %q, want my-rule", e.BlockedByRule)
	}
	if e.Layer != "L1" {
		t.Errorf("Layer = %q, want L1", e.Layer)
	}
}

func TestGetSessions_LimitEnforced(t *testing.T) {
	s := newTestStorage(t)

	for i := range 10 {
		if err := s.LogToolCall(ToolCallLog{
			TraceID:   fmt.Sprintf("trace-%d", i),
			SessionID: fmt.Sprintf("session-%d", i),
			ToolName:  "Read",
		}); err != nil {
			t.Fatal(err)
		}
	}

	sessions, err := s.GetSessions(60, 3)
	if err != nil {
		t.Fatalf("GetSessions: %v", err)
	}
	if len(sessions) != 3 {
		t.Fatalf("session count = %d, want 3 (limit enforced)", len(sessions))
	}
}

func TestLogToolCall_Concurrent(t *testing.T) {
	s := newTestStorage(t)

	var wg sync.WaitGroup
	const n = 3

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for range 10 {
				err := s.LogToolCall(ToolCallLog{
					TraceID:  fmt.Sprintf("trace-%d", idx),
					ToolName: "Bash",
					Layer:    "L1",
				})
				if err != nil {
					t.Errorf("LogToolCall(%d): %v", idx, err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	// Verify all 30 logs written
	var count int
	_ = s.DB().QueryRow("SELECT COUNT(*) FROM tool_call_logs").Scan(&count)
	if count != n*10 {
		t.Errorf("tool_call_logs count = %d, want %d", count, n*10)
	}
}
