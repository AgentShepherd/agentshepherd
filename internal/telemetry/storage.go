package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/telemetry/db"
	"github.com/BakeLens/crust/internal/types"
	_ "github.com/mutecomm/go-sqlcipher/v4" // SQLCipher driver for encrypted SQLite
)

var log = logger.New("telemetry")

// Storage handles SQLite/SQLCipher database operations
type Storage struct {
	conn      *sql.DB
	queries   *db.Queries
	encrypted bool
}

// MinEncryptionKeyLength is the minimum required length for encryption keys
const MinEncryptionKeyLength = 16

// NewStorage creates a new storage instance with optional encryption
func NewStorage(dbPath string, encryptionKey string) (*Storage, error) {
	// Build connection string with parameters
	params := url.Values{}
	params.Set("_busy_timeout", "5000")
	params.Set("_journal_mode", "WAL")

	// SECURITY FIX: Pass encryption key via connection string parameter
	// instead of PRAGMA statement to prevent SQL injection
	if encryptionKey != "" {
		// SECURITY: Validate encryption key strength
		if len(encryptionKey) < MinEncryptionKeyLength {
			return nil, fmt.Errorf("encryption key must be at least %d characters", MinEncryptionKeyLength)
		}
		params.Set("_pragma_key", encryptionKey)
	}

	dsn := dbPath + "?" + params.Encode()

	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Verify encryption is working by running a simple query
	encrypted := false
	if encryptionKey != "" {
		var result int
		if err := conn.QueryRow("SELECT 1").Scan(&result); err != nil {
			conn.Close()
			return nil, fmt.Errorf("encryption key verification failed: %w", err)
		}
		encrypted = true
		log.Info("Database encryption enabled")
	}

	s := &Storage{
		conn:      conn,
		queries:   db.New(conn),
		encrypted: encrypted,
	}

	if err := s.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

// IsEncrypted returns whether the database is encrypted
func (s *Storage) IsEncrypted() bool {
	return s.encrypted
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.conn.Close()
}

// DB returns the underlying database connection
func (s *Storage) DB() *sql.DB {
	return s.conn
}

// Queries returns the sqlc queries interface
func (s *Storage) Queries() *db.Queries {
	return s.queries
}

func (s *Storage) initSchema() error {
	// Read schema from embedded file or inline
	schemaFile := "internal/telemetry/schema.sql"
	schema, err := os.ReadFile(schemaFile)
	if err != nil {
		// Fallback to inline schema if file not found
		schema = []byte(inlineSchema)
	}

	_, err = s.conn.Exec(string(schema))
	return err
}

// inlineSchema is a fallback if schema.sql is not found
const inlineSchema = `
CREATE TABLE IF NOT EXISTS traces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_id TEXT NOT NULL UNIQUE,
	session_id TEXT,
	start_time DATETIME,
	end_time DATETIME,
	metadata JSON,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_traces_trace_id ON traces(trace_id);
CREATE INDEX IF NOT EXISTS idx_traces_session_id ON traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_start_time ON traces(start_time);

CREATE TABLE IF NOT EXISTS spans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_rowid INTEGER REFERENCES traces(id) ON DELETE CASCADE,
	span_id TEXT NOT NULL,
	parent_span_id TEXT,
	name TEXT NOT NULL,
	span_kind TEXT,
	start_time DATETIME,
	end_time DATETIME,
	attributes JSON,
	events JSON,
	input_tokens INTEGER DEFAULT 0,
	output_tokens INTEGER DEFAULT 0,
	status_code TEXT DEFAULT 'UNSET',
	status_message TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_spans_trace_rowid ON spans(trace_rowid);
CREATE INDEX IF NOT EXISTS idx_spans_span_id ON spans(span_id);
CREATE INDEX IF NOT EXISTS idx_spans_parent_span_id ON spans(parent_span_id);
CREATE INDEX IF NOT EXISTS idx_spans_start_time ON spans(start_time);
CREATE INDEX IF NOT EXISTS idx_spans_span_kind ON spans(span_kind);

CREATE TABLE IF NOT EXISTS tool_call_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	trace_id TEXT NOT NULL,
	session_id TEXT,
	tool_name TEXT NOT NULL,
	tool_arguments TEXT,
	api_type TEXT,
	was_blocked BOOLEAN DEFAULT FALSE,
	blocked_by_rule TEXT,
	model TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_timestamp ON tool_call_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_trace_id ON tool_call_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_tool_name ON tool_call_logs(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_was_blocked ON tool_call_logs(was_blocked);
`

// =============================================================================
// API Types (wrappers over db types with non-nullable fields for JSON)
// =============================================================================

// Trace represents a trace record (wraps db.Trace for compatibility)
type Trace struct {
	ID        int64           `json:"id"`
	TraceID   string          `json:"trace_id"`
	SessionID string          `json:"session_id,omitempty"`
	StartTime time.Time       `json:"start_time"`
	EndTime   time.Time       `json:"end_time"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// Span represents a span record (wraps db.Span for compatibility)
type Span struct {
	ID            int64           `json:"id"`
	TraceRowID    int64           `json:"trace_rowid"`
	SpanID        string          `json:"span_id"`
	ParentSpanID  string          `json:"parent_span_id,omitempty"`
	Name          string          `json:"name"`
	SpanKind      string          `json:"span_kind"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       time.Time       `json:"end_time"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	Events        json.RawMessage `json:"events,omitempty"`
	InputTokens   int64           `json:"input_tokens"`
	OutputTokens  int64           `json:"output_tokens"`
	StatusCode    string          `json:"status_code"`
	StatusMessage string          `json:"status_message,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ToolCallLog represents a logged tool call
type ToolCallLog struct {
	ID            int64           `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	TraceID       string          `json:"trace_id"`
	SessionID     string          `json:"session_id,omitempty"`
	ToolName      string          `json:"tool_name"`
	ToolArguments json.RawMessage `json:"tool_arguments,omitempty"`
	APIType       types.APIType   `json:"api_type"`
	WasBlocked    bool            `json:"was_blocked"`
	BlockedByRule string          `json:"blocked_by_rule,omitempty"`
	Model         string          `json:"model,omitempty"`
}

// Stats represents security statistics
type Stats struct {
	TotalToolCalls   int64            `json:"total_tool_calls"`
	BlockedToolCalls int64            `json:"blocked_tool_calls"`
	TopBlockedTools  []ToolStat       `json:"top_blocked_tools"`
	RecentActivity   []ActivityWindow `json:"recent_activity"`
}

// ToolStat represents statistics for a specific tool
type ToolStat struct {
	ToolName     string `json:"tool_name"`
	TotalCalls   int64  `json:"total_calls"`
	BlockedCalls int64  `json:"blocked_calls"`
}

// ActivityWindow represents activity within a time window
type ActivityWindow struct {
	Window       string `json:"window"`
	TotalCalls   int64  `json:"total_calls"`
	BlockedCalls int64  `json:"blocked_calls"`
}

// =============================================================================
// Trace Operations (using sqlc)
// =============================================================================

// GetOrCreateTrace gets an existing trace or creates a new one
func (s *Storage) GetOrCreateTrace(traceID string, sessionID string) (*Trace, error) {
	ctx := context.Background()

	// Try to get existing trace
	dbTrace, err := s.queries.GetTraceByID(ctx, traceID)
	if err == nil {
		return dbTraceToTrace(&dbTrace), nil
	}

	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to query trace: %w", err)
	}

	// Create new trace
	now := time.Now().UTC()
	rowID, err := s.queries.CreateTrace(ctx, db.CreateTraceParams{
		TraceID:   traceID,
		SessionID: strPtr(sessionID),
		StartTime: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create trace: %w", err)
	}

	// Return constructed trace (we know the values we just inserted)
	return &Trace{
		ID:        rowID,
		TraceID:   traceID,
		SessionID: sessionID,
		StartTime: now,
	}, nil
}

// UpdateTraceEndTime updates the end time of a trace
func (s *Storage) UpdateTraceEndTime(traceID string, endTime time.Time) error {
	ctx := context.Background()
	t := endTime.UTC()
	return s.queries.UpdateTraceEndTime(ctx, db.UpdateTraceEndTimeParams{
		TraceID: traceID,
		EndTime: &t,
	})
}

// InsertSpan inserts a new span
func (s *Storage) InsertSpan(span *Span) error {
	ctx := context.Background()

	id, err := s.queries.InsertSpan(ctx, db.InsertSpanParams{
		TraceRowid:    int64Ptr(span.TraceRowID),
		SpanID:        span.SpanID,
		ParentSpanID:  strPtr(span.ParentSpanID),
		Name:          span.Name,
		SpanKind:      strPtr(span.SpanKind),
		StartTime:     timePtr(span.StartTime),
		EndTime:       timePtr(span.EndTime),
		Attributes:    span.Attributes,
		Events:        span.Events,
		InputTokens:   int64Ptr(span.InputTokens),
		OutputTokens:  int64Ptr(span.OutputTokens),
		StatusCode:    strPtr(span.StatusCode),
		StatusMessage: strPtr(span.StatusMessage),
	})
	if err != nil {
		return fmt.Errorf("failed to insert span: %w", err)
	}

	span.ID = id
	return nil
}

// GetTraceSpans returns all spans for a trace
func (s *Storage) GetTraceSpans(traceID string) ([]Span, error) {
	ctx := context.Background()

	dbSpans, err := s.queries.GetTraceSpans(ctx, traceID)
	if err != nil {
		return nil, fmt.Errorf("failed to query spans: %w", err)
	}

	spans := make([]Span, len(dbSpans))
	for i, dbSpan := range dbSpans {
		spans[i] = dbSpanToSpan(&dbSpan)
	}

	return spans, nil
}

// ListRecentTraces returns recent traces
func (s *Storage) ListRecentTraces(limit int) ([]Trace, error) {
	ctx := context.Background()

	if limit <= 0 {
		limit = 100
	}

	dbTraces, err := s.queries.ListRecentTraces(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to query traces: %w", err)
	}

	traces := make([]Trace, len(dbTraces))
	for i, dbTrace := range dbTraces {
		traces[i] = *dbTraceToTrace(&dbTrace)
	}

	return traces, nil
}

// GetTelemetryStats returns telemetry statistics
func (s *Storage) GetTelemetryStats() (map[string]interface{}, error) {
	ctx := context.Background()
	stats := make(map[string]interface{})

	// Total traces and spans
	traceCount, err := s.queries.GetTraceCount(ctx)
	if err != nil {
		log.Debug("Failed to get trace count: %v", err)
	}
	spanCount, err := s.queries.GetSpanCount(ctx)
	if err != nil {
		log.Debug("Failed to get span count: %v", err)
	}
	stats["total_traces"] = traceCount
	stats["total_spans"] = spanCount

	// Token totals
	tokenTotals, err := s.queries.GetTokenTotals(ctx)
	if err != nil {
		log.Debug("Failed to get token totals: %v", err)
	}
	stats["total_input_tokens"] = tokenTotals.TotalInput
	stats["total_output_tokens"] = tokenTotals.TotalOutput

	// Spans by kind
	spansByKind, err := s.queries.GetSpansByKind(ctx)
	if err == nil {
		kindMap := make(map[string]int64)
		for _, row := range spansByKind {
			if row.SpanKind != nil {
				kindMap[*row.SpanKind] = row.Count
			}
		}
		stats["spans_by_kind"] = kindMap
	}

	return stats, nil
}

// =============================================================================
// Tool Call Logging (using sqlc)
// =============================================================================

// LogToolCall logs a tool call
func (s *Storage) LogToolCall(toolLog ToolCallLog) error {
	ctx := context.Background()

	var argsStr *string
	if toolLog.ToolArguments != nil {
		str := string(toolLog.ToolArguments)
		argsStr = &str
	}

	return s.queries.LogToolCall(ctx, db.LogToolCallParams{
		TraceID:       toolLog.TraceID,
		SessionID:     strPtr(toolLog.SessionID),
		ToolName:      toolLog.ToolName,
		ToolArguments: argsStr,
		ApiType:       strPtr(string(toolLog.APIType)),
		WasBlocked:    &toolLog.WasBlocked,
		BlockedByRule: strPtr(toolLog.BlockedByRule),
		Model:         strPtr(toolLog.Model),
	})
}

// MaxRecentMinutes is the maximum time window for recent logs (7 days)
const MaxRecentMinutes = 10080

// GetRecentLogs returns recent tool call logs
func (s *Storage) GetRecentLogs(minutes int, limit int) ([]ToolCallLog, error) {
	ctx := context.Background()

	if limit <= 0 {
		limit = 100
	}

	// SECURITY FIX: Validate minutes parameter
	if minutes <= 0 {
		minutes = 60
	} else if minutes > MaxRecentMinutes {
		minutes = MaxRecentMinutes
	}

	dbLogs, err := s.queries.GetRecentToolCallLogs(ctx, db.GetRecentToolCallLogsParams{
		Datetime: fmt.Sprintf("-%d minutes", minutes),
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get recent logs: %w", err)
	}

	logs := make([]ToolCallLog, len(dbLogs))
	for i, dbLog := range dbLogs {
		logs[i] = dbToolCallLogToToolCallLog(&dbLog)
	}

	return logs, nil
}

// GetStats returns security statistics
func (s *Storage) GetStats() (*Stats, error) {
	ctx := context.Background()
	stats := &Stats{}

	// Total and blocked tool calls
	toolStats, err := s.queries.GetToolCallStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool call counts: %w", err)
	}
	stats.TotalToolCalls = toolStats.Total
	if blocked, ok := toolStats.Blocked.(int64); ok {
		stats.BlockedToolCalls = blocked
	}

	// Top blocked tools
	topBlocked, err := s.queries.GetTopBlockedTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get top blocked tools: %w", err)
	}

	for _, row := range topBlocked {
		blockedCalls := int64(0)
		if row.BlockedCalls != nil {
			blockedCalls = int64(*row.BlockedCalls)
		}
		stats.TopBlockedTools = append(stats.TopBlockedTools, ToolStat{
			ToolName:     row.ToolName,
			TotalCalls:   row.TotalCalls,
			BlockedCalls: blockedCalls,
		})
	}

	// Note: RecentActivity query was removed due to sqlc limitations
	// Can be added back with raw SQL if needed

	return stats, nil
}

// MaxRetentionDays is the maximum allowed retention period
const MaxRetentionDays = 36500 // 100 years

// CleanupOldData deletes data older than the specified number of days
func (s *Storage) CleanupOldData(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}

	// SECURITY FIX: Validate days parameter to prevent integer overflow
	if days > MaxRetentionDays {
		days = MaxRetentionDays
	}

	ctx := context.Background()
	var totalDeleted int64
	timeOffset := fmt.Sprintf("-%d days", days)

	// Delete old tool call logs
	result, err := s.queries.DeleteOldToolCallLogs(ctx, timeOffset)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old tool call logs: %w", err)
	}
	deleted, _ := result.RowsAffected()
	totalDeleted += deleted

	// Delete old spans
	result, err = s.queries.DeleteOldSpans(ctx, timeOffset)
	if err != nil {
		return totalDeleted, fmt.Errorf("failed to delete old spans: %w", err)
	}
	deleted, _ = result.RowsAffected()
	totalDeleted += deleted

	// Delete old traces
	result, err = s.queries.DeleteOldTraces(ctx, timeOffset)
	if err != nil {
		return totalDeleted, fmt.Errorf("failed to delete old traces: %w", err)
	}
	deleted, _ = result.RowsAffected()
	totalDeleted += deleted

	if totalDeleted > 0 {
		log.Info("Cleaned up %d old records (retention: %d days)", totalDeleted, days)
	}

	return totalDeleted, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func int64Ptr(i int64) *int64 {
	return &i
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt64(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func dbTraceToTrace(t *db.Trace) *Trace {
	return &Trace{
		ID:        t.ID,
		TraceID:   t.TraceID,
		SessionID: derefStr(t.SessionID),
		StartTime: derefTime(t.StartTime),
		EndTime:   derefTime(t.EndTime),
		Metadata:  t.Metadata,
		CreatedAt: derefTime(t.CreatedAt),
	}
}

func dbSpanToSpan(s *db.Span) Span {
	return Span{
		ID:            s.ID,
		TraceRowID:    derefInt64(s.TraceRowid),
		SpanID:        s.SpanID,
		ParentSpanID:  derefStr(s.ParentSpanID),
		Name:          s.Name,
		SpanKind:      derefStr(s.SpanKind),
		StartTime:     derefTime(s.StartTime),
		EndTime:       derefTime(s.EndTime),
		Attributes:    s.Attributes,
		Events:        s.Events,
		InputTokens:   derefInt64(s.InputTokens),
		OutputTokens:  derefInt64(s.OutputTokens),
		StatusCode:    derefStr(s.StatusCode),
		StatusMessage: derefStr(s.StatusMessage),
		CreatedAt:     derefTime(s.CreatedAt),
	}
}

func dbToolCallLogToToolCallLog(l *db.ToolCallLog) ToolCallLog {
	var args json.RawMessage
	if l.ToolArguments != nil {
		args = json.RawMessage(*l.ToolArguments)
	}

	return ToolCallLog{
		ID:            l.ID,
		Timestamp:     derefTime(l.Timestamp),
		TraceID:       l.TraceID,
		SessionID:     derefStr(l.SessionID),
		ToolName:      l.ToolName,
		ToolArguments: args,
		APIType:       types.APIType(derefStr(l.ApiType)),
		WasBlocked:    derefBool(l.WasBlocked),
		BlockedByRule: derefStr(l.BlockedByRule),
		Model:         derefStr(l.Model),
	}
}

// Ensure io is used (for interface compliance)
var _ io.Closer = (*Storage)(nil)
