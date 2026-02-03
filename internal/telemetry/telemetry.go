package telemetry

import (
	"context"
	crypto_rand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"
)

const (
	// OpenInference semantic convention attributes
	AttrSpanKind        = "openinference.span.kind"
	AttrLLMModel        = "llm.model_name"
	AttrLLMProvider     = "llm.provider"
	AttrLLMIsStreaming  = "llm.is_streaming"
	AttrLLMTokensInput  = "llm.token_count.prompt"     //nolint:gosec // G101: attribute name, not credential
	AttrLLMTokensOutput = "llm.token_count.completion" //nolint:gosec // G101: attribute name, not credential
	AttrInputValue      = "input.value"
	AttrOutputValue     = "output.value"
	AttrHTTPStatusCode  = "http.status_code"
	AttrHTTPLatencyMs   = "http.latency_ms"
	AttrTargetURL       = "http.target_url"
	AttrToolName        = "tool.name"
	AttrToolParameters  = "tool.parameters"
	AttrTraceID         = "trace.id"

	// Span kinds
	SpanKindLLM  = "LLM"
	SpanKindTool = "TOOL"
)

// Config holds telemetry configuration
type Config struct {
	Enabled     bool
	ServiceName string
	SampleRate  float64
}

// ToolCall represents a tool call extracted from LLM response
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// LLMSpanData contains all data to record for an LLM request
type LLMSpanData struct {
	TraceID      string          // From X-Trace-ID header
	SpanKind     string          // LLM, TOOL
	SpanName     string          // Custom span name
	Model        string          // Requested model name
	TargetURL    string          // Upstream URL
	Messages     json.RawMessage // Request body
	Response     json.RawMessage // Response body
	ToolCalls    []ToolCall      // Extracted tool calls
	InputTokens  int64
	OutputTokens int64
	Latency      time.Duration
	StatusCode   int
	IsStreaming  bool
}

// SpanContext holds span timing information
type SpanContext struct {
	TraceID   string
	SpanID    string
	Name      string
	StartTime time.Time
}

// Provider manages telemetry
type Provider struct {
	enabled     bool
	serviceName string
	sampleRate  float64
}

var globalProvider *Provider
var globalStorage *Storage

// Init initializes the telemetry provider
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	globalProvider = &Provider{
		enabled:     cfg.Enabled,
		serviceName: cfg.ServiceName,
		sampleRate:  cfg.SampleRate,
	}

	if cfg.Enabled {
		log.Debug("[TELEMETRY] Initialized (service=%s, sample_rate=%.2f)", cfg.ServiceName, cfg.SampleRate)
	}

	return globalProvider, nil
}

// Shutdown shuts down the provider
func (p *Provider) Shutdown(ctx context.Context) error {
	return nil
}

// IsEnabled returns whether telemetry is enabled
func (p *Provider) IsEnabled() bool {
	return p != nil && p.enabled
}

// GetGlobalProvider returns the global telemetry provider
func GetGlobalProvider() *Provider {
	return globalProvider
}

// SetGlobalStorage sets the global storage for telemetry
func SetGlobalStorage(s *Storage) {
	globalStorage = s
}

// GetGlobalStorage returns the global storage
func GetGlobalStorage() *Storage {
	return globalStorage
}

// StartLLMSpan starts a new span for an LLM request
func (p *Provider) StartLLMSpan(ctx context.Context, operationName string, traceID string, spanName string) (context.Context, *SpanContext) {
	if p == nil || !p.enabled {
		return ctx, nil
	}

	if spanName != "" {
		operationName = spanName
	}

	spanCtx := &SpanContext{
		TraceID:   traceID,
		SpanID:    generateSpanID(),
		Name:      operationName,
		StartTime: time.Now(),
	}

	return ctx, spanCtx
}

// EndLLMSpan ends the span and records all data to SQLite
func (p *Provider) EndLLMSpan(spanCtx *SpanContext, data LLMSpanData) {
	if p == nil || !p.enabled || spanCtx == nil {
		return
	}

	storage := globalStorage
	if storage == nil {
		log.Debug("[TELEMETRY] Warning: storage not available, skipping span")
		return
	}

	// Get or create trace
	trace, err := storage.GetOrCreateTrace(data.TraceID, data.TraceID)
	if err != nil {
		log.Debug("[TELEMETRY] Failed to get/create trace: %v", err)
		return
	}

	// Build attributes
	attrs := map[string]interface{}{
		AttrSpanKind:        data.SpanKind,
		AttrLLMModel:        data.Model,
		AttrTargetURL:       data.TargetURL,
		AttrLLMIsStreaming:  data.IsStreaming,
		AttrLLMTokensInput:  data.InputTokens,
		AttrLLMTokensOutput: data.OutputTokens,
		AttrHTTPStatusCode:  data.StatusCode,
		AttrHTTPLatencyMs:   data.Latency.Milliseconds(),
		AttrTraceID:         data.TraceID,
	}

	if len(data.Messages) > 0 {
		attrs[AttrInputValue] = truncateString(string(data.Messages), 32000)
	}
	if len(data.Response) > 0 {
		attrs[AttrOutputValue] = truncateString(string(data.Response), 32000)
	}

	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		log.Debug("Failed to marshal span attributes: %v", err)
	}

	// Determine status code
	statusCode := "OK"
	if data.StatusCode >= 400 {
		statusCode = "ERROR"
	}

	spanKind := data.SpanKind
	if spanKind == "" {
		spanKind = SpanKindLLM
	}

	// Insert main span
	span := &Span{
		TraceRowID:   trace.ID,
		SpanID:       spanCtx.SpanID,
		Name:         spanCtx.Name,
		SpanKind:     spanKind,
		StartTime:    spanCtx.StartTime,
		EndTime:      time.Now(),
		Attributes:   attrsJSON,
		InputTokens:  data.InputTokens,
		OutputTokens: data.OutputTokens,
		StatusCode:   statusCode,
	}

	if err := storage.InsertSpan(span); err != nil {
		log.Debug("[TELEMETRY] Failed to insert span: %v", err)
		return
	}

	// Create tool call spans
	if len(data.ToolCalls) > 0 {
		p.createToolSpans(storage, trace.ID, spanCtx.SpanID, data)
	}

	// Update trace end time
	if err := storage.UpdateTraceEndTime(data.TraceID, time.Now()); err != nil {
		log.Debug("Failed to update trace end time: %v", err)
	}
}

func (p *Provider) createToolSpans(storage *Storage, traceRowID int64, parentSpanID string, data LLMSpanData) {
	for _, tc := range data.ToolCalls {
		spanName := "tool:" + tc.Name

		attrs := map[string]interface{}{
			AttrSpanKind:       SpanKindTool,
			AttrToolName:       tc.Name,
			AttrToolParameters: truncateString(string(tc.Arguments), 4000),
			AttrTraceID:        data.TraceID,
		}
		attrsJSON, err := json.Marshal(attrs)
		if err != nil {
			log.Debug("Failed to marshal tool span attributes: %v", err)
		}

		toolSpan := &Span{
			TraceRowID:   traceRowID,
			SpanID:       generateSpanID(),
			ParentSpanID: parentSpanID,
			Name:         spanName,
			SpanKind:     SpanKindTool,
			StartTime:    time.Now(),
			EndTime:      time.Now(),
			Attributes:   attrsJSON,
			StatusCode:   "OK",
		}

		if err := storage.InsertSpan(toolSpan); err != nil {
			log.Debug("[TELEMETRY] Failed to insert tool span: %v", err)
		}
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}

// generateSpanID generates a cryptographically secure span ID
func generateSpanID() string {
	b := make([]byte, 8)
	if _, err := crypto_rand.Read(b); err != nil {
		// Fallback should never happen, but handle gracefully
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano))[:8])
	}
	return hex.EncodeToString(b)
}
