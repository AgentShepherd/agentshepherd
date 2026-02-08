package telemetry

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/BakeLens/crust/internal/api"
)

// APIHandler handles HTTP API requests for telemetry
type APIHandler struct {
	storage *Storage
}

// NewAPIHandler creates a new telemetry API handler
func NewAPIHandler(storage *Storage) *APIHandler {
	return &APIHandler{storage: storage}
}

// RegisterRoutes registers telemetry API routes on the given router
func (h *APIHandler) RegisterRoutes(router *gin.Engine) {
	telemetry := router.Group("/api/telemetry")
	{
		telemetry.GET("/traces", h.HandleTraces)
		telemetry.GET("/traces/:trace_id", h.HandleTrace)
		telemetry.GET("/stats", h.HandleStats)
	}
}

// TracesQuery represents query parameters for traces endpoint
type TracesQuery struct {
	Limit int `form:"limit" binding:"omitempty,min=1,max=1000"` // SECURITY: reduced max
}

// HandleTraces handles GET /api/telemetry/traces
func (h *APIHandler) HandleTraces(c *gin.Context) {
	var query TracesQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		api.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	// Set defaults
	if query.Limit == 0 {
		query.Limit = 100
	}

	traces, err := h.storage.ListRecentTraces(query.Limit)
	if err != nil {
		api.Error(c, http.StatusInternalServerError, "Failed to list traces")
		return
	}

	if traces == nil {
		traces = []Trace{}
	}

	// Enrich with span counts
	type TraceWithStats struct {
		Trace
		SpanCount   int   `json:"span_count"`
		TotalTokens int64 `json:"total_tokens"`
		LatencyMs   int64 `json:"latency_ms"`
	}

	result := make([]TraceWithStats, 0, len(traces))
	for _, trace := range traces {
		spans, err := h.storage.GetTraceSpans(trace.TraceID)
		if err != nil {
			log.Debug("Failed to get spans for trace %s: %v", trace.TraceID, err)
		}
		var totalTokens int64
		for _, span := range spans {
			totalTokens += span.InputTokens + span.OutputTokens
		}

		var latencyMs int64
		if !trace.EndTime.IsZero() && !trace.StartTime.IsZero() {
			latencyMs = trace.EndTime.Sub(trace.StartTime).Milliseconds()
		}

		result = append(result, TraceWithStats{
			Trace:       trace,
			SpanCount:   len(spans),
			TotalTokens: totalTokens,
			LatencyMs:   latencyMs,
		})
	}

	api.Success(c, result)
}

// HandleTrace handles GET /api/telemetry/traces/:trace_id
func (h *APIHandler) HandleTrace(c *gin.Context) {
	traceID := c.Param("trace_id")
	if traceID == "" {
		api.Error(c, http.StatusBadRequest, "Trace ID required")
		return
	}

	// Get spans for this trace
	spans, err := h.storage.GetTraceSpans(traceID)
	if err != nil {
		api.Error(c, http.StatusInternalServerError, "Failed to get spans")
		return
	}

	if spans == nil {
		api.Error(c, http.StatusNotFound, "Trace not found")
		return
	}

	// Calculate totals
	var totalInputTokens, totalOutputTokens int64
	for _, span := range spans {
		totalInputTokens += span.InputTokens
		totalOutputTokens += span.OutputTokens
	}

	// Find root span (no parent)
	var rootSpan *Span
	for i := range spans {
		if spans[i].ParentSpanID == "" {
			rootSpan = &spans[i]
			break
		}
	}

	var latencyMs int64
	if rootSpan != nil && !rootSpan.EndTime.IsZero() && !rootSpan.StartTime.IsZero() {
		latencyMs = rootSpan.EndTime.Sub(rootSpan.StartTime).Milliseconds()
	}

	response := gin.H{
		"trace_id":            traceID,
		"spans":               spans,
		"span_count":          len(spans),
		"total_input_tokens":  totalInputTokens,
		"total_output_tokens": totalOutputTokens,
		"total_tokens":        totalInputTokens + totalOutputTokens,
		"latency_ms":          latencyMs,
	}

	if rootSpan != nil {
		response["root_span_name"] = rootSpan.Name
		response["root_span_kind"] = rootSpan.SpanKind
	}

	api.Success(c, response)
}

// HandleStats handles GET /api/telemetry/stats
func (h *APIHandler) HandleStats(c *gin.Context) {
	stats, err := h.storage.GetTelemetryStats()
	if err != nil {
		api.Error(c, http.StatusInternalServerError, "Failed to get stats")
		return
	}

	api.Success(c, stats)
}
