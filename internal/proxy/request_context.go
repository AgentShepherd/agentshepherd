package proxy

import (
	"net/http"
	"time"

	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// RequestContext holds all context needed for processing a proxy request.
// This consolidates the many parameters passed between handler functions.
type RequestContext struct {
	// HTTP components
	Writer      http.ResponseWriter
	Request     *http.Request
	UpstreamReq *http.Request

	// Request body
	BodyBytes   []byte // Body sent to upstream
	RequestBody []byte // Original body for telemetry

	// Timing
	StartTime time.Time

	// Tracing identifiers
	TraceID   string
	SessionID string
	SpanName  string
	SpanKind  string

	// Request metadata
	Model     string
	TargetURL string
	APIType   types.APIType
	Tools     []ToolDefinition

	// Telemetry (optional)
	Provider *telemetry.Provider
	SpanCtx  *telemetry.SpanContext
}
