package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

var log = logger.New("proxy")

const encodingGzip = "gzip"

// RequestBody represents minimal structure to extract model and messages
type RequestBody struct {
	Model    string           `json:"model"`
	Stream   bool             `json:"stream"`
	Messages []RequestMessage `json:"messages"`
	Tools    []ToolDefinition `json:"tools,omitempty"`
	Input    json.RawMessage  `json:"input,omitempty"` // Responses API: input items
}

// ToolDefinition represents a tool definition in the request
type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"` // Anthropic format
	Parameters  json.RawMessage `json:"parameters,omitempty"`   // OpenAI format
}

// RequestMessage represents a message in the request
type RequestMessage struct {
	Role    types.MessageRole `json:"role"`
	Content json.RawMessage   `json:"content"`
}

// ContentString returns the message content as a plain string.
// If Content is a JSON string, it returns the unquoted string.
// If Content is an array or other type, it returns the raw JSON text.
func (m RequestMessage) ContentString() string {
	if len(m.Content) == 0 {
		return ""
	}
	// Try to unmarshal as a plain string first
	var s string
	if err := json.Unmarshal(m.Content, &s); err == nil {
		return s
	}
	// Fallback: return raw JSON (for array content parts, etc.)
	return string(m.Content)
}

// UsageResponse represents usage info from API responses
type UsageResponse struct {
	// Anthropic format
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	// OpenAI format
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
}

// ResponseWithUsage represents API response with usage field
type ResponseWithUsage struct {
	Usage UsageResponse `json:"usage"`
}

// Proxy is the transparent proxy that captures telemetry
type Proxy struct {
	upstreamURL   *url.URL
	apiKey        string
	client        *http.Client
	userProviders map[string]string // user-defined keyword → base URL
	autoMode      bool              // true = resolve provider from model name; false = always use upstreamURL
}

// NewProxy creates a new proxy
func NewProxy(upstreamURL string, apiKey string, timeout time.Duration, userProviders map[string]string, autoMode bool) (*Proxy, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		upstreamURL:   u,
		apiKey:        apiKey,
		userProviders: userProviders,
		autoMode:      autoMode,
		client: &http.Client{
			// Do NOT set http.Client.Timeout — it covers the entire response
			// lifecycle including body reads, which kills long-running SSE
			// streams. Instead, use Transport-level timeouts that only apply
			// to connection setup and waiting for the first response byte.
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment, // Respect system proxy (HTTP_PROXY, HTTPS_PROXY, etc.)
				// SECURITY: Enforce TLS 1.2+ for upstream connections
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ForceAttemptHTTP2:     true, // Required: custom TLSClientConfig disables auto-HTTP/2
				DisableCompression:    true, // Preserve client's original Accept-Encoding
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: timeout, // Time to wait for server's first response byte
			},
			// Don't follow redirects automatically
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// doRequest performs an HTTP request and guarantees a non-nil *http.Response on success.
func (p *Proxy) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := p.client.Do(req) //nolint:gosec // proxy by design forwards client-controlled URLs to upstream providers
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("nil response from upstream")
	}
	return resp, nil
}

// Header length limits for security
const (
	maxTraceIDLen       = 128
	maxSpanNameLen      = 256
	maxSpanKindLen      = 32
	maxRequestBodySize  = 100 * 1024 * 1024 // 100MB - generous limit for LLM API requests
	maxResponseBodySize = 100 * 1024 * 1024 // 100MB - generous limit for LLM API responses
	maxErrorBodySize    = 1 * 1024 * 1024   // 1MB - error responses should be small
)

// sanitizeHeader truncates and sanitizes header values
func sanitizeHeader(value string, maxLen int) string {
	if len(value) > maxLen {
		return value[:maxLen]
	}
	return value
}

// ServeHTTP handles all incoming requests
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Extract and sanitize telemetry headers
	// SECURITY: Limit header lengths to prevent resource exhaustion
	traceID := sanitizeHeader(r.Header.Get("X-Trace-Id"), maxTraceIDLen)
	spanName := sanitizeHeader(r.Header.Get("X-Span-Name"), maxSpanNameLen)
	spanKind := sanitizeHeader(r.Header.Get("X-Span-Kind"), maxSpanKindLen)

	// Fallback to W3C traceparent
	if traceID == "" {
		if traceparent := r.Header.Get("Traceparent"); traceparent != "" {
			// W3C traceparent format: version-trace_id-parent_id-flags
			// Validate format before parsing
			if len(traceparent) <= 256 {
				parts := strings.Split(traceparent, "-")
				if len(parts) >= 2 && len(parts[1]) <= maxTraceIDLen {
					traceID = parts[1]
				}
			}
		}
	}

	// Read request body with size limit to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			log.Warn("Request body too large (limit: %dMB)", maxRequestBodySize/(1024*1024))
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		log.Error("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	// Decompress request body for local parsing only (model extraction, security scanning).
	// The original compressed body is forwarded to upstream untouched for full transparency.
	parseBytes := bodyBytes
	if len(bodyBytes) > 4 {
		contentEncoding := r.Header.Get("Content-Encoding")
		if contentEncoding == "" {
			// Auto-detect by magic bytes
			if bodyBytes[0] == 0x1f && bodyBytes[1] == 0x8b {
				contentEncoding = encodingGzip
			} else if bodyBytes[0] == 0x28 && bodyBytes[1] == 0xb5 && bodyBytes[2] == 0x2f && bodyBytes[3] == 0xfd {
				contentEncoding = "zstd"
			}
		}
		switch contentEncoding {
		case encodingGzip:
			if gr, err := gzip.NewReader(bytes.NewReader(bodyBytes)); err == nil {
				if decompressed, err := io.ReadAll(gr); err == nil {
					parseBytes = decompressed
				}
				if err := gr.Close(); err != nil {
					log.Debug("Failed to close gzip reader: %v", err)
				}
			}
		case "zstd":
			if decoder, err := zstd.NewReader(nil); err == nil {
				if decompressed, err := decoder.DecodeAll(bodyBytes, nil); err == nil {
					parseBytes = decompressed
				}
				decoder.Close()
			}
		}

		// Fail-closed: reject requests with unsupported Content-Encoding
		// that we couldn't decompress (prevents bypassing security scanning).
		// Only reject when a Content-Encoding header was present but we couldn't decode it.
		if contentEncoding != "" && bytes.Equal(parseBytes, bodyBytes) {
			log.Warn("Unsupported Content-Encoding %q — rejecting request", contentEncoding)
			http.Error(w, "Unsupported Content-Encoding: "+contentEncoding, http.StatusUnsupportedMediaType)
			return
		}
	}

	// Save decompressed request body for telemetry (human-readable JSON)
	requestBody := make([]byte, len(parseBytes))
	copy(requestBody, parseBytes)

	// Parse model name and messages (from decompressed bytes)
	var reqBody RequestBody
	if err := json.Unmarshal(parseBytes, &reqBody); err != nil && len(parseBytes) > 0 {
		log.Debug("Request body parse error: %v", err)
	}

	// Compute session ID from messages (system prompt + first user message)
	sessionID := computeSessionID(reqBody.Messages)
	if sessionID == "" {
		sessionID = traceID // fallback to traceID if no messages
	}

	// Determine API type from path
	apiType := detectAPIType(r.URL.Path)

	// [Layer0] Scan tool_calls in request history (format-agnostic).
	// Walks raw JSON to find tool calls across OpenAI Chat, Anthropic Messages,
	// and OpenAI Responses formats without format-specific struct parsing.
	interceptor := security.GetGlobalInterceptor()
	if interceptor != nil && interceptor.IsEnabled() && interceptor.GetEngine() != nil {
		for _, tc := range extractToolCallsFromJSON(parseBytes) {
			result := interceptor.GetEngine().Evaluate(tc)
			if result.Matched && result.Action == rules.ActionBlock {
				log.Warn("[Layer0] Request blocked: %s in history (rule: %s)", tc.Name, result.RuleName)
				security.RecordEvent(security.Event{
					Layer:      security.LayerL0,
					TraceID:    traceID,
					SessionID:  sessionID,
					ToolName:   tc.Name,
					Arguments:  tc.Arguments,
					APIType:    apiType,
					Model:      reqBody.Model,
					WasBlocked: true,
					RuleName:   result.RuleName,
				})
				msg := "[Crust] Request blocked: " + result.Message
				if result.Message == "" {
					msg = "[Crust] Request blocked by rule: " + result.RuleName
				}
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}
	}

	// Start telemetry span
	tp := telemetry.GetGlobalProvider()
	var spanCtx *telemetry.SpanContext
	var ctx context.Context

	if tp != nil && tp.IsEnabled() {
		ctx, spanCtx = tp.StartLLMSpan(r.Context(), "llm.request", traceID, spanName)
	} else {
		ctx = r.Context()
	}

	// Build upstream URL
	upstreamURL, err := p.buildUpstreamURL(r.URL.Path, reqBody.Model)
	if err != nil {
		log.Warn("Failed to build upstream URL: %v", err)
		http.Error(w, "invalid upstream URL", http.StatusBadGateway)
		return
	}
	upstreamURL.RawQuery = r.URL.RawQuery

	targetURLStr := upstreamURL.String()

	log.Debug("Forwarding %s %s model=%s → %s", r.Method, r.URL.Path, reqBody.Model, targetURLStr)

	// Clone original request for maximum transparency — preserves all headers,
	// trailers, and internal state exactly as the client sent them.
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		http.Error(w, "invalid upstream URL", http.StatusBadGateway)
		return
	}
	upstreamReq := r.Clone(ctx)
	upstreamReq.URL = targetURL
	upstreamReq.Host = targetURL.Host
	upstreamReq.RequestURI = "" // required for http.Client.Do()
	upstreamReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	upstreamReq.ContentLength = int64(len(bodyBytes))

	// Remove hop-by-hop headers (including Connection-listed per RFC 7230 §6.1)
	stripHopByHopHeaders(upstreamReq.Header)

	// Auth passthrough: only inject gateway key if client didn't provide auth
	if !hasClientAuth(upstreamReq.Header) && p.apiKey != "" {
		if apiType.IsAnthropic() {
			upstreamReq.Header.Set("X-Api-Key", p.apiKey)
		} else {
			upstreamReq.Header.Set("Authorization", "Bearer "+p.apiKey)
		}
	}

	// For streaming requests, use reverse proxy for better streaming support
	if reqBody.Stream {
		ctx := &RequestContext{
			Writer:      w,
			Request:     r,
			UpstreamReq: upstreamReq,
			BodyBytes:   bodyBytes,
			RequestBody: requestBody,
			StartTime:   startTime,
			TraceID:     traceID,
			SessionID:   sessionID,
			SpanName:    spanName,
			SpanKind:    spanKind,
			Model:       reqBody.Model,
			TargetURL:   targetURLStr,
			APIType:     apiType,
			Tools:       reqBody.Tools,
			Provider:    tp,
			SpanCtx:     spanCtx,
		}
		p.handleStreamingRequest(ctx)
		return
	}

	// Non-streaming: use http.Client directly
	resp, err := p.doRequest(upstreamReq)
	if err != nil {
		log.Error("Upstream request failed: %v", err)

		if tp != nil && tp.IsEnabled() && spanCtx != nil {
			tp.EndLLMSpan(spanCtx, telemetry.LLMSpanData{
				TraceID:    traceID,
				Model:      reqBody.Model,
				TargetURL:  targetURLStr,
				Messages:   requestBody,
				Latency:    time.Since(startTime),
				StatusCode: 502,
			})
		}

		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	var responseBody []byte
	var inputTokens, outputTokens int64
	var toolCalls []telemetry.ToolCall

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		inputTokens, outputTokens, responseBody = extractUsageAndBody(resp, apiType)
		toolCalls = extractToolCalls(responseBody, apiType)

		// Security interception for non-streaming responses
		interceptor := security.GetGlobalInterceptor()
		if interceptor != nil && interceptor.IsEnabled() && len(toolCalls) > 0 {
			secCfg := security.GetInterceptionConfig()
			result, err := interceptor.InterceptToolCalls(responseBody, traceID, sessionID, reqBody.Model, apiType, secCfg.BlockMode)
			if err != nil {
				log.Warn("Security interception error: %v", err)
			} else {
				responseBody = result.ModifiedResponse
				if result.HasBlockedCalls {
					log.Info("Blocked %d tool calls", len(result.BlockedToolCalls))
				}
				toolCalls = result.AllowedToolCalls
			}
		}

	} else {
		var err error
		responseBody, err = io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize+1))
		if err != nil {
			log.Warn("Failed to read error response body: %v", err)
		}
		if int64(len(responseBody)) > maxErrorBodySize {
			log.Warn("Error response body too large, truncating to %dKB", maxErrorBodySize/1024)
			responseBody = responseBody[:maxErrorBodySize]
		}
	}

	duration := time.Since(startTime)

	log.Info("%s %s model=%s → %s status=%d duration=%v tokens=%d/%d tools=%d",
		r.Method, r.URL.Path, reqBody.Model, targetURLStr, resp.StatusCode, duration, inputTokens, outputTokens, len(toolCalls))

	// Record telemetry
	if tp != nil && tp.IsEnabled() && spanCtx != nil {
		tp.EndLLMSpan(spanCtx, telemetry.LLMSpanData{
			TraceID:      traceID,
			SpanKind:     spanKind,
			SpanName:     spanName,
			Model:        reqBody.Model,
			TargetURL:    targetURLStr,
			Messages:     requestBody,
			Response:     responseBody,
			ToolCalls:    toolCalls,
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			Latency:      duration,
			StatusCode:   resp.StatusCode,
			IsStreaming:  false,
		})
	}

	// Copy response headers and fix Content-Length before writing the status
	// (headers cannot be modified after WriteHeader is called).
	copyHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Length", strconv.Itoa(len(responseBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(responseBody) //nolint:gosec // binary proxy relay, not HTML; nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
}

// handleStreamingRequest handles SSE streaming requests
func (p *Proxy) handleStreamingRequest(ctx *RequestContext) {
	// Auto-buffer: only buffer when security buffering is enabled AND the
	// request carries tool definitions. Pure text-generation streams can
	// never produce tool calls, so buffering them adds latency for zero
	// security benefit.
	secCfg := security.GetInterceptionConfig()
	if secCfg.BufferStreaming && len(ctx.Tools) > 0 {
		p.handleBufferedStreamingRequest(ctx, secCfg)
		return
	}

	// Use reverse proxy for non-buffered streaming
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = ctx.UpstreamReq.URL
			pr.Out.Host = ctx.UpstreamReq.URL.Host
			copyHeaders(pr.Out.Header, ctx.UpstreamReq.Header)
			pr.Out.Body = io.NopCloser(bytes.NewReader(ctx.BodyBytes))
			pr.Out.ContentLength = int64(len(ctx.BodyBytes))
			// Auth passthrough: only inject gateway key if client didn't provide auth
			if !hasClientAuth(pr.Out.Header) && p.apiKey != "" {
				if ctx.APIType.IsAnthropic() {
					pr.Out.Header.Set("X-Api-Key", p.apiKey)
				} else {
					pr.Out.Header.Set("Authorization", "Bearer "+p.apiKey)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				resp.Body = NewSSEReaderWithSecurity(resp.Body, ctx.APIType, ctx.TraceID, ctx.SessionID, ctx.Model, func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
					duration := time.Since(ctx.StartTime)

					log.Info("%s %s model=%s → %s status=%d duration=%v tokens=%d/%d tools=%d [stream]",
						ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, resp.StatusCode, duration, in, out, len(toolCalls))

					if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
						ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
							TraceID:      ctx.TraceID,
							SpanKind:     ctx.SpanKind,
							SpanName:     ctx.SpanName,
							Model:        ctx.Model,
							TargetURL:    ctx.TargetURL,
							Messages:     ctx.RequestBody,
							Response:     json.RawMessage(`{"content":"` + escapeJSON(content) + `"}`),
							ToolCalls:    toolCalls,
							InputTokens:  in,
							OutputTokens: out,
							Latency:      duration,
							StatusCode:   resp.StatusCode,
							IsStreaming:  true,
						})
					}
				})
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("Proxy error: %v", err)

			if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
				ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
					TraceID:    ctx.TraceID,
					Model:      ctx.Model,
					TargetURL:  ctx.TargetURL,
					Messages:   ctx.RequestBody,
					Latency:    time.Since(ctx.StartTime),
					StatusCode: 502,
				})
			}

			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		FlushInterval: -1,
	}

	proxy.ServeHTTP(ctx.Writer, ctx.Request) //nolint:gosec // reverse proxy by design forwards client requests
}

// handleBufferedStreamingRequest handles SSE streaming with response buffering for security evaluation
func (p *Proxy) handleBufferedStreamingRequest(ctx *RequestContext, secCfg security.InterceptionConfig) {
	// Make the upstream request
	resp, err := p.doRequest(ctx.UpstreamReq)
	if err != nil {
		log.Error("Upstream request failed: %v", err)
		if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
			ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
				TraceID:    ctx.TraceID,
				Model:      ctx.Model,
				TargetURL:  ctx.TargetURL,
				Messages:   ctx.RequestBody,
				Latency:    time.Since(ctx.StartTime),
				StatusCode: 502,
			})
		}
		http.Error(ctx.Writer, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// For non-2xx responses, log and proxy through
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Info("%s %s model=%s → %s status=%d duration=%v [stream-error]",
			ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, resp.StatusCode, time.Since(ctx.StartTime))
		copyHeaders(ctx.Writer.Header(), resp.Header)
		ctx.Writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(ctx.Writer, resp.Body)
		return
	}

	// Create buffered SSE writer with available tools
	timeout := time.Duration(secCfg.BufferTimeout) * time.Second
	availableTools := make([]AvailableTool, 0, len(ctx.Tools))
	for _, t := range ctx.Tools {
		schema := t.InputSchema
		if len(schema) == 0 {
			schema = t.Parameters // OpenAI format
		}
		availableTools = append(availableTools, AvailableTool{
			Name:        t.Name,
			InputSchema: schema,
		})
	}
	buffer := NewBufferedSSEWriter(ctx.Writer, secCfg.MaxBufferEvents, timeout, ctx.TraceID, ctx.SessionID, ctx.Model, ctx.APIType, availableTools)

	// Copy response headers and status code before buffering
	copyHeaders(ctx.Writer.Header(), resp.Header)
	ctx.Writer.WriteHeader(resp.StatusCode)

	// Get interceptor early to avoid goto issues
	interceptor := security.GetGlobalInterceptor()

	// Read and buffer SSE events
	bufferOverflowed := false
	reader := &bytes.Buffer{}
	buf := make([]byte, 4096)

readLoop:
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			reader.Write(buf[:n])

			// Process complete SSE events
			for {
				data := reader.Bytes()
				idx := bytes.Index(data, []byte("\n\n"))
				if idx == -1 {
					idx = bytes.Index(data, []byte("\r\n\r\n"))
					if idx == -1 {
						break
					}
					// Process event with \r\n\r\n separator
					eventData := data[:idx]
					raw := data[:idx+4]
					eventType, jsonData := parseSSEEventData(eventData)
					if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
						log.Warn("Buffer error: %v, flushing immediately", err)
						// On buffer error (timeout/size exceeded), flush what we have and stream rest
						if flushErr := buffer.FlushAll(); flushErr != nil {
							log.Warn("FlushAll error during recovery: %v", flushErr)
						}
						// Write the event that caused the overflow, then remaining data
						_, _ = ctx.Writer.Write(raw)
						_, _ = ctx.Writer.Write(data[idx+4:])
						// Stream rest directly
						_, _ = io.Copy(ctx.Writer, resp.Body)
						bufferOverflowed = true
						break readLoop
					}
					reader.Reset()
					reader.Write(data[idx+4:])
					continue
				}
				// Process event with \n\n separator
				eventData := data[:idx]
				raw := data[:idx+2]
				eventType, jsonData := parseSSEEventData(eventData)
				if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
					log.Warn("Buffer error: %v, flushing immediately", err)
					if flushErr := buffer.FlushAll(); flushErr != nil {
						log.Warn("FlushAll error during recovery: %v", flushErr)
					}
					// Write the event that caused the overflow, then remaining data
					_, _ = ctx.Writer.Write(raw)
					_, _ = ctx.Writer.Write(data[idx+2:])
					_, _ = io.Copy(ctx.Writer, resp.Body)
					bufferOverflowed = true
					break readLoop
				}
				reader.Reset()
				reader.Write(data[idx+2:])
			}
		}

		if readErr != nil {
			if readErr != io.EOF {
				log.Error("Read error: %v", readErr)
			}
			break
		}
	}

	// Flush any remaining data in the reader buffer that wasn't terminated
	// by \n\n. This handles the case where the server closes the connection
	// right after the last event (e.g., response.completed) without a
	// trailing blank line — the event would otherwise be silently dropped.
	if !bufferOverflowed && reader.Len() > 0 {
		remaining := reader.Bytes()
		remaining = bytes.TrimRight(remaining, "\r\n")
		if len(remaining) > 0 {
			eventType, jsonData := parseSSEEventData(remaining)
			raw := reader.Bytes() // include original whitespace
			// Ensure raw ends with \n\n for proper SSE formatting
			if !bytes.HasSuffix(raw, []byte("\n\n")) {
				raw = append(raw, '\n', '\n')
			}
			if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
				log.Debug("Failed to buffer trailing event: %v", err)
			} else {
				log.Debug("Buffered trailing SSE event: %s", eventType)
			}
		}
	}

	// Evaluate and flush if we didn't overflow
	if !bufferOverflowed {
		if err := buffer.FlushModified(interceptor, secCfg.BlockMode); err != nil {
			log.Error("Flush error: %v", err)
		}
	}

	// Log telemetry
	duration := time.Since(ctx.StartTime)
	toolCalls := buffer.GetToolCalls()

	log.Info("%s %s model=%s → %s status=%d duration=%v tools=%d [buffered-stream]",
		ctx.Request.Method, ctx.Request.URL.Path, ctx.Model, ctx.TargetURL, resp.StatusCode, duration, len(toolCalls))

	if ctx.Provider != nil && ctx.Provider.IsEnabled() && ctx.SpanCtx != nil {
		ctx.Provider.EndLLMSpan(ctx.SpanCtx, telemetry.LLMSpanData{
			TraceID:     ctx.TraceID,
			SpanKind:    ctx.SpanKind,
			SpanName:    ctx.SpanName,
			Model:       ctx.Model,
			TargetURL:   ctx.TargetURL,
			Messages:    ctx.RequestBody,
			ToolCalls:   toolCalls,
			Latency:     duration,
			StatusCode:  resp.StatusCode,
			IsStreaming: true,
		})
	}
}

// detectAPIType detects the API type from the request path
func detectAPIType(path string) types.APIType {
	if strings.Contains(path, "/anthropic") || strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	if strings.Contains(path, "/v1/responses") || strings.HasSuffix(path, "/responses") {
		return types.APITypeOpenAIResponses
	}
	return types.APITypeOpenAICompletion
}

// hasClientAuth returns true if the request already carries an auth header.
func hasClientAuth(h http.Header) bool {
	return h.Get("Authorization") != "" || h.Get("X-Api-Key") != ""
}

// buildUpstreamURL constructs the target URL for a proxy request.
// In auto mode it resolves the provider from the model name; in endpoint mode
// it always uses the configured upstream URL.
func (p *Proxy) buildUpstreamURL(reqPath, model string) (url.URL, error) {
	u := *p.upstreamURL

	if p.autoMode {
		// Auto mode: resolve provider from model name
		if resolvedBaseURL, ok := ResolveProvider(model, p.userProviders); ok {
			resolvedURL, err := url.Parse(resolvedBaseURL)
			if err != nil {
				return url.URL{}, fmt.Errorf("invalid provider URL %q: %w", resolvedBaseURL, err)
			}
			// Normalize /responses → /v1/responses only when the provider
			// has no meaningful path (e.g. "https://api.openai.com").
			// Providers with a path (e.g. "chatgpt.com/backend-api/codex")
			// get the request path appended directly.
			if reqPath == "/responses" && (resolvedURL.Path == "" || resolvedURL.Path == "/") {
				reqPath = "/v1/responses"
			}
			u.Scheme = resolvedURL.Scheme
			u.Host = resolvedURL.Host
			// path.Join concatenates provider path + request path and
			// cleans the result (collapses double slashes, resolves dots).
			u.Path = path.Join(resolvedURL.Path, reqPath)
			return u, nil
		}
	}

	// Endpoint mode (or auto mode with unrecognized model):
	// Use ResolveReference which keeps the base scheme+host and replaces
	// the path with reqPath — no manual path dedup needed.
	if reqPath == "/responses" {
		reqPath = "/v1/responses"
	}
	ref := &url.URL{Path: reqPath}
	resolved := u.ResolveReference(ref)
	return *resolved, nil
}

// extractUsageAndBody extracts token usage and body from response
func extractUsageAndBody(resp *http.Response, apiType types.APIType) (inputTokens, outputTokens int64, bodyBytes []byte) {
	if resp == nil {
		return 0, 0, nil
	}
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
		if err != nil {
			log.Debug("Failed to read non-JSON response body: %v", err)
		}
		if int64(len(bodyBytes)) > maxResponseBodySize {
			log.Warn("Non-JSON response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
			bodyBytes = nil
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	// Read the entire raw body first so we have it available as fallback on gzip error
	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
	if err != nil {
		log.Debug("Failed to read response body: %v", err)
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return 0, 0, nil
	}
	if int64(len(rawBytes)) > maxResponseBodySize {
		log.Warn("Response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
		resp.Body = io.NopCloser(bytes.NewReader(nil))
		return 0, 0, nil
	}

	bodyBytes = rawBytes

	if resp.Header.Get("Content-Encoding") == encodingGzip {
		gzReader, err := gzip.NewReader(bytes.NewReader(rawBytes))
		if err != nil {
			log.Debug("Failed to create gzip reader, using raw body: %v", err)
			resp.Header.Del("Content-Encoding")
			// Fall through with bodyBytes = rawBytes
		} else {
			decompressed, readErr := io.ReadAll(io.LimitReader(gzReader, maxResponseBodySize+1))
			gzReader.Close()
			if readErr != nil {
				log.Debug("Failed to decompress gzip body, using raw body: %v", readErr)
				resp.Header.Del("Content-Encoding")
				// Fall through with bodyBytes = rawBytes
			} else if int64(len(decompressed)) > maxResponseBodySize {
				log.Warn("Decompressed response body too large (limit: %dMB)", maxResponseBodySize/(1024*1024))
				resp.Header.Del("Content-Encoding")
				// Fall through with bodyBytes = rawBytes
			} else {
				bodyBytes = decompressed
				resp.Header.Del("Content-Encoding")
			}
		}
	}

	var respData ResponseWithUsage
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	switch apiType {
	case types.APITypeAnthropic, types.APITypeOpenAIResponses:
		inputTokens = respData.Usage.InputTokens
		outputTokens = respData.Usage.OutputTokens
	case types.APITypeOpenAICompletion:
		inputTokens = respData.Usage.PromptTokens
		outputTokens = respData.Usage.CompletionTokens
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))

	return inputTokens, outputTokens, bodyBytes
}

// extractToolCalls extracts tool calls from response
func extractToolCalls(bodyBytes []byte, apiType types.APIType) []telemetry.ToolCall {
	var toolCalls []telemetry.ToolCall

	if len(bodyBytes) == 0 {
		return toolCalls
	}

	switch apiType {
	case types.APITypeOpenAICompletion:
		var resp struct {
			Choices []struct {
				Message struct {
					ToolCalls []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string          `json:"name"`
							Arguments json.RawMessage `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil && len(resp.Choices) > 0 {
			for _, tc := range resp.Choices[0].Message.ToolCalls {
				toolCalls = append(toolCalls, telemetry.ToolCall{
					ID:        tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
		}

	case types.APITypeAnthropic:
		var resp struct {
			Content []struct {
				Type  string          `json:"type"`
				ID    string          `json:"id"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			} `json:"content"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil {
			for _, c := range resp.Content {
				if c.Type == contentTypeToolUse {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        c.ID,
						Name:      c.Name,
						Arguments: c.Input,
					})
				}
			}
		}

	case types.APITypeOpenAIResponses:
		var resp struct {
			Output []struct {
				Type      string `json:"type"`
				CallID    string `json:"call_id"`
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"output"`
		}
		if err := json.Unmarshal(bodyBytes, &resp); err == nil {
			for _, item := range resp.Output {
				if item.Type == contentTypeFunctionCall {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        item.CallID,
						Name:      item.Name,
						Arguments: json.RawMessage(item.Arguments),
					})
				}
			}
		}
	}

	return toolCalls
}

func escapeJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(b[1 : len(b)-1])
}

// computeSessionID generates a session ID from system prompt and first user message
// Same session will have the same system prompt + first user message, so the hash is stable
func computeSessionID(messages []RequestMessage) string {
	var sb strings.Builder

	// Extract system prompt
	for _, msg := range messages {
		if msg.Role == types.RoleSystem {
			sb.WriteString(msg.ContentString())
			break
		}
	}

	// Extract first user message
	for _, msg := range messages {
		if msg.Role == types.RoleUser {
			sb.WriteString(msg.ContentString())
			break
		}
	}

	// If no messages, return empty (will fall back to traceID)
	if sb.Len() == 0 {
		return ""
	}

	// SHA256 hash, take first 8 bytes (16 hex chars)
	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:8])
}

// maxJSONWalkDepth limits recursion depth in walkJSONForToolCalls to prevent
// stack overflow from adversarially nested JSON. Tool calls in real API
// requests are at most ~5 levels deep; 64 is generous.
const maxJSONWalkDepth = 64

// extractToolCallsFromJSON walks raw JSON to find tool call objects across
// all API formats (OpenAI Chat, Anthropic Messages, OpenAI Responses) without
// format-specific struct parsing.
func extractToolCallsFromJSON(data []byte) []rules.ToolCall {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var results []rules.ToolCall
	walkJSONForToolCalls(raw, &results, 0)
	if len(results) > 0 {
		log.Debug("extractToolCallsFromJSON: found %d tool calls", len(results))
	}
	return results
}

func walkJSONForToolCalls(v any, results *[]rules.ToolCall, depth int) {
	if depth > maxJSONWalkDepth {
		return
	}
	switch val := v.(type) {
	case map[string]any:
		// Pattern 1: type=tool_use (Anthropic)
		// Pattern 2: type=function_call (OpenAI Responses)
		matched := false
		if tc, ok := matchTypedToolCall(val); ok {
			*results = append(*results, tc)
			matched = true
		}
		// Pattern 3: function.{name, arguments} (OpenAI Chat)
		// Skip if already matched as typed tool call to avoid double-counting.
		if !matched {
			if fn, ok := val["function"].(map[string]any); ok {
				if tc, ok := matchFunctionObject(fn); ok {
					*results = append(*results, tc)
				}
			}
		}
		// Recurse into all values
		for _, child := range val {
			walkJSONForToolCalls(child, results, depth+1)
		}
	case []any:
		for _, child := range val {
			walkJSONForToolCalls(child, results, depth+1)
		}
	}
}

func matchTypedToolCall(obj map[string]any) (rules.ToolCall, bool) {
	t, _ := obj["type"].(string)
	name, _ := obj["name"].(string)
	if name == "" {
		return rules.ToolCall{}, false
	}
	switch t {
	case contentTypeToolUse:
		// Anthropic: input is a JSON object
		return rules.ToolCall{Name: name, Arguments: toRawMessage(obj["input"])}, true
	case contentTypeFunctionCall:
		// OpenAI Responses: arguments is a JSON string
		return rules.ToolCall{Name: name, Arguments: toRawMessage(obj["arguments"])}, true
	}
	return rules.ToolCall{}, false
}

func matchFunctionObject(fn map[string]any) (rules.ToolCall, bool) {
	name, _ := fn["name"].(string)
	if name == "" {
		return rules.ToolCall{}, false
	}
	_, hasArgs := fn["arguments"]
	if !hasArgs {
		return rules.ToolCall{}, false
	}
	return rules.ToolCall{Name: name, Arguments: toRawMessage(fn["arguments"])}, true
}

// toRawMessage converts a value to json.RawMessage.
// If the value is a string, it's treated as already-encoded JSON arguments.
// Otherwise, it's marshaled to JSON.
func toRawMessage(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return json.RawMessage(s)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
