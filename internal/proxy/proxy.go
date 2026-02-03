package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AgentShepherd/agentshepherd/internal/logger"
	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/security"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

var log = logger.New("proxy")

// RequestBody represents minimal structure to extract model and messages
type RequestBody struct {
	Model    string           `json:"model"`
	Stream   bool             `json:"stream"`
	Messages []RequestMessage `json:"messages"`
	Tools    []ToolDefinition `json:"tools,omitempty"`
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
	Role      string            `json:"role"`
	Content   string            `json:"content"`
	ToolCalls []RequestToolCall `json:"tool_calls,omitempty"` // Tool calls in message history
}

// RequestToolCall represents a tool call in message history (OpenAI format)
type RequestToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
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
	upstreamURL *url.URL
	apiKey      string
	client      *http.Client
}

// NewProxy creates a new proxy
func NewProxy(upstreamURL string, apiKey string, timeout time.Duration) (*Proxy, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	return &Proxy{
		upstreamURL: u,
		apiKey:      apiKey,
		client: &http.Client{
			Timeout: timeout,
			// SECURITY: Enforce TLS 1.2+ for upstream connections
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
			// Don't follow redirects automatically
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Header length limits for security
const (
	maxTraceIDLen  = 128
	maxSpanNameLen = 256
	maxSpanKindLen = 32
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
	traceID := sanitizeHeader(r.Header.Get("X-Trace-ID"), maxTraceIDLen)
	spanName := sanitizeHeader(r.Header.Get("X-Span-Name"), maxSpanNameLen)
	spanKind := sanitizeHeader(r.Header.Get("X-Span-Kind"), maxSpanKindLen)

	// Fallback to W3C traceparent
	if traceID == "" {
		if traceparent := r.Header.Get("traceparent"); traceparent != "" {
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

	// Read request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Save original request body for telemetry
	requestBody := make([]byte, len(bodyBytes))
	copy(requestBody, bodyBytes)

	// Parse model name and messages (ignore errors - body may not match struct)
	var reqBody RequestBody
	_ = json.Unmarshal(bodyBytes, &reqBody) //nolint:errcheck // intentional - partial parsing OK

	// Compute session ID from messages (system prompt + first user message)
	sessionID := computeSessionID(reqBody.Messages)
	if sessionID == "" {
		sessionID = traceID // fallback to traceID if no messages
	}

	// Determine API type from path
	apiType := detectAPIType(r.URL.Path)

	// [Layer0] Scan tool_calls in request message history
	interceptor := security.GetGlobalInterceptor()
	if interceptor != nil && interceptor.IsEnabled() && interceptor.GetEngine() != nil {
		for _, msg := range reqBody.Messages {
			for _, tc := range msg.ToolCalls {
				result := interceptor.GetEngine().Evaluate(rules.ToolCall{
					Name:      tc.Function.Name,
					Arguments: json.RawMessage(tc.Function.Arguments),
				})
				if result.Matched && result.Action == rules.ActionBlock {
					log.Warn("[Layer0] Request blocked: %s in history (rule: %s)", tc.Function.Name, result.RuleName)
					security.RecordLayer0Block()
					msg := fmt.Sprintf("[AgentShepherd] Request blocked: %s", result.Message)
					if result.Message == "" {
						msg = fmt.Sprintf("[AgentShepherd] Request blocked by rule: %s", result.RuleName)
					}
					http.Error(w, msg, http.StatusForbidden)
					return
				}
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
	// Always append the request path to upstream path (e.g., /anthropic + /v1/messages)
	upstreamURL := *p.upstreamURL
	upstreamURL.Path = singleJoiningSlash(upstreamURL.Path, r.URL.Path)
	upstreamURL.RawQuery = r.URL.RawQuery

	targetURLStr := upstreamURL.String()

	log.Debug("Forwarding %s %s model=%s → %s", r.Method, r.URL.Path, reqBody.Model, targetURLStr)

	// Create upstream request
	upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, targetURLStr, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Error("Failed to create upstream request: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Copy headers (except hop-by-hop)
	copyHeaders(upstreamReq.Header, r.Header)
	upstreamReq.ContentLength = int64(len(bodyBytes))

	// Inject API key if configured
	if p.apiKey != "" {
		upstreamReq.Header.Set("Authorization", "Bearer "+p.apiKey)
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
	resp, err := p.client.Do(upstreamReq)
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
		responseBody, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Warn("Failed to read error response body: %v", err)
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

	// Copy response headers
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	// Update Content-Length if response was modified
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(responseBody)))
	_, _ = w.Write(responseBody)
}

// handleStreamingRequest handles SSE streaming requests
func (p *Proxy) handleStreamingRequest(ctx *RequestContext) {
	// Check if buffered streaming is enabled
	secCfg := security.GetInterceptionConfig()
	if secCfg.BufferStreaming {
		p.handleBufferedStreamingRequest(ctx, secCfg)
		return
	}

	// Use reverse proxy for non-buffered streaming
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL = ctx.UpstreamReq.URL
			req.Host = ctx.UpstreamReq.URL.Host
			copyHeaders(req.Header, ctx.Request.Header)
			req.Body = io.NopCloser(bytes.NewReader(ctx.BodyBytes))
			req.ContentLength = int64(len(ctx.BodyBytes))
			// Inject API key if configured
			if p.apiKey != "" {
				req.Header.Set("Authorization", "Bearer "+p.apiKey)
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

	proxy.ServeHTTP(ctx.Writer, ctx.Request)
}

// handleBufferedStreamingRequest handles SSE streaming with response buffering for security evaluation
func (p *Proxy) handleBufferedStreamingRequest(ctx *RequestContext, secCfg security.InterceptionConfig) {
	// Make the upstream request
	resp, err := p.client.Do(ctx.UpstreamReq)
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

	// For non-2xx responses, just proxy through
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
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
	buffer := NewBufferedSSEWriter(ctx.Writer, secCfg.MaxBufferSize, timeout, ctx.TraceID, ctx.SessionID, ctx.Model, ctx.APIType, availableTools)

	// Copy response headers before buffering
	copyHeaders(ctx.Writer.Header(), resp.Header)

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
						// Write remaining buffered data (ignore errors - client may have disconnected)
						_, _ = ctx.Writer.Write(data[idx+4:]) //nolint:errcheck // best effort
						// Stream rest directly
						_, _ = io.Copy(ctx.Writer, resp.Body) //nolint:errcheck // best effort
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
					_, _ = ctx.Writer.Write(data[idx+2:]) //nolint:errcheck // best effort
					_, _ = io.Copy(ctx.Writer, resp.Body) //nolint:errcheck // best effort
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

// parseSSEEventData extracts event type and JSON data from SSE event
func parseSSEEventData(event []byte) (eventType string, data []byte) {
	lines := bytes.Split(event, []byte("\n"))

	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte("\r"))

		if bytes.HasPrefix(line, []byte("event:")) {
			eventType = string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("event:"))))
		} else if bytes.HasPrefix(line, []byte("data:")) {
			data = bytes.TrimPrefix(line, []byte("data:"))
			data = bytes.TrimPrefix(data, []byte(" "))
		}
	}

	return eventType, data
}

// detectAPIType detects the API type from the request path
func detectAPIType(path string) types.APIType {
	if strings.Contains(path, "/anthropic") || strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	return types.APITypeOpenAI
}

// copyHeaders copies headers, excluding hop-by-hop headers and Host
func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if HopByHopHeaders[key] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// extractUsageAndBody extracts token usage and body from response
func extractUsageAndBody(resp *http.Response, apiType types.APIType) (inputTokens, outputTokens int64, bodyBytes []byte) {
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Debug("Failed to read non-JSON response body: %v", err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	var bodyReader io.Reader = resp.Body

	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return 0, 0, nil
		}
		defer gzReader.Close()
		bodyReader = gzReader
	}

	bodyBytes, err := io.ReadAll(bodyReader)
	if err != nil {
		return 0, 0, nil
	}

	var respData ResponseWithUsage
	if err := json.Unmarshal(bodyBytes, &respData); err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		return 0, 0, bodyBytes
	}

	switch apiType {
	case types.APITypeAnthropic:
		inputTokens = respData.Usage.InputTokens
		outputTokens = respData.Usage.OutputTokens
	case types.APITypeOpenAI:
		inputTokens = respData.Usage.PromptTokens
		outputTokens = respData.Usage.CompletionTokens
	}

	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	resp.ContentLength = int64(len(bodyBytes))
	if resp.Header.Get("Content-Encoding") == "gzip" {
		resp.Header.Del("Content-Encoding")
	}

	return inputTokens, outputTokens, bodyBytes
}

// extractToolCalls extracts tool calls from response
func extractToolCalls(bodyBytes []byte, apiType types.APIType) []telemetry.ToolCall {
	var toolCalls []telemetry.ToolCall

	if len(bodyBytes) == 0 {
		return toolCalls
	}

	switch apiType {
	case types.APITypeOpenAI:
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
				if c.Type == "tool_use" {
					toolCalls = append(toolCalls, telemetry.ToolCall{
						ID:        c.ID,
						Name:      c.Name,
						Arguments: c.Input,
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
		return s
	}
	return string(b[1 : len(b)-1])
}

// computeSessionID generates a session ID from system prompt and first user message
// Same session will have the same system prompt + first user message, so the hash is stable
func computeSessionID(messages []RequestMessage) string {
	var sessionKey string

	// Extract system prompt
	for _, msg := range messages {
		if msg.Role == "system" {
			sessionKey += msg.Content
			break
		}
	}

	// Extract first user message
	for _, msg := range messages {
		if msg.Role == "user" {
			sessionKey += msg.Content
			break
		}
	}

	// If no messages, return empty (will fall back to traceID)
	if sessionKey == "" {
		return ""
	}

	// SHA256 hash, take first 8 bytes (16 hex chars)
	h := sha256.Sum256([]byte(sessionKey))
	return hex.EncodeToString(h[:8])
}
