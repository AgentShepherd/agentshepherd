package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/security"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// SSEReader wraps a response body to extract token usage from SSE streams.
type SSEReader struct {
	reader  io.ReadCloser
	apiType types.APIType
	parser  *SSEParser

	buffer        bytes.Buffer
	contentBuffer bytes.Buffer

	mu           sync.Mutex
	inputTokens  int64
	outputTokens int64

	toolCalls    map[int]*StreamingToolCall
	toolCallsArr []telemetry.ToolCall

	onComplete func(input, output int64, content string, toolCalls []telemetry.ToolCall)
	completed  bool

	// Security interception fields
	traceID   string
	sessionID string
	model     string
}

// NewSSEReaderWithSecurity creates a new SSE reader with security interception support
func NewSSEReaderWithSecurity(body io.ReadCloser, apiType types.APIType, traceID, sessionID, model string, onComplete func(int64, int64, string, []telemetry.ToolCall)) *SSEReader {
	return &SSEReader{
		reader:     body,
		apiType:    apiType,
		parser:     NewSSEParser(true), // Enable sanitization
		onComplete: onComplete,
		toolCalls:  make(map[int]*StreamingToolCall),
		traceID:    traceID,
		sessionID:  sessionID,
		model:      model,
	}
}

func (r *SSEReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.buffer.Write(p[:n])
		r.processBuffer()
	}

	if err == io.EOF {
		r.triggerComplete()
	}

	return n, err
}

func (r *SSEReader) Close() error {
	r.triggerComplete()
	return r.reader.Close()
}

func (r *SSEReader) triggerComplete() {
	r.mu.Lock()
	if r.completed || r.onComplete == nil {
		r.mu.Unlock()
		return
	}
	r.completed = true
	input, output := r.inputTokens, r.outputTokens
	content := r.contentBuffer.String()
	callback := r.onComplete

	r.finalizeToolCalls()
	toolCalls := r.toolCallsArr

	// Security interception for streaming responses
	// SECURITY LIMITATION: For SSE streaming, tool calls are evaluated AFTER being sent to the client.
	// This is an architectural limitation - the response is streamed in real-time.
	// Blocking is only possible for non-streaming responses.
	// For streaming: we log violations and emit warnings, but cannot prevent the tool call.
	// MITIGATION: Consider implementing response buffering for critical security rules,
	// or advise users to disable streaming for high-security use cases.
	interceptor := security.GetGlobalInterceptor()
	if interceptor != nil && interceptor.IsEnabled() && len(toolCalls) > 0 {
		engine := interceptor.GetEngine()
		storage := interceptor.GetStorage()

		// Log all tool calls and check for violations
		for _, tc := range toolCalls {
			matchResult := engine.Evaluate(rules.ToolCall{
				Name:      tc.Name,
				Arguments: tc.Arguments,
			})

			blocked := matchResult.Matched && matchResult.Action == rules.ActionBlock

			// Log the tool call
			tcLog := telemetry.ToolCallLog{
				TraceID:       r.traceID,
				SessionID:     r.sessionID,
				ToolName:      tc.Name,
				ToolArguments: tc.Arguments,
				APIType:       r.apiType,
				Model:         r.model,
				WasBlocked:    blocked,
			}
			if blocked {
				tcLog.BlockedByRule = matchResult.RuleName
				log.Warn("[STREAMING] Tool call would be blocked: %s (rule: %s) - already sent to client",
					tc.Name, matchResult.RuleName)
			}
			if storage != nil {
				if err := storage.LogToolCall(tcLog); err != nil {
					log.Debug("Failed to log tool call: %v", err)
				}
			}
		}
	}

	r.mu.Unlock()

	callback(input, output, content, toolCalls)
}

func (r *SSEReader) finalizeToolCalls() {
	for _, tc := range r.toolCalls {
		r.toolCallsArr = append(r.toolCallsArr, telemetry.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: json.RawMessage(tc.Arguments.Bytes()),
		})
	}
}

func (r *SSEReader) processBuffer() {
	data := r.buffer.Bytes()

	for {
		idx := bytes.Index(data, []byte("\n\n"))
		if idx == -1 {
			idx = bytes.Index(data, []byte("\r\n\r\n"))
			if idx == -1 {
				break
			}
			r.parseSSEEvent(data[:idx])
			data = data[idx+4:]
			continue
		}

		r.parseSSEEvent(data[:idx])
		data = data[idx+2:]
	}

	r.buffer.Reset()
	r.buffer.Write(data)
}

func (r *SSEReader) parseSSEEvent(event []byte) {
	lines := bytes.Split(event, []byte("\n"))

	var dataLine []byte
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte("\r"))

		if bytes.HasPrefix(line, []byte("data:")) {
			dataLine = bytes.TrimPrefix(line, []byte("data:"))
			dataLine = bytes.TrimPrefix(dataLine, []byte(" "))
		}
	}

	if len(dataLine) == 0 {
		return
	}

	if bytes.Equal(dataLine, []byte("[DONE]")) {
		return
	}

	// Use unified parser
	result := r.parser.ParseEvent(dataLine, r.apiType)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Apply token usage
	if result.InputTokens > r.inputTokens {
		r.inputTokens = result.InputTokens
	}
	if result.OutputTokens > r.outputTokens {
		r.outputTokens = result.OutputTokens
	}

	// Apply text content
	if result.TextContent != "" {
		r.contentBuffer.WriteString(result.TextContent)
	}

	// Apply tool call updates
	r.parser.ApplyResultToToolCalls(result, r.toolCalls)
}

// Note: SSE event types (anthropicMessageStart, etc.) and parsing logic
// are now in sse_parser.go for shared use across SSEReader and BufferedSSEWriter.
