package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/security"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// SSEEvent represents a buffered SSE event
type SSEEvent struct {
	EventType string // "message_start", "content_block_start", etc.
	Data      []byte
	Raw       []byte // Original raw bytes including "data: " prefix
}

// AvailableTool represents a tool available in the request
type AvailableTool struct {
	Name        string
	InputSchema json.RawMessage // The full schema for input validation
}

// BufferedSSEWriter buffers SSE events for security evaluation before sending to client
type BufferedSSEWriter struct {
	underlying http.ResponseWriter
	flusher    http.Flusher
	parser     *SSEParser

	mu            sync.Mutex
	events        []SSEEvent
	toolCalls     map[int]*StreamingToolCall
	contentBuffer bytes.Buffer

	// Configuration
	maxBufferSize int
	timeout       time.Duration

	// Metadata for security evaluation
	traceID   string
	sessionID string
	model     string
	apiType   types.APIType

	// Available tools from request (for replace mode)
	availableTools map[string]AvailableTool

	// State
	hasToolUse bool
	completed  bool
	timedOut   bool
	startTime  time.Time
}

// NewBufferedSSEWriter creates a buffered SSE writer
func NewBufferedSSEWriter(w http.ResponseWriter, maxSize int, timeout time.Duration, traceID, sessionID, model string, apiType types.APIType, tools []AvailableTool) *BufferedSSEWriter {
	flusher, _ := w.(http.Flusher)

	// Build tool lookup map
	toolMap := make(map[string]AvailableTool)
	for _, t := range tools {
		toolMap[t.Name] = t
	}

	return &BufferedSSEWriter{
		underlying:     w,
		flusher:        flusher,
		parser:         NewSSEParser(true), // Enable sanitization
		events:         make([]SSEEvent, 0, 100),
		toolCalls:      make(map[int]*StreamingToolCall),
		maxBufferSize:  maxSize,
		timeout:        timeout,
		traceID:        traceID,
		sessionID:      sessionID,
		model:          model,
		apiType:        apiType,
		availableTools: toolMap,
		startTime:      time.Now(),
	}
}

// shellToolNames lists tool names that can execute shell commands (in priority order)
var shellToolNames = []string{"Bash", "bash", "Shell", "shell", "Execute", "execute", "Exec", "exec", "RunCommand", "run_command", "Terminal", "terminal", "Cmd", "cmd"}

// findShellTool finds a shell/command execution tool from available tools
// Returns the tool name and whether one was found
func (b *BufferedSSEWriter) findShellTool() (string, bool) {
	for _, name := range shellToolNames {
		if _, exists := b.availableTools[name]; exists {
			return name, true
		}
	}
	return "", false
}

// BufferEvent adds an SSE event to the buffer
func (b *BufferedSSEWriter) BufferEvent(eventType string, data, raw []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.completed {
		return fmt.Errorf("buffer already completed")
	}

	// Check timeout
	if time.Since(b.startTime) > b.timeout {
		b.timedOut = true
		return fmt.Errorf("buffer timeout exceeded")
	}

	// Check size limit
	if len(b.events) >= b.maxBufferSize {
		return fmt.Errorf("buffer size limit exceeded")
	}

	event := SSEEvent{
		EventType: eventType,
		Data:      make([]byte, len(data)),
		Raw:       make([]byte, len(raw)),
	}
	copy(event.Data, data)
	copy(event.Raw, raw)

	b.events = append(b.events, event)

	// Parse the event to extract tool calls
	b.parseEvent(eventType, data)

	return nil
}

// parseEvent extracts tool call information from SSE events using the unified parser
func (b *BufferedSSEWriter) parseEvent(eventType string, data []byte) {
	result := b.parser.ParseEvent(data, b.apiType)

	// Apply text content
	if result.TextContent != "" {
		b.contentBuffer.WriteString(result.TextContent)
	}

	// Apply tool call updates
	if b.parser.ApplyResultToToolCalls(result, b.toolCalls) {
		b.hasToolUse = true
	}

	// Also mark hasToolUse if we got a tool call delta for an existing tool
	if result.ToolCallDelta != nil {
		b.hasToolUse = true
	}
}

// HasToolUse returns whether any tool_use blocks were detected
func (b *BufferedSSEWriter) HasToolUse() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hasToolUse
}

// GetToolCalls returns the parsed tool calls
func (b *BufferedSSEWriter) GetToolCalls() []telemetry.ToolCall {
	b.mu.Lock()
	defer b.mu.Unlock()

	var toolCalls []telemetry.ToolCall
	for _, tc := range b.toolCalls {
		toolCalls = append(toolCalls, telemetry.ToolCall{
			ID:        tc.ID,
			Name:      tc.Name,
			Arguments: json.RawMessage(tc.Arguments.Bytes()),
		})
	}
	return toolCalls
}

// FlushAll sends all buffered events to the client without modification
func (b *BufferedSSEWriter) FlushAll() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.completed {
		return nil
	}
	b.completed = true

	for _, event := range b.events {
		if _, err := b.underlying.Write(event.Raw); err != nil {
			return err
		}
		if b.flusher != nil {
			b.flusher.Flush()
		}
	}

	return nil
}

// FlushModified evaluates tool calls and sends modified response if needed
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with echo command)
func (b *BufferedSSEWriter) FlushModified(interceptor *security.Interceptor, blockMode types.BlockMode) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.completed {
		return nil
	}
	b.completed = true

	if !b.hasToolUse || interceptor == nil || !interceptor.IsEnabled() {
		// No tool use or no interceptor, flush as-is
		return b.flushEventsUnlocked()
	}

	// Evaluate each tool call
	engine := interceptor.GetEngine()
	storage := interceptor.GetStorage()

	// Based on global blockMode, all blocked calls go to either blockedIndices or replacedIndices
	blockedIndices := make(map[int]rules.MatchResult)  // for "remove" mode
	replacedIndices := make(map[int]rules.MatchResult) // for "replace" mode
	var blockedCalls []security.BlockedToolCall

	useReplaceMode := blockMode.IsReplace()

	for idx, tc := range b.toolCalls {
		matchResult := engine.Evaluate(rules.ToolCall{
			Name:      tc.Name,
			Arguments: json.RawMessage(tc.Arguments.Bytes()),
		})

		isBlocked := matchResult.Matched && matchResult.Action == rules.ActionBlock

		// Log the tool call
		tcLog := telemetry.ToolCallLog{
			TraceID:       b.traceID,
			SessionID:     b.sessionID,
			ToolName:      tc.Name,
			ToolArguments: json.RawMessage(tc.Arguments.Bytes()),
			APIType:       b.apiType,
			Model:         b.model,
			WasBlocked:    isBlocked,
		}

		if isBlocked {
			tcLog.BlockedByRule = matchResult.RuleName
			blockedCalls = append(blockedCalls, security.BlockedToolCall{
				ToolCall: telemetry.ToolCall{
					ID:        tc.ID,
					Name:      tc.Name,
					Arguments: json.RawMessage(tc.Arguments.Bytes()),
				},
				MatchResult: matchResult,
			})

			// Route to remove or replace based on global block mode
			if useReplaceMode {
				replacedIndices[idx] = matchResult
				log.Warn("[BUFFERED] Replaced tool call: %s (rule: %s)", tc.Name, matchResult.RuleName)
			} else {
				blockedIndices[idx] = matchResult
				log.Warn("[BUFFERED] Blocked tool call: %s (rule: %s)", tc.Name, matchResult.RuleName)
			}
		}

		if storage != nil {
			if err := storage.LogToolCall(tcLog); err != nil {
				log.Debug("Failed to log tool call: %v", err)
			}
		}
	}

	if len(blockedIndices) == 0 && len(replacedIndices) == 0 {
		// No blocked/replaced calls, flush as-is
		return b.flushEventsUnlocked()
	}

	// Generate modified stream
	return b.flushFilteredEvents(blockedIndices, replacedIndices, blockedCalls)
}

func (b *BufferedSSEWriter) flushEventsUnlocked() error {
	for _, event := range b.events {
		if _, err := b.underlying.Write(event.Raw); err != nil {
			return err
		}
		if b.flusher != nil {
			b.flusher.Flush()
		}
	}
	return nil
}

// flushFilteredEvents sends events but filters out blocked tool use content blocks
// blockedIndices: tool calls to remove entirely
// replacedIndices: tool calls to replace with safe echo command
func (b *BufferedSSEWriter) flushFilteredEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	switch b.apiType {
	case types.APITypeAnthropic:
		return b.flushFilteredAnthropicEvents(blockedIndices, replacedIndices, blockedCalls)
	case types.APITypeOpenAI:
		return b.flushFilteredOpenAIEvents(blockedIndices, replacedIndices, blockedCalls)
	default:
		return b.flushEventsUnlocked()
	}
}

func (b *BufferedSSEWriter) flushFilteredAnthropicEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	// Track which content block indices to skip (block action)
	skipIndices := make(map[int]bool)
	for idx := range blockedIndices {
		skipIndices[idx] = true
	}

	// Track which content block indices to replace
	replaceIndices := make(map[int]bool)
	for idx := range replacedIndices {
		replaceIndices[idx] = true
	}

	warningInjected := false
	replacedStartSent := make(map[int]bool) // Track if we already sent the replacement content_block_start
	replacedDeltaSent := make(map[int]bool) // Track if we already sent the replacement delta

	for _, event := range b.events {
		// Check if this event is related to a blocked/replaced content block
		shouldSkip := false
		shouldReplace := false
		eventIndex := -1

		if bytes.Contains(event.Data, []byte(`"content_block_start"`)) {
			var evt AnthropicContentBlockStart
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					shouldReplace = true
				}
			}
		} else if bytes.Contains(event.Data, []byte(`"content_block_delta"`)) {
			var evt AnthropicContentBlockDelta
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					shouldReplace = true
				}
			}
		} else if bytes.Contains(event.Data, []byte(`"content_block_stop"`)) {
			var evt AnthropicContentBlockStop
			if err := json.Unmarshal(event.Data, &evt); err == nil {
				eventIndex = evt.Index
				if skipIndices[evt.Index] {
					shouldSkip = true
				} else if replaceIndices[evt.Index] {
					// For content_block_stop, just send as-is (no modification needed)
					shouldReplace = false
				}
			}
		}

		if shouldSkip {
			continue
		}

		if shouldReplace && eventIndex >= 0 {
			matchResult := replacedIndices[eventIndex]
			tc := b.toolCalls[eventIndex]

			// Find a shell tool (Bash, shell, execute, etc.)
			shellToolName, hasShellTool := b.findShellTool()

			// If no shell tool available, fall back to remove mode (skip this event)
			if !hasShellTool {
				continue
			}

			// Handle content_block_start
			if bytes.Contains(event.Data, []byte(`"content_block_start"`)) && !replacedStartSent[eventIndex] {
				replacedStartSent[eventIndex] = true

				replacedEvent := map[string]interface{}{
					"type":  "content_block_start",
					"index": eventIndex,
					"content_block": map[string]interface{}{
						"type":  "tool_use",
						"id":    tc.ID,
						"name":  shellToolName,
						"input": map[string]interface{}{},
					},
				}
				data, err := json.Marshal(replacedEvent)
				if err != nil {
					log.Debug("Failed to marshal replaced event: %v", err)
					continue
				}
				if _, err := b.underlying.Write([]byte("event: content_block_start\ndata: " + string(data) + "\n\n")); err != nil {
					return err
				}
				if b.flusher != nil {
					b.flusher.Flush()
				}
				continue
			}

			// Handle content_block_delta
			if bytes.Contains(event.Data, []byte(`"content_block_delta"`)) && !replacedDeltaSent[eventIndex] {
				replacedDeltaSent[eventIndex] = true

				// Build message
				msg := fmt.Sprintf("[AgentShepherd] Tool %s blocked.", tc.Name)
				if matchResult.Message != "" {
					msg = fmt.Sprintf("[AgentShepherd] Tool %s blocked: %s", tc.Name, matchResult.Message)
				}

				// Escape special chars for shell and JSON
				escapedMsg := security.EscapeForShellEcho(msg)
				inputJSON := fmt.Sprintf(`{"command":"echo '%s'","description":"Security: blocked tool call"}`, escapedMsg)
				replacedEvent := map[string]interface{}{
					"type":  "content_block_delta",
					"index": eventIndex,
					"delta": map[string]interface{}{
						"type":         "input_json_delta",
						"partial_json": inputJSON,
					},
				}
				data, err := json.Marshal(replacedEvent)
				if err != nil {
					log.Debug("Failed to marshal replaced delta: %v", err)
					continue
				}
				if _, err := b.underlying.Write([]byte("event: content_block_delta\ndata: " + string(data) + "\n\n")); err != nil {
					return err
				}
				if b.flusher != nil {
					b.flusher.Flush()
				}
				continue
			}

			// Skip subsequent deltas for the same replaced block
			if bytes.Contains(event.Data, []byte(`"content_block_delta"`)) {
				continue
			}
		}

		// Inject warning before message_stop (for both remove and replace modes if not already sent via text block)
		if !warningInjected && bytes.Contains(event.Data, []byte(`"message_stop"`)) {
			// Only inject for remove mode; replace mode already has text blocks
			if len(blockedIndices) > 0 {
				if err := b.injectAnthropicWarning(blockedCalls); err != nil {
					log.Warn("Failed to inject warning: %v", err)
				}
			}
			warningInjected = true
		}

		if _, err := b.underlying.Write(event.Raw); err != nil {
			return err
		}
		if b.flusher != nil {
			b.flusher.Flush()
		}
	}

	return nil
}

// injectAnthropicWarning injects a text content block with security warning
func (b *BufferedSSEWriter) injectAnthropicWarning(blockedCalls []security.BlockedToolCall) error {
	warning := "[SECURITY] The following tool calls were blocked:\n"
	for _, bc := range blockedCalls {
		warning += "- " + bc.ToolCall.Name
		if bc.MatchResult.Message != "" {
			warning += ": " + bc.MatchResult.Message
		}
		warning += "\n"
	}

	// Inject content_block_start for text
	startEvent := anthropicContentBlockStartEvent{
		Type:  "content_block_start",
		Index: WarningBlockIndex, // Use high index to not conflict
		ContentBlock: anthropicContentBlockMeta{
			Type: "text",
			Text: "",
		},
	}
	startData, err := json.Marshal(startEvent)
	if err != nil {
		log.Debug("Failed to marshal warning start event: %v", err)
		return nil
	}
	if _, err := b.underlying.Write([]byte("event: content_block_start\ndata: " + string(startData) + "\n\n")); err != nil {
		return err
	}

	// Inject content_block_delta with warning text
	deltaEvent := anthropicContentBlockDeltaEvent{
		Type:  "content_block_delta",
		Index: WarningBlockIndex,
		Delta: anthropicDeltaContent{
			Type: "text_delta",
			Text: warning,
		},
	}
	deltaData, err := json.Marshal(deltaEvent)
	if err != nil {
		log.Debug("Failed to marshal warning delta event: %v", err)
		return nil
	}
	if _, err := b.underlying.Write([]byte("event: content_block_delta\ndata: " + string(deltaData) + "\n\n")); err != nil {
		return err
	}

	// Inject content_block_stop
	stopEvent := anthropicContentBlockStopEvent{
		Type:  "content_block_stop",
		Index: WarningBlockIndex,
	}
	stopData, err := json.Marshal(stopEvent)
	if err != nil {
		log.Debug("Failed to marshal warning stop event: %v", err)
		return nil
	}
	if _, err := b.underlying.Write([]byte("event: content_block_stop\ndata: " + string(stopData) + "\n\n")); err != nil {
		return err
	}

	if b.flusher != nil {
		b.flusher.Flush()
	}

	return nil
}

func (b *BufferedSSEWriter) flushFilteredOpenAIEvents(blockedIndices, replacedIndices map[int]rules.MatchResult, blockedCalls []security.BlockedToolCall) error {
	// For OpenAI, we need to rewrite the chunks to exclude/replace blocked tool calls
	warningInjected := false

	for _, event := range b.events {
		// Check for [DONE] marker
		if bytes.Equal(bytes.TrimSpace(event.Data), []byte("[DONE]")) {
			// Inject warning before [DONE] for both remove and replace modes
			if !warningInjected && (len(blockedIndices) > 0 || len(replacedIndices) > 0) {
				if err := b.injectOpenAIWarning(blockedCalls); err != nil {
					log.Warn("Failed to inject warning: %v", err)
				}
				warningInjected = true
			}
			if _, err := b.underlying.Write(event.Raw); err != nil {
				return err
			}
			if b.flusher != nil {
				b.flusher.Flush()
			}
			continue
		}

		var chunk OpenAIStreamChunk
		if err := json.Unmarshal(event.Data, &chunk); err != nil {
			// Not a valid chunk, send as-is
			if _, err := b.underlying.Write(event.Raw); err != nil {
				return err
			}
			if b.flusher != nil {
				b.flusher.Flush()
			}
			continue
		}

		// Filter out blocked tool calls and replace marked ones
		modified := false
		for choiceIdx := range chunk.Choices {
			choice := &chunk.Choices[choiceIdx]
			if len(choice.Delta.ToolCalls) == 0 {
				continue
			}

			// Use same type as original ToolCalls
			type toolCallDelta struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			filtered := make([]toolCallDelta, 0)

			for _, tc := range choice.Delta.ToolCalls {
				if blockedIndices[tc.Index].Matched {
					// Skip blocked tool calls entirely
					modified = true
					continue
				}

				if replacedIndices[tc.Index].Matched {
					// Replace mode: skip tool call entirely, will inject text warning
					modified = true
					continue
				}

				// Keep unmatched tool calls - convert to local type
				kept := toolCallDelta{
					Index: tc.Index,
					ID:    tc.ID,
				}
				kept.Function.Name = tc.Function.Name
				kept.Function.Arguments = tc.Function.Arguments
				filtered = append(filtered, kept)
			}

			// Need to convert back - just modify in place via JSON marshal/unmarshal dance
			if modified {
				filteredJSON, err := json.Marshal(filtered)
				if err != nil {
					log.Debug("Failed to marshal filtered tool calls: %v", err)
					continue
				}
				if err := json.Unmarshal(filteredJSON, &choice.Delta.ToolCalls); err != nil {
					log.Debug("Failed to unmarshal filtered tool calls: %v", err)
				}
			}
		}

		var dataToWrite []byte
		if modified {
			var err error
			dataToWrite, err = json.Marshal(chunk)
			if err != nil {
				log.Debug("Failed to marshal modified chunk: %v", err)
				dataToWrite = event.Data // Fall back to original
			}
		} else {
			dataToWrite = event.Data
		}

		formatted := fmt.Sprintf("data: %s\n\n", dataToWrite)
		if _, err := b.underlying.Write([]byte(formatted)); err != nil {
			return err
		}
		if b.flusher != nil {
			b.flusher.Flush()
		}
	}

	return nil
}

// injectOpenAIWarning injects a content delta with security warning
func (b *BufferedSSEWriter) injectOpenAIWarning(blockedCalls []security.BlockedToolCall) error {
	warning := "[SECURITY] The following tool calls were blocked:\n"
	for _, bc := range blockedCalls {
		warning += "- " + bc.ToolCall.Name
		if bc.MatchResult.Message != "" {
			warning += ": " + bc.MatchResult.Message
		}
		warning += "\n"
	}

	chunk := openAIWarningChunk{
		ID:      "security-warning",
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   b.model,
		Choices: []openAIWarningChoice{
			{
				Index: 0,
				Delta: openAIWarningDelta{
					Content: warning,
				},
				FinishReason: nil,
			},
		},
	}

	data, err := json.Marshal(chunk)
	if err != nil {
		log.Debug("Failed to marshal OpenAI warning chunk: %v", err)
		return nil
	}
	formatted := fmt.Sprintf("data: %s\n\n", data)

	if _, err := b.underlying.Write([]byte(formatted)); err != nil {
		return err
	}
	if b.flusher != nil {
		b.flusher.Flush()
	}

	return nil
}

// IsTimedOut returns whether the buffer timed out
func (b *BufferedSSEWriter) IsTimedOut() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.timedOut
}

// EventCount returns the number of buffered events
func (b *BufferedSSEWriter) EventCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.events)
}

// Anthropic SSE event types for compile-time type safety
type anthropicContentBlockStartEvent struct {
	Type         string                    `json:"type"`
	Index        int                       `json:"index"`
	ContentBlock anthropicContentBlockMeta `json:"content_block"`
}

type anthropicContentBlockMeta struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicContentBlockDeltaEvent struct {
	Type  string                `json:"type"`
	Index int                   `json:"index"`
	Delta anthropicDeltaContent `json:"delta"`
}

type anthropicDeltaContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicContentBlockStopEvent struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// OpenAI SSE event types for compile-time type safety
type openAIWarningChunk struct {
	ID      string                `json:"id"`
	Object  string                `json:"object"`
	Created int64                 `json:"created"`
	Model   string                `json:"model"`
	Choices []openAIWarningChoice `json:"choices"`
}

type openAIWarningChoice struct {
	Index        int                `json:"index"`
	Delta        openAIWarningDelta `json:"delta"`
	FinishReason *string            `json:"finish_reason"`
}

type openAIWarningDelta struct {
	Content string `json:"content,omitempty"`
}
