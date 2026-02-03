package proxy

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBufferedSSEWriter_AnthropicToolUse(t *testing.T) {
	// Create a test response recorder
	w := httptest.NewRecorder()

	// Create buffered writer
	buffer := NewBufferedSSEWriter(w, 100, 30*time.Second, "trace-1", "session-1", "claude-3", "anthropic", nil)

	// Simulate Anthropic SSE events for a tool_use
	events := []struct {
		eventType string
		data      string
	}{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","content":[],"model":"claude-3-opus-20240229","stop_reason":null,"usage":{"input_tokens":100,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"Bash","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":50}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}

	for _, evt := range events {
		raw := []byte("event: " + evt.eventType + "\ndata: " + evt.data + "\n\n")
		err := buffer.BufferEvent(evt.eventType, []byte(evt.data), raw)
		if err != nil {
			t.Fatalf("BufferEvent failed: %v", err)
		}
	}

	// Check that tool use was detected
	if !buffer.HasToolUse() {
		t.Error("Expected HasToolUse() to be true")
	}

	// Check tool calls were extracted
	toolCalls := buffer.GetToolCalls()
	if len(toolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(toolCalls))
	}

	if toolCalls[0].Name != "Bash" {
		t.Errorf("Expected tool name 'Bash', got '%s'", toolCalls[0].Name)
	}

	if toolCalls[0].ID != "toolu_123" {
		t.Errorf("Expected tool ID 'toolu_123', got '%s'", toolCalls[0].ID)
	}

	var args map[string]string
	if err := json.Unmarshal(toolCalls[0].Arguments, &args); err != nil {
		t.Fatalf("Failed to unmarshal arguments: %v", err)
	}
	if args["command"] != "ls" {
		t.Errorf("Expected command 'ls', got '%s'", args["command"])
	}
}

func TestBufferedSSEWriter_OpenAIToolUse(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w, 100, 30*time.Second, "trace-1", "session-1", "gpt-4", "openai", nil)

	// Simulate OpenAI SSE events for a tool call
	events := []struct {
		data string
	}{
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"role":"assistant","content":null,"tool_calls":[{"index":0,"id":"call_abc","function":{"name":"get_weather","arguments":""}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"location\":"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"NYC\"}"}}]},"finish_reason":null}]}`},
		{`{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`},
		{`[DONE]`},
	}

	for _, evt := range events {
		raw := []byte("data: " + evt.data + "\n\n")
		err := buffer.BufferEvent("", []byte(evt.data), raw)
		if err != nil {
			t.Fatalf("BufferEvent failed: %v", err)
		}
	}

	if !buffer.HasToolUse() {
		t.Error("Expected HasToolUse() to be true")
	}

	toolCalls := buffer.GetToolCalls()
	if len(toolCalls) != 1 {
		t.Fatalf("Expected 1 tool call, got %d", len(toolCalls))
	}

	if toolCalls[0].Name != "get_weather" {
		t.Errorf("Expected tool name 'get_weather', got '%s'", toolCalls[0].Name)
	}

	if toolCalls[0].ID != "call_abc" {
		t.Errorf("Expected tool ID 'call_abc', got '%s'", toolCalls[0].ID)
	}
}

func TestBufferedSSEWriter_FlushAll(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w, 100, 30*time.Second, "trace-1", "session-1", "claude-3", "anthropic", nil)

	// Add some events
	event1 := []byte("data: {\"type\":\"message_start\"}\n\n")
	event2 := []byte("data: {\"type\":\"message_stop\"}\n\n")

	_ = buffer.BufferEvent("message_start", []byte(`{"type":"message_start"}`), event1)
	_ = buffer.BufferEvent("message_stop", []byte(`{"type":"message_stop"}`), event2)

	// Flush all
	err := buffer.FlushAll()
	if err != nil {
		t.Fatalf("FlushAll failed: %v", err)
	}

	// Check output
	body := w.Body.String()
	if !bytes.Contains([]byte(body), []byte("message_start")) {
		t.Error("Expected output to contain message_start")
	}
	if !bytes.Contains([]byte(body), []byte("message_stop")) {
		t.Error("Expected output to contain message_stop")
	}
}

func TestBufferedSSEWriter_BufferSizeLimit(t *testing.T) {
	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w, 2, 30*time.Second, "trace-1", "session-1", "claude-3", "anthropic", nil)

	// Add events up to limit
	_ = buffer.BufferEvent("event1", []byte("{}"), []byte("data: {}\n\n"))
	_ = buffer.BufferEvent("event2", []byte("{}"), []byte("data: {}\n\n"))

	// Third event should fail
	err := buffer.BufferEvent("event3", []byte("{}"), []byte("data: {}\n\n"))
	if err == nil {
		t.Error("Expected error when buffer size exceeded")
	}
}

func TestBufferedSSEWriter_Timeout(t *testing.T) {
	w := httptest.NewRecorder()
	// Very short timeout
	buffer := NewBufferedSSEWriter(w, 100, 1*time.Millisecond, "trace-1", "session-1", "claude-3", "anthropic", nil)

	// Wait for timeout
	time.Sleep(10 * time.Millisecond)

	// Should fail due to timeout
	err := buffer.BufferEvent("event", []byte("{}"), []byte("data: {}\n\n"))
	if err == nil {
		t.Error("Expected error when buffer timed out")
	}

	if !buffer.IsTimedOut() {
		t.Error("Expected IsTimedOut() to be true")
	}
}
