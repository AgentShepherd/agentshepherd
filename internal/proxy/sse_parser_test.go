package proxy

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/BakeLens/crust/internal/types"
)

// =============================================================================
// Table-Driven Tests for Normal Cases
// =============================================================================

func TestParseAnthropicEvent_MessageStart(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantInput    int64
		wantOutput   int64
		wantToolCall bool
	}{
		{
			name:         "basic message_start",
			data:         `{"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":0}}}`,
			wantInput:    100,
			wantOutput:   0,
			wantToolCall: false,
		},
		{
			name:         "message_start with both tokens",
			data:         `{"type":"message_start","message":{"usage":{"input_tokens":250,"output_tokens":10}}}`,
			wantInput:    250,
			wantOutput:   10,
			wantToolCall: false,
		},
		{
			name:         "message_start with large token counts",
			data:         `{"type":"message_start","message":{"usage":{"input_tokens":100000,"output_tokens":50000}}}`,
			wantInput:    100000,
			wantOutput:   50000,
			wantToolCall: false,
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseAnthropicEvent([]byte(tt.data))
			if result.InputTokens != tt.wantInput {
				t.Errorf("InputTokens = %d, want %d", result.InputTokens, tt.wantInput)
			}
			if result.OutputTokens != tt.wantOutput {
				t.Errorf("OutputTokens = %d, want %d", result.OutputTokens, tt.wantOutput)
			}
			if (result.ToolCallStart != nil) != tt.wantToolCall {
				t.Errorf("ToolCallStart presence = %v, want %v", result.ToolCallStart != nil, tt.wantToolCall)
			}
		})
	}
}

func TestParseAnthropicEvent_ContentBlockStart(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantStart bool
		wantIndex int
		wantID    string
		wantName  string
	}{
		{
			name:      "tool_use content block",
			data:      `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"Bash","input":{}}}`,
			wantStart: true,
			wantIndex: 0,
			wantID:    "toolu_123",
			wantName:  "Bash",
		},
		{
			name:      "tool_use with different index",
			data:      `{"type":"content_block_start","index":5,"content_block":{"type":"tool_use","id":"toolu_abc","name":"Read","input":{}}}`,
			wantStart: true,
			wantIndex: 5,
			wantID:    "toolu_abc",
			wantName:  "Read",
		},
		{
			name:      "text content block (not tool_use)",
			data:      `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			wantStart: false,
		},
		{
			name:      "image content block (not tool_use)",
			data:      `{"type":"content_block_start","index":0,"content_block":{"type":"image","source":{}}}`,
			wantStart: false,
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseAnthropicEvent([]byte(tt.data))
			if (result.ToolCallStart != nil) != tt.wantStart {
				t.Errorf("ToolCallStart presence = %v, want %v", result.ToolCallStart != nil, tt.wantStart)
				return
			}
			if tt.wantStart && result.ToolCallStart != nil {
				if result.ToolCallStart.Index != tt.wantIndex {
					t.Errorf("Index = %d, want %d", result.ToolCallStart.Index, tt.wantIndex)
				}
				if result.ToolCallStart.ID != tt.wantID {
					t.Errorf("ID = %q, want %q", result.ToolCallStart.ID, tt.wantID)
				}
				if result.ToolCallStart.Name != tt.wantName {
					t.Errorf("Name = %q, want %q", result.ToolCallStart.Name, tt.wantName)
				}
			}
		})
	}
}

func TestParseAnthropicEvent_ContentBlockDelta(t *testing.T) {
	tests := []struct {
		name            string
		data            string
		wantTextContent string
		wantDelta       bool
		wantIndex       int
		wantPartialJSON string
	}{
		{
			name:            "text_delta",
			data:            `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello, world!"}}`,
			wantTextContent: "Hello, world!",
			wantDelta:       false,
		},
		{
			name:            "input_json_delta",
			data:            `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}`,
			wantTextContent: "",
			wantDelta:       true,
			wantIndex:       0,
			wantPartialJSON: `{"command":`,
		},
		{
			name:            "input_json_delta with different index",
			data:            `{"type":"content_block_delta","index":3,"delta":{"type":"input_json_delta","partial_json":"\"ls -la\"}"}}`,
			wantTextContent: "",
			wantDelta:       true,
			wantIndex:       3,
			wantPartialJSON: `"ls -la"}`,
		},
		{
			name:            "text_delta with empty text",
			data:            `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":""}}`,
			wantTextContent: "",
			wantDelta:       false,
		},
		{
			name:            "input_json_delta with empty partial_json",
			data:            `{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":""}}`,
			wantTextContent: "",
			wantDelta:       false,
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseAnthropicEvent([]byte(tt.data))
			if result.TextContent != tt.wantTextContent {
				t.Errorf("TextContent = %q, want %q", result.TextContent, tt.wantTextContent)
			}
			if (result.ToolCallDelta != nil) != tt.wantDelta {
				t.Errorf("ToolCallDelta presence = %v, want %v", result.ToolCallDelta != nil, tt.wantDelta)
				return
			}
			if tt.wantDelta && result.ToolCallDelta != nil {
				if result.ToolCallDelta.Index != tt.wantIndex {
					t.Errorf("Index = %d, want %d", result.ToolCallDelta.Index, tt.wantIndex)
				}
				if result.ToolCallDelta.PartialJSON != tt.wantPartialJSON {
					t.Errorf("PartialJSON = %q, want %q", result.ToolCallDelta.PartialJSON, tt.wantPartialJSON)
				}
			}
		})
	}
}

func TestParseAnthropicEvent_MessageDelta(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantInput  int64
		wantOutput int64
	}{
		{
			name:       "message_delta with output tokens",
			data:       `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":0,"output_tokens":150}}`,
			wantInput:  0,
			wantOutput: 150,
		},
		{
			name:       "message_delta with both tokens",
			data:       `{"type":"message_delta","usage":{"input_tokens":50,"output_tokens":200}}`,
			wantInput:  50,
			wantOutput: 200,
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseAnthropicEvent([]byte(tt.data))
			if result.InputTokens != tt.wantInput {
				t.Errorf("InputTokens = %d, want %d", result.InputTokens, tt.wantInput)
			}
			if result.OutputTokens != tt.wantOutput {
				t.Errorf("OutputTokens = %d, want %d", result.OutputTokens, tt.wantOutput)
			}
		})
	}
}

func TestParseOpenAIEvent(t *testing.T) {
	tests := []struct {
		name            string
		data            string
		wantTextContent string
		wantToolStart   bool
		wantToolDelta   bool
		wantInput       int64
		wantOutput      int64
	}{
		{
			name:            "streaming content",
			data:            `{"choices":[{"delta":{"content":"Hello"}}]}`,
			wantTextContent: "Hello",
			wantToolStart:   false,
			wantToolDelta:   false,
		},
		{
			name:          "tool call start with ID and name",
			data:          `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_123","function":{"name":"Bash","arguments":""}}]}}]}`,
			wantToolStart: true,
			wantToolDelta: false,
		},
		{
			name:          "tool call with arguments",
			data:          `{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":"}}]}}]}`,
			wantToolStart: false,
			wantToolDelta: true,
		},
		{
			name:          "tool call start with ID, name, and arguments",
			data:          `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_456","function":{"name":"Read","arguments":"{\"path\":"}}]}}]}`,
			wantToolStart: true,
			wantToolDelta: true,
		},
		{
			name:       "usage data",
			data:       `{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`,
			wantInput:  100,
			wantOutput: 50,
		},
		{
			name:            "empty choices",
			data:            `{"choices":[]}`,
			wantTextContent: "",
			wantToolStart:   false,
			wantToolDelta:   false,
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseOpenAIEvent([]byte(tt.data))
			if result.TextContent != tt.wantTextContent {
				t.Errorf("TextContent = %q, want %q", result.TextContent, tt.wantTextContent)
			}
			if (result.ToolCallStart != nil) != tt.wantToolStart {
				t.Errorf("ToolCallStart presence = %v, want %v", result.ToolCallStart != nil, tt.wantToolStart)
			}
			if (result.ToolCallDelta != nil) != tt.wantToolDelta {
				t.Errorf("ToolCallDelta presence = %v, want %v", result.ToolCallDelta != nil, tt.wantToolDelta)
			}
			if result.InputTokens != tt.wantInput {
				t.Errorf("InputTokens = %d, want %d", result.InputTokens, tt.wantInput)
			}
			if result.OutputTokens != tt.wantOutput {
				t.Errorf("OutputTokens = %d, want %d", result.OutputTokens, tt.wantOutput)
			}
		})
	}
}

func TestParseEvent_APITypeRouting(t *testing.T) {
	parser := NewSSEParser(false)

	// Anthropic event
	anthropicData := `{"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":0}}}`
	result := parser.ParseEvent("", []byte(anthropicData), types.APITypeAnthropic)
	if result.InputTokens != 100 {
		t.Errorf("Anthropic routing failed: InputTokens = %d, want 100", result.InputTokens)
	}

	// OpenAI event
	openaiData := `{"choices":[],"usage":{"prompt_tokens":200,"completion_tokens":50}}`
	result = parser.ParseEvent("", []byte(openaiData), types.APITypeOpenAICompletion)
	if result.InputTokens != 200 {
		t.Errorf("OpenAI routing failed: InputTokens = %d, want 200", result.InputTokens)
	}

	// Unknown API type
	result = parser.ParseEvent("", []byte(anthropicData), types.APIType("unknown"))
	if result.InputTokens != 0 || result.OutputTokens != 0 {
		t.Error("Unknown API type should return empty result")
	}
}

// =============================================================================
// Malformed Input Tests
// =============================================================================

func TestParseAnthropicEvent_MalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty byte slice", []byte{}},
		{"invalid JSON - not JSON", []byte(`{not json}`)},
		{"truncated JSON", []byte(`{"type":`)},
		{"truncated JSON 2", []byte(`{"type":"message_start","message":{`)},
		{"null bytes", []byte{0, 0, 0, 0}},
		{"just whitespace", []byte("   \t\n\r  ")},
		{"just brackets", []byte(`{}`)},
		{"array instead of object", []byte(`["message_start"]`)},
		{"wrong type for input_tokens (string)", []byte(`{"type":"message_start","message":{"usage":{"input_tokens":"not a number","output_tokens":0}}}`)},
		{"wrong type for index (string)", []byte(`{"type":"content_block_start","index":"zero","content_block":{"type":"tool_use","id":"id","name":"name"}}`)},
		{"deeply nested JSON", []byte(`{"type":"message_start","message":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":"deep"}}}}}}}}}}}`)},
		{"null values", []byte(`{"type":"message_start","message":null}`)},
		{"null usage", []byte(`{"type":"message_start","message":{"usage":null}}`)},
		// Note: negative tokens are technically valid JSON and the parser allows them
		// (no validation is performed on token counts)
		{"negative tokens", []byte(`{"type":"message_start","message":{"usage":{"input_tokens":-100,"output_tokens":-50}}}`)},
		{"very large index", []byte(`{"type":"content_block_start","index":9999999999999,"content_block":{"type":"tool_use","id":"id","name":"name"}}`)},
		{"unicode in unexpected places", []byte(`{"type":"message_start\u0000","message":{"usage":{"input_tokens":100}}}`)},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The main invariant: must not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseAnthropicEvent panicked: %v", r)
				}
			}()

			result := parser.ParseAnthropicEvent(tt.data)

			// Note: The parser doesn't validate token counts, so negative values are allowed
			// This documents the current behavior (no input validation)
			_ = result.InputTokens
			_ = result.OutputTokens

			// Pointer fields should be safe to check
			if result.ToolCallStart != nil {
				_ = result.ToolCallStart.Index
				_ = result.ToolCallStart.ID
				_ = result.ToolCallStart.Name
			}
			if result.ToolCallDelta != nil {
				_ = result.ToolCallDelta.Index
				_ = result.ToolCallDelta.PartialJSON
			}
		})
	}
}

func TestParseOpenAIEvent_MalformedInput(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty byte slice", []byte{}},
		{"invalid JSON - not JSON", []byte(`{not json}`)},
		{"truncated JSON", []byte(`{"choices":`)},
		{"null bytes", []byte{0, 0, 0, 0}},
		{"just whitespace", []byte("   \t\n\r  ")},
		{"just brackets", []byte(`{}`)},
		{"array instead of object", []byte(`["choices"]`)},
		{"wrong type for choices (string)", []byte(`{"choices":"not an array"}`)},
		{"wrong type for index (string)", []byte(`{"choices":[{"delta":{"tool_calls":[{"index":"zero"}]}}]}`)},
		{"deeply nested JSON", []byte(`{"choices":[{"delta":{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}}]}`)},
		{"null choices", []byte(`{"choices":null}`)},
		{"null usage", []byte(`{"choices":[],"usage":null}`)},
		// Note: negative tokens are technically valid JSON and the parser allows them
		// (no validation is performed on token counts)
		{"negative tokens", []byte(`{"choices":[],"usage":{"prompt_tokens":-100,"completion_tokens":-50}}`)},
		{"very large index", []byte(`{"choices":[{"delta":{"tool_calls":[{"index":9999999999999}]}}]}`)},
		{"empty tool_calls array", []byte(`{"choices":[{"delta":{"tool_calls":[]}}]}`)},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ParseOpenAIEvent panicked: %v", r)
				}
			}()

			result := parser.ParseOpenAIEvent(tt.data)

			// Note: The parser doesn't validate token counts, so negative values are allowed
			// This documents the current behavior (no input validation)
			_ = result.InputTokens
			_ = result.OutputTokens

			if result.ToolCallStart != nil {
				_ = result.ToolCallStart.Index
				_ = result.ToolCallStart.ID
				_ = result.ToolCallStart.Name
			}
			if result.ToolCallDelta != nil {
				_ = result.ToolCallDelta.Index
				_ = result.ToolCallDelta.PartialJSON
			}
		})
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestParseAnthropicEvent_EdgeCases(t *testing.T) {
	parser := NewSSEParser(false)

	t.Run("tool call with empty ID", func(t *testing.T) {
		data := `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"","name":"Bash","input":{}}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if result.ToolCallStart == nil {
			t.Fatal("Expected ToolCallStart to be set")
		}
		if result.ToolCallStart.ID != "" {
			t.Errorf("Expected empty ID, got %q", result.ToolCallStart.ID)
		}
	})

	t.Run("tool call with empty name", func(t *testing.T) {
		data := `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"","input":{}}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if result.ToolCallStart == nil {
			t.Fatal("Expected ToolCallStart to be set")
		}
		if result.ToolCallStart.Name != "" {
			t.Errorf("Expected empty name, got %q", result.ToolCallStart.Name)
		}
	})

	t.Run("content block with unknown type", func(t *testing.T) {
		data := `{"type":"content_block_start","index":0,"content_block":{"type":"unknown_type","id":"id","name":"name"}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if result.ToolCallStart != nil {
			t.Error("Expected no ToolCallStart for unknown content block type")
		}
	})

	t.Run("delta with unknown type", func(t *testing.T) {
		data := `{"type":"content_block_delta","index":0,"delta":{"type":"unknown_delta"}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if result.TextContent != "" || result.ToolCallDelta != nil {
			t.Error("Expected empty result for unknown delta type")
		}
	})

	t.Run("unicode text content", func(t *testing.T) {
		data := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello \u4e16\u754c \ud83d\udc4b"}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if !strings.Contains(result.TextContent, "世界") {
			t.Errorf("Unicode not properly decoded: %q", result.TextContent)
		}
	})

	t.Run("very long text content", func(t *testing.T) {
		longText := strings.Repeat("a", 100000)
		data := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + longText + `"}}`
		result := parser.ParseAnthropicEvent([]byte(data))
		if len(result.TextContent) != 100000 {
			t.Errorf("Long text not properly parsed, got length %d", len(result.TextContent))
		}
	})
}

func TestParseOpenAIEvent_EdgeCases(t *testing.T) {
	parser := NewSSEParser(false)

	t.Run("tool call with empty ID", func(t *testing.T) {
		data := `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"","function":{"name":"Bash","arguments":""}}]}}]}`
		result := parser.ParseOpenAIEvent([]byte(data))
		// Empty ID but has name, should still create start event
		if result.ToolCallStart == nil {
			t.Fatal("Expected ToolCallStart to be set when name is present")
		}
	})

	t.Run("tool call with empty name", func(t *testing.T) {
		data := `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_123","function":{"name":"","arguments":""}}]}}]}`
		result := parser.ParseOpenAIEvent([]byte(data))
		// Has ID but empty name, should still create start event
		if result.ToolCallStart == nil {
			t.Fatal("Expected ToolCallStart to be set when ID is present")
		}
	})

	t.Run("empty choices array", func(t *testing.T) {
		data := `{"choices":[]}`
		result := parser.ParseOpenAIEvent([]byte(data))
		if result.TextContent != "" || result.ToolCallStart != nil || result.ToolCallDelta != nil {
			t.Error("Expected empty result for empty choices")
		}
	})

	t.Run("empty tool_calls array", func(t *testing.T) {
		data := `{"choices":[{"delta":{"tool_calls":[]}}]}`
		result := parser.ParseOpenAIEvent([]byte(data))
		if result.ToolCallStart != nil || result.ToolCallDelta != nil {
			t.Error("Expected no tool events for empty tool_calls")
		}
	})

	t.Run("multiple choices - only first content captured", func(t *testing.T) {
		data := `{"choices":[{"delta":{"content":"First"}},{"delta":{"content":"Second"}}]}`
		result := parser.ParseOpenAIEvent([]byte(data))
		// Note: current implementation overwrites, so last one wins
		if result.TextContent != "Second" {
			t.Errorf("Expected 'Second', got %q", result.TextContent)
		}
	})
}

// =============================================================================
// ApplyResultToToolCalls Tests
// =============================================================================

func TestApplyResultToToolCalls(t *testing.T) {
	parser := NewSSEParser(false)

	t.Run("new tool call creation", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		result := ParseResult{
			ToolCallStart: &ToolCallStartEvent{
				Index: 0,
				ID:    "call_123",
				Name:  "Bash",
			},
		}
		isNew := parser.ApplyResultToToolCalls(result, toolCalls)
		if !isNew {
			t.Error("Expected isNew to be true")
		}
		if len(toolCalls) != 1 {
			t.Fatalf("Expected 1 tool call, got %d", len(toolCalls))
		}
		tc := toolCalls[0]
		if tc.ID != "call_123" {
			t.Errorf("ID = %q, want %q", tc.ID, "call_123")
		}
		if tc.Name != "Bash" {
			t.Errorf("Name = %q, want %q", tc.Name, "Bash")
		}
	})

	t.Run("update existing tool call", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		toolCalls[0] = &StreamingToolCall{ID: "call_123"}

		result := ParseResult{
			ToolCallStart: &ToolCallStartEvent{
				Index: 0,
				Name:  "Bash",
			},
		}
		isNew := parser.ApplyResultToToolCalls(result, toolCalls)
		if isNew {
			t.Error("Expected isNew to be false for existing tool call")
		}
		tc := toolCalls[0]
		if tc.ID != "call_123" {
			t.Errorf("ID should remain unchanged, got %q", tc.ID)
		}
		if tc.Name != "Bash" {
			t.Errorf("Name = %q, want %q", tc.Name, "Bash")
		}
	})

	t.Run("delta for existing tool call", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		toolCalls[0] = &StreamingToolCall{ID: "call_123", Name: "Bash"}

		result := ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{
				Index:       0,
				PartialJSON: `{"command":`,
			},
		}
		parser.ApplyResultToToolCalls(result, toolCalls)
		if toolCalls[0].Arguments.String() != `{"command":` {
			t.Errorf("Arguments = %q, want %q", toolCalls[0].Arguments.String(), `{"command":`)
		}

		// Second delta
		result2 := ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{
				Index:       0,
				PartialJSON: `"ls -la"}`,
			},
		}
		parser.ApplyResultToToolCalls(result2, toolCalls)
		if toolCalls[0].Arguments.String() != `{"command":"ls -la"}` {
			t.Errorf("Arguments = %q, want %q", toolCalls[0].Arguments.String(), `{"command":"ls -la"}`)
		}
	})

	t.Run("delta for non-existent index - should not crash", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		result := ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{
				Index:       999,
				PartialJSON: `{"command":"test"}`,
			},
		}
		// Should not panic
		parser.ApplyResultToToolCalls(result, toolCalls)
		// Tool call should not be created by delta alone
		if _, exists := toolCalls[999]; exists {
			t.Error("Delta should not create new tool call")
		}
	})

	t.Run("multiple sequential updates", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)

		// First: start tool call 0
		parser.ApplyResultToToolCalls(ParseResult{
			ToolCallStart: &ToolCallStartEvent{Index: 0, ID: "call_0", Name: "Bash"},
		}, toolCalls)

		// Second: start tool call 1
		parser.ApplyResultToToolCalls(ParseResult{
			ToolCallStart: &ToolCallStartEvent{Index: 1, ID: "call_1", Name: "Read"},
		}, toolCalls)

		// Third: delta for tool call 0
		parser.ApplyResultToToolCalls(ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{Index: 0, PartialJSON: `{"cmd":"ls"}`},
		}, toolCalls)

		// Fourth: delta for tool call 1
		parser.ApplyResultToToolCalls(ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{Index: 1, PartialJSON: `{"path":"/tmp"}`},
		}, toolCalls)

		if len(toolCalls) != 2 {
			t.Fatalf("Expected 2 tool calls, got %d", len(toolCalls))
		}
		if toolCalls[0].Arguments.String() != `{"cmd":"ls"}` {
			t.Errorf("Tool call 0 arguments = %q", toolCalls[0].Arguments.String())
		}
		if toolCalls[1].Arguments.String() != `{"path":"/tmp"}` {
			t.Errorf("Tool call 1 arguments = %q", toolCalls[1].Arguments.String())
		}
	})

	t.Run("empty result does nothing", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		result := ParseResult{}
		isNew := parser.ApplyResultToToolCalls(result, toolCalls)
		if isNew {
			t.Error("Expected isNew to be false for empty result")
		}
		if len(toolCalls) != 0 {
			t.Error("Expected no tool calls to be created")
		}
	})

	t.Run("start event with only ID updates existing", func(t *testing.T) {
		toolCalls := make(map[int]*StreamingToolCall)
		toolCalls[0] = &StreamingToolCall{Name: "Bash"}

		result := ParseResult{
			ToolCallStart: &ToolCallStartEvent{Index: 0, ID: "call_new"},
		}
		parser.ApplyResultToToolCalls(result, toolCalls)
		if toolCalls[0].ID != "call_new" {
			t.Errorf("ID = %q, want %q", toolCalls[0].ID, "call_new")
		}
		if toolCalls[0].Name != "Bash" {
			t.Errorf("Name should remain unchanged, got %q", toolCalls[0].Name)
		}
	})
}

// =============================================================================
// Fuzz Tests
// =============================================================================

func FuzzParseAnthropicEvent(f *testing.F) {
	// Seed corpus with valid JSON events
	f.Add([]byte(`{"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":0}}}`))
	f.Add([]byte(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"Bash","input":{}}}`))
	f.Add([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`))
	f.Add([]byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"key\":\"value\"}"}}`))
	f.Add([]byte(`{"type":"message_delta","usage":{"input_tokens":0,"output_tokens":50}}`))

	// Empty data
	f.Add([]byte{})
	f.Add([]byte(""))

	// Truncated JSON
	f.Add([]byte(`{"type":`))
	f.Add([]byte(`{"type":"message_start","message":`))

	// Invalid JSON
	f.Add([]byte(`{not json}`))
	f.Add([]byte(`{"type":}`))
	f.Add([]byte(`{{{{{`))

	// Very large data
	f.Add(bytes.Repeat([]byte("a"), 10000))

	// Null bytes
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte("{\x00type\x00}"))

	// Unicode
	f.Add([]byte(`{"type":"message_start","message":{"id":"世界"}}`))
	f.Add(append([]byte{0xef, 0xbb, 0xbf}, []byte("{}")...)) // UTF-8 BOM

	// Special characters
	f.Add([]byte(`{"type":"message_start\\n\\r\\t"}`))

	parser := NewSSEParser(false)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant 1: Must not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseAnthropicEvent panicked on input %q: %v", data, r)
			}
		}()

		result := parser.ParseAnthropicEvent(data)

		// Invariant 2: Must not return negative token counts
		if result.InputTokens < 0 {
			t.Errorf("InputTokens is negative: %d", result.InputTokens)
		}
		if result.OutputTokens < 0 {
			t.Errorf("OutputTokens is negative: %d", result.OutputTokens)
		}

		// Invariant 3: Pointer fields must be safe to access
		if result.ToolCallStart != nil {
			// Access fields to ensure they're safe (negative index is technically possible in JSON)
			_ = result.ToolCallStart.Index
			_ = result.ToolCallStart.ID
			_ = result.ToolCallStart.Name
		}
		if result.ToolCallDelta != nil {
			_ = result.ToolCallDelta.Index
			_ = result.ToolCallDelta.Text
			_ = result.ToolCallDelta.PartialJSON
		}
		_ = result.TextContent
	})
}

func FuzzParseOpenAIEvent(f *testing.F) {
	// Seed corpus with valid JSON events
	f.Add([]byte(`{"choices":[{"delta":{"content":"Hello"}}]}`))
	f.Add([]byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_123","function":{"name":"Bash","arguments":""}}]}}]}`))
	f.Add([]byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"key\":\"value\"}"}}]}}]}`))
	f.Add([]byte(`{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`))

	// Empty data
	f.Add([]byte{})
	f.Add([]byte(""))

	// Truncated JSON
	f.Add([]byte(`{"choices":`))
	f.Add([]byte(`{"choices":[{"delta":`))

	// Invalid JSON
	f.Add([]byte(`{not json}`))
	f.Add([]byte(`{"choices":}`))
	f.Add([]byte(`[[[[[`))

	// Very large data
	f.Add(bytes.Repeat([]byte("a"), 10000))

	// Null bytes
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte("{\x00choices\x00}"))

	// Unicode
	f.Add([]byte(`{"choices":[{"delta":{"content":"世界"}}]}`))
	f.Add(append([]byte{0xef, 0xbb, 0xbf}, []byte("{}")...)) // UTF-8 BOM

	// Special edge cases
	f.Add([]byte(`{"choices":null}`))
	f.Add([]byte(`{"choices":[null]}`))
	f.Add([]byte(`{"choices":[{"delta":null}]}`))

	parser := NewSSEParser(false)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Invariant 1: Must not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseOpenAIEvent panicked on input %q: %v", data, r)
			}
		}()

		result := parser.ParseOpenAIEvent(data)

		// Invariant 2: Must not return negative token counts
		if result.InputTokens < 0 {
			t.Errorf("InputTokens is negative: %d", result.InputTokens)
		}
		if result.OutputTokens < 0 {
			t.Errorf("OutputTokens is negative: %d", result.OutputTokens)
		}

		// Invariant 3: Pointer fields must be safe to access
		if result.ToolCallStart != nil {
			_ = result.ToolCallStart.Index
			_ = result.ToolCallStart.ID
			_ = result.ToolCallStart.Name
		}
		if result.ToolCallDelta != nil {
			_ = result.ToolCallDelta.Index
			_ = result.ToolCallDelta.Text
			_ = result.ToolCallDelta.PartialJSON
		}
		_ = result.TextContent
	})
}

func FuzzParseEvent(f *testing.F) {
	// Seed corpus with both API types
	f.Add([]byte(`{"type":"message_start","message":{"usage":{"input_tokens":100}}}`), byte(0))
	f.Add([]byte(`{"choices":[{"delta":{"content":"Hello"}}]}`), byte(1))
	f.Add([]byte(`{}`), byte(0))
	f.Add([]byte(`{}`), byte(1))
	f.Add([]byte(`{}`), byte(2)) // Unknown API type

	parser := NewSSEParser(false)

	f.Fuzz(func(t *testing.T, data []byte, apiTypeFlag byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseEvent panicked: %v", r)
			}
		}()

		var apiType types.APIType
		switch apiTypeFlag % 3 {
		case 0:
			apiType = types.APITypeAnthropic
		case 1:
			apiType = types.APITypeOpenAICompletion
		default:
			apiType = types.APIType("unknown")
		}

		result := parser.ParseEvent("", data, apiType)

		if result.InputTokens < 0 || result.OutputTokens < 0 {
			t.Error("Negative token count")
		}
	})
}

// =============================================================================
// Additional Fuzz Tests for Integer Overflow Attempts
// =============================================================================

func FuzzApplyResultToToolCalls(f *testing.F) {
	// Seed with normal indices
	f.Add(0, "id1", "Bash", "{\"key\":")
	f.Add(1, "id2", "Read", "\"value\"}")
	f.Add(0, "", "", "")

	// Edge cases
	f.Add(-1, "id", "name", "args")
	f.Add(math.MaxInt32, "id", "name", "args")
	f.Add(math.MinInt32, "id", "name", "args")

	parser := NewSSEParser(false)

	f.Fuzz(func(t *testing.T, index int, id, name, partialJSON string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ApplyResultToToolCalls panicked: %v", r)
			}
		}()

		toolCalls := make(map[int]*StreamingToolCall)

		// Test start event
		startResult := ParseResult{
			ToolCallStart: &ToolCallStartEvent{
				Index: index,
				ID:    id,
				Name:  name,
			},
		}
		parser.ApplyResultToToolCalls(startResult, toolCalls)

		// Test delta event
		deltaResult := ParseResult{
			ToolCallDelta: &ToolCallDeltaEvent{
				Index:       index,
				PartialJSON: partialJSON,
			},
		}
		parser.ApplyResultToToolCalls(deltaResult, toolCalls)

		// Check invariants
		if tc, exists := toolCalls[index]; exists {
			_ = tc.ID
			_ = tc.Name
			_ = tc.Arguments.String()
		}
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkParseAnthropicEvent_MessageStart(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`{"type":"message_start","message":{"usage":{"input_tokens":100,"output_tokens":0}}}`)
	parser := NewSSEParser(false)

	for b.Loop() {
		parser.ParseAnthropicEvent(data)
	}
}

func BenchmarkParseAnthropicEvent_ContentBlockDelta(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls -la\"}"}}`)
	parser := NewSSEParser(false)

	for b.Loop() {
		parser.ParseAnthropicEvent(data)
	}
}

func BenchmarkParseOpenAIEvent_ToolCall(b *testing.B) {
	b.ReportAllocs()
	data := []byte(`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_123","function":{"name":"Bash","arguments":"{\"command\":\"ls\"}"}}]}}]}`)
	parser := NewSSEParser(false)

	for b.Loop() {
		parser.ParseOpenAIEvent(data)
	}
}

func BenchmarkApplyResultToToolCalls(b *testing.B) {
	b.ReportAllocs()
	parser := NewSSEParser(false)
	result := ParseResult{
		ToolCallStart: &ToolCallStartEvent{Index: 0, ID: "call_123", Name: "Bash"},
		ToolCallDelta: &ToolCallDeltaEvent{Index: 0, PartialJSON: `{"command":"ls"}`},
	}

	for b.Loop() {
		toolCalls := make(map[int]*StreamingToolCall)
		parser.ApplyResultToToolCalls(result, toolCalls)
	}
}

// =============================================================================
// Test Parser with Sanitization (when enabled)
// =============================================================================

func TestSSEParser_SanitizationDisabled(t *testing.T) {
	parser := NewSSEParser(false)

	// Anthropic tool name should not be sanitized
	data := `{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_123","name":"Bash","input":{}}}`
	result := parser.ParseAnthropicEvent([]byte(data))
	if result.ToolCallStart == nil {
		t.Fatal("Expected ToolCallStart")
	}
	if result.ToolCallStart.Name != "Bash" {
		t.Errorf("Name = %q, want %q", result.ToolCallStart.Name, "Bash")
	}

	// OpenAI tool name should not be sanitized
	data = `{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_123","function":{"name":"Read","arguments":""}}]}}]}`
	result = parser.ParseOpenAIEvent([]byte(data))
	if result.ToolCallStart == nil {
		t.Fatal("Expected ToolCallStart")
	}
	if result.ToolCallStart.Name != "Read" {
		t.Errorf("Name = %q, want %q", result.ToolCallStart.Name, "Read")
	}
}

// =============================================================================
// Stress Tests
// =============================================================================

func TestParseAnthropicEvent_VeryLargePayload(t *testing.T) {
	// Create a very large but valid JSON payload
	largeText := strings.Repeat("x", 1000000) // 1MB of text
	data := `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + largeText + `"}}`

	parser := NewSSEParser(false)
	result := parser.ParseAnthropicEvent([]byte(data))

	if len(result.TextContent) != 1000000 {
		t.Errorf("Expected 1000000 characters, got %d", len(result.TextContent))
	}
}

func TestParseOpenAIEvent_VeryLargePayload(t *testing.T) {
	largeContent := strings.Repeat("y", 1000000)
	data := `{"choices":[{"delta":{"content":"` + largeContent + `"}}]}`

	parser := NewSSEParser(false)
	result := parser.ParseOpenAIEvent([]byte(data))

	if len(result.TextContent) != 1000000 {
		t.Errorf("Expected 1000000 characters, got %d", len(result.TextContent))
	}
}

// =============================================================================
// Unicode and Special Character Tests
// =============================================================================

func TestParseAnthropicEvent_UnicodeHandling(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "Chinese characters",
			data:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"你好世界"}}`,
			expected: "你好世界",
		},
		{
			name:     "Emoji",
			data:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello 👋 World 🌍"}}`,
			expected: "Hello 👋 World 🌍",
		},
		{
			name:     "Mixed scripts",
			data:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello こんにちは مرحبا"}}`,
			expected: "Hello こんにちは مرحبا",
		},
		{
			name:     "JSON escaped unicode",
			data:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\\u0048\\u0065\\u006c\\u006c\\u006f"}}`,
			expected: "\\u0048\\u0065\\u006c\\u006c\\u006f", // Not decoded by Go's JSON parser in this form
		},
		{
			name:     "Real JSON unicode escapes",
			data:     `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\u0048\u0065\u006c\u006c\u006f"}}`,
			expected: "Hello",
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseAnthropicEvent([]byte(tt.data))
			if result.TextContent != tt.expected {
				t.Errorf("TextContent = %q, want %q", result.TextContent, tt.expected)
			}
			// Verify it's valid UTF-8
			if !utf8.ValidString(result.TextContent) {
				t.Error("TextContent is not valid UTF-8")
			}
		})
	}
}

func TestParseOpenAIEvent_UnicodeHandling(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{
			name:     "Chinese characters",
			data:     `{"choices":[{"delta":{"content":"你好世界"}}]}`,
			expected: "你好世界",
		},
		{
			name:     "Emoji",
			data:     `{"choices":[{"delta":{"content":"🚀 Launch!"}}]}`,
			expected: "🚀 Launch!",
		},
		{
			name:     "Real JSON unicode escapes",
			data:     `{"choices":[{"delta":{"content":"\u4e16\u754c"}}]}`,
			expected: "世界",
		},
	}

	parser := NewSSEParser(false)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseOpenAIEvent([]byte(tt.data))
			if result.TextContent != tt.expected {
				t.Errorf("TextContent = %q, want %q", result.TextContent, tt.expected)
			}
			if !utf8.ValidString(result.TextContent) {
				t.Error("TextContent is not valid UTF-8")
			}
		})
	}
}
