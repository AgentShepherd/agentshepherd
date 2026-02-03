// Package proxy provides SSE parsing for LLM streaming responses.
package proxy

import (
	"bytes"
	"encoding/json"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// StreamingToolCall represents a tool call being accumulated from SSE events.
// Used by both SSEReader and BufferedSSEWriter.
type StreamingToolCall struct {
	ID        string
	Name      string
	Arguments bytes.Buffer
}

// Anthropic SSE event structures

// AnthropicMessageStart represents the message_start event.
type AnthropicMessageStart struct {
	Type    string `json:"type"`
	Message struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// AnthropicMessageDelta represents the message_delta event.
type AnthropicMessageDelta struct {
	Type  string `json:"type"`
	Usage struct {
		InputTokens  int64 `json:"input_tokens"`
		OutputTokens int64 `json:"output_tokens"`
	} `json:"usage"`
}

// AnthropicContentBlockStart represents the content_block_start event.
type AnthropicContentBlockStart struct {
	Type         string `json:"type"`
	Index        int    `json:"index"`
	ContentBlock struct {
		Type  string   `json:"type"`
		ID    string   `json:"id"`
		Name  string   `json:"name"`
		Input struct{} `json:"input"` // Always empty object at start
	} `json:"content_block"`
}

// AnthropicContentBlockDelta represents the content_block_delta event.
type AnthropicContentBlockDelta struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
	Delta struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
	} `json:"delta"`
}

// AnthropicContentBlockStop represents the content_block_stop event.
type AnthropicContentBlockStop struct {
	Type  string `json:"type"`
	Index int    `json:"index"`
}

// OpenAI SSE event structures

// OpenAIStreamChunk represents a streaming chunk from OpenAI.
type OpenAIStreamChunk struct {
	Choices []OpenAIStreamChoice `json:"choices"`
	Usage   *OpenAIUsage         `json:"usage"`
}

// OpenAIStreamChoice represents a choice in a streaming chunk.
type OpenAIStreamChoice struct {
	Delta struct {
		Content   string                `json:"content"`
		ToolCalls []OpenAIToolCallDelta `json:"tool_calls"`
	} `json:"delta"`
}

// OpenAIToolCallDelta represents a partial tool call in a streaming chunk.
type OpenAIToolCallDelta struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// OpenAIUsage represents token usage from OpenAI.
type OpenAIUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// SSEParser provides unified SSE parsing with optional sanitization.
type SSEParser struct {
	sanitizer *rules.InputSanitizer
}

// NewSSEParser creates a new SSE parser.
// If sanitize is true, tool names will be sanitized using the rules sanitizer.
func NewSSEParser(sanitize bool) *SSEParser {
	p := &SSEParser{}
	if sanitize {
		p.sanitizer = rules.GetSanitizer()
	}
	return p
}

// ParseResult contains the result of parsing an SSE event.
type ParseResult struct {
	// Token usage (updated incrementally)
	InputTokens  int64
	OutputTokens int64

	// Content accumulation
	TextContent string

	// Tool call events
	ToolCallStart *ToolCallStartEvent
	ToolCallDelta *ToolCallDeltaEvent
}

// ToolCallStartEvent represents the start of a new tool call.
type ToolCallStartEvent struct {
	Index int
	ID    string
	Name  string
}

// ToolCallDeltaEvent represents incremental tool call data.
type ToolCallDeltaEvent struct {
	Index       int
	Text        string // For text content
	PartialJSON string // For tool call arguments
}

// ParseAnthropicEvent parses an Anthropic SSE event and returns the result.
func (p *SSEParser) ParseAnthropicEvent(data []byte) ParseResult {
	var result ParseResult

	if bytes.Contains(data, []byte(`"message_start"`)) {
		var event AnthropicMessageStart
		if err := json.Unmarshal(data, &event); err == nil {
			result.InputTokens = event.Message.Usage.InputTokens
			result.OutputTokens = event.Message.Usage.OutputTokens
		}
	} else if bytes.Contains(data, []byte(`"content_block_start"`)) {
		var event AnthropicContentBlockStart
		if err := json.Unmarshal(data, &event); err == nil {
			if event.ContentBlock.Type == "tool_use" {
				name := event.ContentBlock.Name
				if p.sanitizer != nil {
					name = p.sanitizer.SanitizeToolName(name)
				}
				result.ToolCallStart = &ToolCallStartEvent{
					Index: event.Index,
					ID:    event.ContentBlock.ID,
					Name:  name,
				}
			}
		}
	} else if bytes.Contains(data, []byte(`"content_block_delta"`)) {
		var event AnthropicContentBlockDelta
		if err := json.Unmarshal(data, &event); err == nil {
			if event.Delta.Type == "text_delta" && event.Delta.Text != "" {
				result.TextContent = event.Delta.Text
			} else if event.Delta.Type == "input_json_delta" && event.Delta.PartialJSON != "" {
				result.ToolCallDelta = &ToolCallDeltaEvent{
					Index:       event.Index,
					PartialJSON: event.Delta.PartialJSON,
				}
			}
		}
	} else if bytes.Contains(data, []byte(`"message_delta"`)) {
		var event AnthropicMessageDelta
		if err := json.Unmarshal(data, &event); err == nil {
			result.InputTokens = event.Usage.InputTokens
			result.OutputTokens = event.Usage.OutputTokens
		}
	}

	return result
}

// ParseOpenAIEvent parses an OpenAI SSE event and returns the result.
func (p *SSEParser) ParseOpenAIEvent(data []byte) ParseResult {
	var result ParseResult

	var chunk OpenAIStreamChunk
	if err := json.Unmarshal(data, &chunk); err != nil {
		return result
	}

	for _, choice := range chunk.Choices {
		if choice.Delta.Content != "" {
			result.TextContent = choice.Delta.Content
		}

		for _, tc := range choice.Delta.ToolCalls {
			// Tool call start (has ID and/or name)
			if tc.ID != "" || tc.Function.Name != "" {
				name := tc.Function.Name
				if p.sanitizer != nil && name != "" {
					name = p.sanitizer.SanitizeToolName(name)
				}
				result.ToolCallStart = &ToolCallStartEvent{
					Index: tc.Index,
					ID:    tc.ID,
					Name:  name,
				}
			}

			// Tool call delta (has arguments)
			if tc.Function.Arguments != "" {
				result.ToolCallDelta = &ToolCallDeltaEvent{
					Index:       tc.Index,
					PartialJSON: tc.Function.Arguments,
				}
			}
		}
	}

	if chunk.Usage != nil {
		result.InputTokens = chunk.Usage.PromptTokens
		result.OutputTokens = chunk.Usage.CompletionTokens
	}

	return result
}

// ParseEvent parses an SSE event based on API type.
func (p *SSEParser) ParseEvent(data []byte, apiType types.APIType) ParseResult {
	switch apiType {
	case types.APITypeAnthropic:
		return p.ParseAnthropicEvent(data)
	case types.APITypeOpenAI:
		return p.ParseOpenAIEvent(data)
	default:
		return ParseResult{}
	}
}

// ApplyResultToToolCalls updates a tool call map with the parse result.
// Returns true if a new tool call was started.
func (p *SSEParser) ApplyResultToToolCalls(result ParseResult, toolCalls map[int]*StreamingToolCall) bool {
	newToolCall := false

	if result.ToolCallStart != nil {
		tc, exists := toolCalls[result.ToolCallStart.Index]
		if !exists {
			tc = &StreamingToolCall{}
			toolCalls[result.ToolCallStart.Index] = tc
			newToolCall = true
		}
		if result.ToolCallStart.ID != "" {
			tc.ID = result.ToolCallStart.ID
		}
		if result.ToolCallStart.Name != "" {
			tc.Name = result.ToolCallStart.Name
		}
	}

	if result.ToolCallDelta != nil {
		if tc, exists := toolCalls[result.ToolCallDelta.Index]; exists {
			tc.Arguments.WriteString(result.ToolCallDelta.PartialJSON)
		}
	}

	return newToolCall
}
