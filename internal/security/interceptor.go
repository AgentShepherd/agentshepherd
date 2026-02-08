package security

import (
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Interceptor handles tool call interception and response modification
type Interceptor struct {
	engine  *rules.Engine
	storage *telemetry.Storage
	enabled atomic.Bool
}

// NewInterceptor creates a new interceptor
func NewInterceptor(engine *rules.Engine, storage *telemetry.Storage) *Interceptor {
	i := &Interceptor{
		engine:  engine,
		storage: storage,
	}
	i.enabled.Store(true)
	return i
}

// SetEnabled enables or disables the interceptor
func (i *Interceptor) SetEnabled(enabled bool) {
	i.enabled.Store(enabled)
}

// IsEnabled returns whether the interceptor is enabled
func (i *Interceptor) IsEnabled() bool {
	return i.enabled.Load()
}

// GetEngine returns the rule engine
func (i *Interceptor) GetEngine() *rules.Engine {
	return i.engine
}

// GetStorage returns the storage
func (i *Interceptor) GetStorage() *telemetry.Storage {
	return i.storage
}

// InterceptionResult contains the result of intercepting tool calls
type InterceptionResult struct {
	ModifiedResponse []byte
	BlockedToolCalls []BlockedToolCall
	AllowedToolCalls []telemetry.ToolCall
	HasBlockedCalls  bool
}

// BlockedToolCall represents a tool call that was blocked
type BlockedToolCall struct {
	ToolCall    telemetry.ToolCall
	MatchResult rules.MatchResult
}

// InterceptOpenAIResponse intercepts tool calls in an OpenAI format response
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with echo command)
func (i *Interceptor) InterceptOpenAIResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	if !i.enabled.Load() || i.engine == nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	var resp openAIResponse
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	result := &InterceptionResult{
		BlockedToolCalls: make([]BlockedToolCall, 0),
		AllowedToolCalls: make([]telemetry.ToolCall, 0),
	}

	useReplaceMode := blockMode.IsReplace()

	modified := false
	for choiceIdx := range resp.Choices {
		choice := &resp.Choices[choiceIdx]
		if choice.Message.ToolCalls == nil {
			continue
		}

		allowedToolCalls := make([]openAIToolCall, 0, len(choice.Message.ToolCalls))
		for _, tc := range choice.Message.ToolCalls {
			toolCall := telemetry.ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: json.RawMessage(tc.Function.Arguments),
			}

			_, blocked := i.evaluateToolCall(result, toolCall, traceID, sessionID, tc.Function.Arguments, apiType, model, useReplaceMode)
			if blocked {
				modified = true
			} else {
				allowedToolCalls = append(allowedToolCalls, tc)
			}
		}

		choice.Message.ToolCalls = allowedToolCalls
	}

	// Inject message for blocked tool calls
	if result.HasBlockedCalls && len(resp.Choices) > 0 {
		var msg string
		if useReplaceMode {
			// Replace mode: friendly message about blocked tools
			msg = buildReplaceWarning(result.BlockedToolCalls)
		} else {
			// Remove mode: standard warning
			msg = BuildWarningContent(result.BlockedToolCalls)
		}
		if resp.Choices[0].Message.Content == "" {
			resp.Choices[0].Message.Content = msg
		} else {
			resp.Choices[0].Message.Content += "\n\n" + msg
		}
		modified = true
	}

	if modified {
		modifiedBody, err := json.Marshal(resp)
		if err != nil {
			return &InterceptionResult{ModifiedResponse: responseBody}, err
		}
		result.ModifiedResponse = modifiedBody
	} else {
		result.ModifiedResponse = responseBody
	}

	return result, nil
}

// InterceptAnthropicResponse intercepts tool calls in an Anthropic format response
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with echo command)
func (i *Interceptor) InterceptAnthropicResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	if !i.enabled.Load() || i.engine == nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	var resp anthropicResponse
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	result := &InterceptionResult{
		BlockedToolCalls: make([]BlockedToolCall, 0),
		AllowedToolCalls: make([]telemetry.ToolCall, 0),
	}

	useReplaceMode := blockMode.IsReplace()

	allowedContent := make([]anthropicContentBlock, 0, len(resp.Content))
	modified := false

	for _, block := range resp.Content {
		if block.Type != "tool_use" {
			allowedContent = append(allowedContent, block)
			continue
		}

		toolCall := telemetry.ToolCall{
			ID:        block.ID,
			Name:      block.Name,
			Arguments: block.Input,
		}

		matchResult, blocked := i.evaluateToolCall(result, toolCall, traceID, sessionID, string(block.Input), apiType, model, useReplaceMode)
		if blocked {
			modified = true
			if useReplaceMode {
				msg := fmt.Sprintf("\n[Crust] Tool '%s' blocked: %s\nPlease inform the user and try a different approach.\n",
					block.Name, buildReplaceMessage(matchResult))
				allowedContent = append(allowedContent, anthropicContentBlock{
					Type: "text",
					Text: msg,
				})
			}
		} else {
			allowedContent = append(allowedContent, block)
		}
	}

	// Only inject warning in remove mode
	if result.HasBlockedCalls && !useReplaceMode {
		warningContent := BuildWarningContent(result.BlockedToolCalls)
		allowedContent = append(allowedContent, anthropicContentBlock{
			Type: "text",
			Text: warningContent,
		})
		modified = true
	}

	resp.Content = allowedContent

	if modified {
		modifiedBody, err := json.Marshal(resp)
		if err != nil {
			return &InterceptionResult{ModifiedResponse: responseBody}, err
		}
		result.ModifiedResponse = modifiedBody
	} else {
		result.ModifiedResponse = responseBody
	}

	return result, nil
}

// InterceptOpenAIResponsesResponse intercepts tool calls in an OpenAI Responses API format response.
// The Responses API uses `output[]` with `type: "function_call"` items.
func (i *Interceptor) InterceptOpenAIResponsesResponse(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	if !i.enabled.Load() || i.engine == nil {
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	var resp openAIResponsesResponse
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		log.Warn("[Layer1] Failed to parse %s response: %v", apiType, err)
		return &InterceptionResult{ModifiedResponse: responseBody}, nil
	}

	result := &InterceptionResult{
		BlockedToolCalls: make([]BlockedToolCall, 0),
		AllowedToolCalls: make([]telemetry.ToolCall, 0),
	}

	useReplaceMode := blockMode.IsReplace()

	allowedOutput := make([]openAIResponsesOutputItem, 0, len(resp.Output))
	modified := false

	for _, item := range resp.Output {
		if item.Type != "function_call" {
			allowedOutput = append(allowedOutput, item)
			continue
		}

		toolCall := telemetry.ToolCall{
			ID:        item.CallID,
			Name:      item.Name,
			Arguments: json.RawMessage(item.Arguments),
		}

		matchResult, blocked := i.evaluateToolCall(result, toolCall, traceID, sessionID, item.Arguments, apiType, model, useReplaceMode)
		if blocked {
			modified = true
			if useReplaceMode {
				msg := fmt.Sprintf("\n[Crust] Tool '%s' blocked: %s\nPlease inform the user and try a different approach.\n",
					item.Name, buildReplaceMessage(matchResult))
				allowedOutput = append(allowedOutput, openAIResponsesOutputItem{
					Type: "message",
					ID:   item.ID,
					Content: []openAIResponsesContent{
						{Type: "output_text", Text: msg},
					},
				})
			}
		} else {
			allowedOutput = append(allowedOutput, item)
		}
	}

	// Inject warning in remove mode
	if result.HasBlockedCalls && !useReplaceMode {
		warningContent := BuildWarningContent(result.BlockedToolCalls)
		allowedOutput = append(allowedOutput, openAIResponsesOutputItem{
			Type: "message",
			Content: []openAIResponsesContent{
				{Type: "output_text", Text: warningContent},
			},
		})
		modified = true
	}

	resp.Output = allowedOutput

	if modified {
		modifiedBody, err := json.Marshal(resp)
		if err != nil {
			return &InterceptionResult{ModifiedResponse: responseBody}, err
		}
		result.ModifiedResponse = modifiedBody
	} else {
		result.ModifiedResponse = responseBody
	}

	return result, nil
}

// InterceptToolCalls intercepts tool calls based on API type
// blockMode: types.BlockModeRemove (delete tool calls) or types.BlockModeReplace (substitute with echo command)
func (i *Interceptor) InterceptToolCalls(responseBody []byte, traceID, sessionID, model string, apiType types.APIType, blockMode types.BlockMode) (*InterceptionResult, error) {
	switch apiType {
	case types.APITypeAnthropic:
		return i.InterceptAnthropicResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	case types.APITypeOpenAIResponses:
		return i.InterceptOpenAIResponsesResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	default:
		return i.InterceptOpenAIResponse(responseBody, traceID, sessionID, model, apiType, blockMode)
	}
}

// evaluateToolCall evaluates a single tool call against the rules engine.
// Returns the match result. Handles logging, metrics, and result bookkeeping.
// Returns true if the tool call was blocked.
func (i *Interceptor) evaluateToolCall(
	result *InterceptionResult,
	tc telemetry.ToolCall,
	traceID, sessionID, argsString string,
	apiType types.APIType,
	model string,
	useReplaceMode bool,
) (rules.MatchResult, bool) {
	matchResult := i.engine.Evaluate(rules.ToolCall{
		Name:      tc.Name,
		Arguments: tc.Arguments,
	})

	i.logToolCall(traceID, sessionID, tc.Name, argsString, apiType, model, matchResult)

	if matchResult.Matched && matchResult.Action == rules.ActionBlock {
		result.BlockedToolCalls = append(result.BlockedToolCalls, BlockedToolCall{
			ToolCall:    tc,
			MatchResult: matchResult,
		})
		result.HasBlockedCalls = true
		RecordLayer1Block()
		if useReplaceMode {
			log.Warn("[Layer1] Replaced: %s (rule: %s)", tc.Name, matchResult.RuleName)
		} else {
			log.Warn("[Layer1] Blocked: %s (rule: %s)", tc.Name, matchResult.RuleName)
		}
		return matchResult, true
	}

	result.AllowedToolCalls = append(result.AllowedToolCalls, tc)
	RecordLayer1Allow()
	return matchResult, false
}

func (i *Interceptor) logToolCall(traceID, sessionID, toolName, arguments string, apiType types.APIType, model string, matchResult rules.MatchResult) {
	isBlocked := matchResult.Matched && matchResult.Action == rules.ActionBlock

	tcLog := telemetry.ToolCallLog{
		TraceID:       traceID,
		SessionID:     sessionID,
		ToolName:      toolName,
		ToolArguments: json.RawMessage(arguments),
		APIType:       apiType,
		Model:         model,
		WasBlocked:    isBlocked,
	}

	if matchResult.Matched {
		tcLog.BlockedByRule = matchResult.RuleName
	}

	if err := i.storage.LogToolCall(tcLog); err != nil {
		log.Warn("Failed to log tool call: %v", err)
	}
}

// BuildWarningContent builds a warning message listing blocked tool calls.
func BuildWarningContent(blockedCalls []BlockedToolCall) string {
	warning := "[Crust] The following tool calls were blocked:\n"
	for _, bc := range blockedCalls {
		warning += "- " + bc.ToolCall.Name
		if bc.MatchResult.Message != "" {
			warning += ": " + bc.MatchResult.Message
		}
		warning += "\n"
	}
	return warning
}

// buildReplaceMessage creates the message for replaced tool calls
func buildReplaceMessage(matchResult rules.MatchResult) string {
	if matchResult.Message != "" {
		return matchResult.Message + " (rule: " + matchResult.RuleName + ")"
	}
	return "blocked by rule: " + matchResult.RuleName
}

// buildReplaceWarning creates a friendly warning for replace mode
func buildReplaceWarning(blockedCalls []BlockedToolCall) string {
	warning := "[Crust] The following tool calls were blocked. Please try a different approach:\n"
	for _, bc := range blockedCalls {
		warning += fmt.Sprintf("- %s: %s\n", bc.ToolCall.Name, buildReplaceMessage(bc.MatchResult))
	}
	return warning
}

// OpenAI response structures
type openAIResponse struct {
	ID      string         `json:"id,omitempty"`
	Object  string         `json:"object,omitempty"`
	Created int64          `json:"created,omitempty"`
	Model   string         `json:"model,omitempty"`
	Choices []openAIChoice `json:"choices,omitempty"`
	Usage   *openAIUsage   `json:"usage,omitempty"`
}

type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIChoice struct {
	Index        int            `json:"index"`
	Message      openAIMessage  `json:"message,omitempty"`
	Delta        *openAIMessage `json:"delta,omitempty"`
	FinishReason string         `json:"finish_reason,omitempty"`
}

type openAIMessage struct {
	Role      string           `json:"role,omitempty"`
	Content   string           `json:"content,omitempty"`
	ToolCalls []openAIToolCall `json:"tool_calls,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

// Anthropic response structures
type anthropicResponse struct {
	ID           string                  `json:"id,omitempty"`
	Type         string                  `json:"type,omitempty"`
	Role         string                  `json:"role,omitempty"`
	Content      []anthropicContentBlock `json:"content,omitempty"`
	Model        string                  `json:"model,omitempty"`
	StopReason   string                  `json:"stop_reason,omitempty"`
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        *anthropicUsage         `json:"usage,omitempty"`
}

type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type anthropicContentBlock struct {
	Type  string          `json:"type"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	Text  string          `json:"text,omitempty"`
}

// OpenAI Responses API structures
type openAIResponsesResponse struct {
	ID     string                      `json:"id,omitempty"`
	Object string                      `json:"object,omitempty"`
	Model  string                      `json:"model,omitempty"`
	Output []openAIResponsesOutputItem `json:"output,omitempty"`
	Usage  *openAIResponsesUsage       `json:"usage,omitempty"`
}

type openAIResponsesOutputItem struct {
	Type      string                   `json:"type"`
	ID        string                   `json:"id,omitempty"`
	CallID    string                   `json:"call_id,omitempty"`
	Name      string                   `json:"name,omitempty"`
	Arguments string                   `json:"arguments,omitempty"`
	Content   []openAIResponsesContent `json:"content,omitempty"`
}

type openAIResponsesContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type openAIResponsesUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}
