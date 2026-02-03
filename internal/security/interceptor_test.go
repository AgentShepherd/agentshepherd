package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentShepherd/agentshepherd/internal/rules"
	"github.com/AgentShepherd/agentshepherd/internal/telemetry"
	"github.com/AgentShepherd/agentshepherd/internal/types"
)

// createOpenAIResponse creates a test OpenAI response JSON
func createOpenAIResponse(toolCalls []openAIToolCall, content string) []byte {
	resp := openAIResponse{
		ID:      "test-id",
		Object:  "chat.completion",
		Created: 1234567890,
		Model:   "gpt-4",
		Choices: []openAIChoice{
			{
				Index: 0,
				Message: openAIMessage{
					Role:      "assistant",
					Content:   content,
					ToolCalls: toolCalls,
				},
				FinishReason: "tool_calls",
			},
		},
	}
	data, _ := json.Marshal(resp)
	return data
}

// createAnthropicResponse creates a test Anthropic response JSON
func createAnthropicResponse(content []anthropicContentBlock) []byte {
	resp := anthropicResponse{
		ID:         "test-id",
		Type:       "message",
		Role:       "assistant",
		Content:    content,
		Model:      "claude-3-opus",
		StopReason: "tool_use",
	}
	data, _ := json.Marshal(resp)
	return data
}

// setupTestRulesDir creates a temporary directory with test rules
func setupTestRulesDir(t *testing.T, rulesYAML string) string {
	t.Helper()
	tempDir, err := os.MkdirTemp("", "test-rules-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	if rulesYAML != "" {
		rulePath := filepath.Join(tempDir, "test-rules.yaml")
		if err := os.WriteFile(rulePath, []byte(rulesYAML), 0644); err != nil {
			t.Fatalf("Failed to write test rules: %v", err)
		}
	}

	return tempDir
}

// createTestInterceptor creates an interceptor with custom rules for testing
func createTestInterceptor(t *testing.T, rulesYAML string) (*Interceptor, func()) {
	t.Helper()

	tempDir := setupTestRulesDir(t, rulesYAML)

	engine, err := rules.NewEngine(rules.EngineConfig{
		UserRulesDir:   tempDir,
		DisableBuiltin: true,
	})
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create engine: %v", err)
	}

	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create storage: %v", err)
	}

	interceptor := NewInterceptor(engine, storage)

	cleanup := func() {
		storage.Close()
		os.RemoveAll(tempDir)
	}

	return interceptor, cleanup
}

// TestInterceptOpenAIResponse_BlockDangerousTool tests blocking dangerous tool calls in OpenAI format
func TestInterceptOpenAIResponse_BlockDangerousTool(t *testing.T) {
	tests := []struct {
		name             string
		rulesYAML        string
		toolName         string
		arguments        string
		blockMode        types.BlockMode
		wantBlocked      bool
		wantToolRemoved  bool
		wantWarningInMsg bool
	}{
		{
			name: "block rm on root in remove mode",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "rm -rf /"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
		{
			name: "block rm on root in replace mode",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "rm -rf /"}`,
			blockMode:        types.BlockModeReplace,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
		{
			name: "allow safe command",
			rulesYAML: `
rules:
  - name: block-dangerous-rm
    block: "/"
    actions: [delete]
    message: "Dangerous command blocked"
    severity: critical
`,
			toolName:         "Bash",
			arguments:        `{"command": "ls -la"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      false,
			wantToolRemoved:  false,
			wantWarningInMsg: false,
		},
		{
			name: "block credential file read",
			rulesYAML: `
rules:
  - name: block-env-file
    block: "**/.env"
    actions: [read]
    message: "Credential file access blocked"
    severity: critical
`,
			toolName:         "Read",
			arguments:        `{"file_path": "/home/user/.env"}`,
			blockMode:        types.BlockModeRemove,
			wantBlocked:      true,
			wantToolRemoved:  true,
			wantWarningInMsg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset metrics before each test
			GetMetrics().Reset()

			interceptor, cleanup := createTestInterceptor(t, tt.rulesYAML)
			defer cleanup()

			// Create OpenAI response with tool call
			toolCalls := []openAIToolCall{
				{
					ID:   "call_123",
					Type: "function",
					Function: struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					}{
						Name:      tt.toolName,
						Arguments: tt.arguments,
					},
				},
			}
			responseBody := createOpenAIResponse(toolCalls, "")

			result, err := interceptor.InterceptOpenAIResponse(
				responseBody,
				"trace-1",
				"session-1",
				"gpt-4",
				types.APITypeOpenAI,
				tt.blockMode,
			)

			if err != nil {
				t.Fatalf("InterceptOpenAIResponse returned error: %v", err)
			}

			// Verify blocked status
			if result.HasBlockedCalls != tt.wantBlocked {
				t.Errorf("HasBlockedCalls = %v, want %v", result.HasBlockedCalls, tt.wantBlocked)
			}

			// Verify tool was removed/kept
			var parsedResp openAIResponse
			if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
				t.Fatalf("Failed to parse modified response: %v", err)
			}

			if len(parsedResp.Choices) == 0 {
				t.Fatal("Modified response has no choices")
			}

			toolCount := len(parsedResp.Choices[0].Message.ToolCalls)
			if tt.wantToolRemoved && toolCount != 0 {
				t.Errorf("Expected tool to be removed, but found %d tool calls", toolCount)
			}
			if !tt.wantToolRemoved && toolCount == 0 {
				t.Errorf("Expected tool to be kept, but no tool calls found")
			}

			// Verify warning message
			hasWarning := parsedResp.Choices[0].Message.Content != ""
			if tt.wantWarningInMsg && !hasWarning {
				t.Errorf("Expected warning message in content, but content is empty")
			}
			if !tt.wantWarningInMsg && hasWarning {
				t.Errorf("Expected no warning message, but got: %s", parsedResp.Choices[0].Message.Content)
			}
		})
	}
}

// TestInterceptOpenAIResponse_MultipleToolCalls tests handling multiple tool calls
func TestInterceptOpenAIResponse_MultipleToolCalls(t *testing.T) {
	// Reset metrics
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked rm -rf"
    severity: critical
`

	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	// Create response with multiple tool calls - one dangerous, others safe
	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /"}`,
			},
		},
		{
			ID:   "call_2",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "ls -la"}`,
			},
		},
		{
			ID:   "call_3",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Read",
				Arguments: `{"file_path": "/tmp/test.txt"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("InterceptOpenAIResponse returned error: %v", err)
	}

	// Should have 1 blocked call and 2 allowed calls
	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("Expected 1 blocked tool call, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 2 {
		t.Errorf("Expected 2 allowed tool calls, got %d", len(result.AllowedToolCalls))
	}

	// Parse modified response
	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse modified response: %v", err)
	}

	// Should have 2 tool calls remaining
	if len(parsedResp.Choices[0].Message.ToolCalls) != 2 {
		t.Errorf("Expected 2 tool calls in response, got %d", len(parsedResp.Choices[0].Message.ToolCalls))
	}

	// Verify the blocked one is not in the response
	for _, tc := range parsedResp.Choices[0].Message.ToolCalls {
		if tc.ID == "call_1" {
			t.Error("Blocked tool call (call_1) should not be in response")
		}
	}
}

// TestInterceptOpenAIResponse_EmptyResponse tests handling empty responses
func TestInterceptOpenAIResponse_EmptyResponse(t *testing.T) {
	interceptor, cleanup := createTestInterceptor(t, "")
	defer cleanup()

	tests := []struct {
		name         string
		responseBody []byte
		wantError    bool
	}{
		{
			name:         "empty body",
			responseBody: []byte{},
			wantError:    false,
		},
		{
			name:         "invalid json",
			responseBody: []byte("not json"),
			wantError:    false,
		},
		{
			name:         "empty choices",
			responseBody: []byte(`{"choices": []}`),
			wantError:    false,
		},
		{
			name:         "no tool calls",
			responseBody: createOpenAIResponse(nil, "Hello, world!"),
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interceptor.InterceptOpenAIResponse(
				tt.responseBody,
				"trace-1",
				"session-1",
				"gpt-4",
				types.APITypeOpenAI,
				types.BlockModeRemove,
			)

			if tt.wantError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Should return original body unchanged for invalid/empty responses
			if string(result.ModifiedResponse) != string(tt.responseBody) {
				t.Errorf("Expected response to be unchanged")
			}
		})
	}
}

// TestInterceptOpenAIResponse_DisabledInterceptor tests that disabled interceptor passes through
func TestInterceptOpenAIResponse_DisabledInterceptor(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-all
    block: "/**"
    actions: [read, write, delete, copy, move, execute]
    message: "Blocked"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	interceptor.SetEnabled(false)

	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Response should be unchanged when interceptor is disabled
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when interceptor is disabled")
	}

	// No blocked calls should be recorded
	if result.HasBlockedCalls {
		t.Error("HasBlockedCalls should be false when interceptor is disabled")
	}
}

// TestInterceptAnthropicResponse_BlockDangerousTool tests blocking in Anthropic format
func TestInterceptAnthropicResponse_BlockDangerousTool(t *testing.T) {
	tests := []struct {
		name            string
		rulesYAML       string
		toolName        string
		input           string
		blockMode       types.BlockMode
		wantBlocked     bool
		wantToolRemoved bool
		wantTextBlock   bool // Warning text block added
	}{
		{
			name: "block dangerous command remove mode",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "rm -rf /"}`,
			blockMode:       types.BlockModeRemove,
			wantBlocked:     true,
			wantToolRemoved: true,
			wantTextBlock:   true, // Warning text block added in remove mode
		},
		{
			name: "block dangerous command replace mode",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "rm -rf /"}`,
			blockMode:       types.BlockModeReplace,
			wantBlocked:     true,
			wantToolRemoved: true,
			wantTextBlock:   true, // Replaced with text block in replace mode
		},
		{
			name: "allow safe command",
			rulesYAML: `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`,
			toolName:        "Bash",
			input:           `{"command": "ls -la"}`,
			blockMode:       types.BlockModeRemove,
			wantBlocked:     false,
			wantToolRemoved: false,
			wantTextBlock:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			GetMetrics().Reset()

			interceptor, cleanup := createTestInterceptor(t, tt.rulesYAML)
			defer cleanup()

			// Create Anthropic response
			content := []anthropicContentBlock{
				{
					Type:  "tool_use",
					ID:    "toolu_123",
					Name:  tt.toolName,
					Input: json.RawMessage(tt.input),
				},
			}
			responseBody := createAnthropicResponse(content)

			result, err := interceptor.InterceptAnthropicResponse(
				responseBody,
				"trace-1",
				"session-1",
				"claude-3-opus",
				types.APITypeAnthropic,
				tt.blockMode,
			)

			if err != nil {
				t.Fatalf("InterceptAnthropicResponse returned error: %v", err)
			}

			if result.HasBlockedCalls != tt.wantBlocked {
				t.Errorf("HasBlockedCalls = %v, want %v", result.HasBlockedCalls, tt.wantBlocked)
			}

			// Parse modified response
			var parsedResp anthropicResponse
			if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
				t.Fatalf("Failed to parse modified response: %v", err)
			}

			// Check tool_use blocks
			toolUseCount := 0
			textBlockCount := 0
			for _, block := range parsedResp.Content {
				if block.Type == "tool_use" {
					toolUseCount++
				}
				if block.Type == "text" {
					textBlockCount++
				}
			}

			if tt.wantToolRemoved && toolUseCount != 0 {
				t.Errorf("Expected tool_use to be removed, found %d", toolUseCount)
			}
			if !tt.wantToolRemoved && toolUseCount == 0 {
				t.Errorf("Expected tool_use to be kept, but none found")
			}
			if tt.wantTextBlock && textBlockCount == 0 {
				t.Errorf("Expected text block (warning/replacement), but none found")
			}
		})
	}
}

// TestInterceptAnthropicResponse_TextBlockPassThrough tests that text blocks are unchanged
func TestInterceptAnthropicResponse_TextBlockPassThrough(t *testing.T) {
	interceptor, cleanup := createTestInterceptor(t, "")
	defer cleanup()

	// Create response with only text blocks
	content := []anthropicContentBlock{
		{
			Type: "text",
			Text: "Hello, this is a text response.",
		},
		{
			Type: "text",
			Text: "Another text block.",
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(
		responseBody,
		"trace-1",
		"session-1",
		"claude-3-opus",
		types.APITypeAnthropic,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not have any blocked calls
	if result.HasBlockedCalls {
		t.Error("Expected no blocked calls for text-only response")
	}

	// Response should be unchanged
	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if len(parsedResp.Content) != 2 {
		t.Errorf("Expected 2 content blocks, got %d", len(parsedResp.Content))
	}
	for _, block := range parsedResp.Content {
		if block.Type != "text" {
			t.Errorf("Expected all blocks to be text, got %s", block.Type)
		}
	}
}

// TestInterceptAnthropicResponse_MixedContent tests mixed text and tool_use blocks
func TestInterceptAnthropicResponse_MixedContent(t *testing.T) {
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-root-delete
    block: "/"
    actions: [delete]
    message: "Bash blocked"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	content := []anthropicContentBlock{
		{
			Type: "text",
			Text: "Let me help you with that.",
		},
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
		{
			Type:  "tool_use",
			ID:    "toolu_2",
			Name:  "Read",
			Input: json.RawMessage(`{"file_path": "/tmp/test.txt"}`),
		},
		{
			Type: "text",
			Text: "Additional text.",
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(
		responseBody,
		"trace-1",
		"session-1",
		"claude-3-opus",
		types.APITypeAnthropic,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(result.BlockedToolCalls) != 1 {
		t.Errorf("Expected 1 blocked call, got %d", len(result.BlockedToolCalls))
	}
	if len(result.AllowedToolCalls) != 1 {
		t.Errorf("Expected 1 allowed call, got %d", len(result.AllowedToolCalls))
	}

	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have: 2 original text blocks + 1 allowed tool_use + 1 warning text block
	textCount := 0
	toolUseCount := 0
	for _, block := range parsedResp.Content {
		if block.Type == "text" {
			textCount++
		}
		if block.Type == "tool_use" {
			toolUseCount++
		}
	}

	if toolUseCount != 1 {
		t.Errorf("Expected 1 tool_use block, got %d", toolUseCount)
	}
	// 2 original text blocks + 1 warning = 3
	if textCount < 3 {
		t.Errorf("Expected at least 3 text blocks (2 original + 1 warning), got %d", textCount)
	}
}

// TestInterceptToolCalls_RoutesToCorrectHandler tests API type routing
func TestInterceptToolCalls_RoutesToCorrectHandler(t *testing.T) {
	tests := []struct {
		name    string
		apiType types.APIType
	}{
		{
			name:    "routes to OpenAI handler",
			apiType: types.APITypeOpenAI,
		},
		{
			name:    "routes to Anthropic handler",
			apiType: types.APITypeAnthropic,
		},
		{
			name:    "defaults to OpenAI for unknown",
			apiType: types.APIType("unknown"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			interceptor, cleanup := createTestInterceptor(t, "")
			defer cleanup()

			var responseBody []byte
			if tt.apiType == types.APITypeAnthropic {
				responseBody = createAnthropicResponse([]anthropicContentBlock{
					{Type: "text", Text: "Hello"},
				})
			} else {
				responseBody = createOpenAIResponse(nil, "Hello")
			}

			result, err := interceptor.InterceptToolCalls(
				responseBody,
				"trace-1",
				"session-1",
				"test-model",
				tt.apiType,
				types.BlockModeRemove,
			)

			if err != nil {
				t.Errorf("InterceptToolCalls returned error: %v", err)
			}

			// Should successfully parse and return
			if result.ModifiedResponse == nil {
				t.Error("ModifiedResponse should not be nil")
			}
		})
	}
}

// TestInterceptOpenAIResponse_NilEngine tests handling nil engine
func TestInterceptOpenAIResponse_NilEngine(t *testing.T) {
	interceptor := &Interceptor{
		engine:  nil,
		storage: nil,
		enabled: true,
	}

	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should pass through unchanged when engine is nil
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when engine is nil")
	}
}

// TestBuildWarningContent tests the warning message builder
func TestBuildWarningContent(t *testing.T) {
	tests := []struct {
		name         string
		blockedCalls []BlockedToolCall
		wantContains []string
	}{
		{
			name: "single blocked call with message",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Bash",
					},
					MatchResult: rules.MatchResult{
						Message: "Dangerous command",
					},
				},
			},
			wantContains: []string{"[SECURITY]", "Bash", "Dangerous command"},
		},
		{
			name: "multiple blocked calls",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Bash",
					},
					MatchResult: rules.MatchResult{
						Message: "Blocked rm",
					},
				},
				{
					ToolCall: telemetry.ToolCall{
						Name: "Read",
					},
					MatchResult: rules.MatchResult{
						Message: "Blocked credential read",
					},
				},
			},
			wantContains: []string{"[SECURITY]", "Bash", "Read", "Blocked rm", "Blocked credential read"},
		},
		{
			name: "blocked call without message",
			blockedCalls: []BlockedToolCall{
				{
					ToolCall: telemetry.ToolCall{
						Name: "Write",
					},
					MatchResult: rules.MatchResult{},
				},
			},
			wantContains: []string{"[SECURITY]", "Write"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildWarningContent(tt.blockedCalls)

			for _, want := range tt.wantContains {
				if !strings.Contains(result, want) {
					t.Errorf("buildWarningContent() = %q, want to contain %q", result, want)
				}
			}
		})
	}
}

// TestBuildReplaceMessage tests the replace message builder
func TestBuildReplaceMessage(t *testing.T) {
	tests := []struct {
		name         string
		matchResult  rules.MatchResult
		wantContains string
	}{
		{
			name: "with custom message",
			matchResult: rules.MatchResult{
				Message:  "Custom block reason",
				RuleName: "test-rule",
			},
			wantContains: "Custom block reason (rule: test-rule)",
		},
		{
			name: "without custom message",
			matchResult: rules.MatchResult{
				RuleName: "test-rule",
			},
			wantContains: "blocked by rule: test-rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildReplaceMessage(tt.matchResult)
			if result != tt.wantContains {
				t.Errorf("buildReplaceMessage() = %q, want %q", result, tt.wantContains)
			}
		})
	}
}

// TestBuildReplaceWarning tests the replace warning builder
func TestBuildReplaceWarning(t *testing.T) {
	blockedCalls := []BlockedToolCall{
		{
			ToolCall: telemetry.ToolCall{
				Name: "Bash",
			},
			MatchResult: rules.MatchResult{
				RuleName: "block-bash",
				Message:  "Dangerous",
			},
		},
	}

	result := buildReplaceWarning(blockedCalls)

	wantContains := []string{
		"[AgentShepherd]",
		"blocked",
		"Bash",
		"Dangerous",
		"block-bash",
	}

	for _, want := range wantContains {
		if !strings.Contains(result, want) {
			t.Errorf("buildReplaceWarning() = %q, want to contain %q", result, want)
		}
	}
}

// TestInterceptorEnableDisable tests enable/disable functionality
func TestInterceptorEnableDisable(t *testing.T) {
	interceptor, cleanup := createTestInterceptor(t, "")
	defer cleanup()

	// Should be enabled by default
	if !interceptor.IsEnabled() {
		t.Error("Interceptor should be enabled by default")
	}

	// Disable
	interceptor.SetEnabled(false)
	if interceptor.IsEnabled() {
		t.Error("Interceptor should be disabled after SetEnabled(false)")
	}

	// Re-enable
	interceptor.SetEnabled(true)
	if !interceptor.IsEnabled() {
		t.Error("Interceptor should be enabled after SetEnabled(true)")
	}
}

// TestInterceptorGetters tests getter methods
func TestInterceptorGetters(t *testing.T) {
	interceptor, cleanup := createTestInterceptor(t, "")
	defer cleanup()

	if interceptor.GetEngine() == nil {
		t.Error("GetEngine() should not return nil")
	}

	if interceptor.GetStorage() == nil {
		t.Error("GetStorage() should not return nil")
	}
}

// TestInterceptOpenAIResponse_ExistingContentPreserved tests that existing content is preserved
func TestInterceptOpenAIResponse_ExistingContentPreserved(t *testing.T) {
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rule
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	existingContent := "I will help you with that task."
	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, existingContent)

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Content should contain both the original content and the warning
	content := parsedResp.Choices[0].Message.Content
	if !strings.Contains(content, existingContent) {
		t.Errorf("Original content should be preserved, got: %s", content)
	}
	if !strings.Contains(content, "[SECURITY]") {
		t.Errorf("Warning should be appended, got: %s", content)
	}
}

// TestInterceptOpenAIResponse_MalformedToolCallArguments tests handling malformed arguments
func TestInterceptOpenAIResponse_MalformedToolCallArguments(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Blocked"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	// Create tool call with malformed arguments (not valid JSON for command extraction)
	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `not-valid-json`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	// Should not error, just treat as non-matching
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should not block because the pattern can't match invalid JSON
	if result.HasBlockedCalls {
		t.Error("Should not block tool calls with malformed arguments that don't match pattern")
	}
}

// TestInterceptAnthropicResponse_DisabledInterceptor tests disabled interceptor for Anthropic
func TestInterceptAnthropicResponse_DisabledInterceptor(t *testing.T) {
	rulesYAML := `
rules:
  - name: block-all
    block: "/**"
    actions: [read, write, delete, copy, move, execute]
    message: "Blocked"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	interceptor.SetEnabled(false)

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(
		responseBody,
		"trace-1",
		"session-1",
		"claude-3-opus",
		types.APITypeAnthropic,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Response should be unchanged when interceptor is disabled
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when interceptor is disabled")
	}

	if result.HasBlockedCalls {
		t.Error("HasBlockedCalls should be false when interceptor is disabled")
	}
}

// TestInterceptAnthropicResponse_NilEngine tests nil engine handling for Anthropic
func TestInterceptAnthropicResponse_NilEngine(t *testing.T) {
	interceptor := &Interceptor{
		engine:  nil,
		storage: nil,
		enabled: true,
	}

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(
		responseBody,
		"trace-1",
		"session-1",
		"claude-3-opus",
		types.APITypeAnthropic,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	// Should pass through unchanged when engine is nil
	if string(result.ModifiedResponse) != string(responseBody) {
		t.Error("Expected response to be unchanged when engine is nil")
	}
}

// TestInterceptAnthropicResponse_EmptyResponse tests empty responses for Anthropic
func TestInterceptAnthropicResponse_EmptyResponse(t *testing.T) {
	interceptor, cleanup := createTestInterceptor(t, "")
	defer cleanup()

	tests := []struct {
		name         string
		responseBody []byte
	}{
		{
			name:         "empty body",
			responseBody: []byte{},
		},
		{
			name:         "invalid json",
			responseBody: []byte("not json"),
		},
		{
			name:         "empty content",
			responseBody: createAnthropicResponse([]anthropicContentBlock{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := interceptor.InterceptAnthropicResponse(
				tt.responseBody,
				"trace-1",
				"session-1",
				"claude-3-opus",
				types.APITypeAnthropic,
				types.BlockModeRemove,
			)

			// Should not error
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Should return original body unchanged for invalid/empty responses
			if string(result.ModifiedResponse) != string(tt.responseBody) {
				t.Errorf("Expected response to be unchanged")
			}
		})
	}
}

// TestInterceptOpenAIResponse_ReplaceModeMessage tests replace mode message formatting
func TestInterceptOpenAIResponse_ReplaceModeMessage(t *testing.T) {
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Security violation detected"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeReplace,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp openAIResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	content := parsedResp.Choices[0].Message.Content
	// In replace mode, should contain AgentShepherd message
	if !strings.Contains(content, "[AgentShepherd]") {
		t.Errorf("Replace mode content should contain [AgentShepherd], got: %s", content)
	}
	if !strings.Contains(content, "Security violation detected") {
		t.Errorf("Replace mode content should contain rule message, got: %s", content)
	}
}

// TestInterceptAnthropicResponse_ReplaceModeMessage tests replace mode for Anthropic
func TestInterceptAnthropicResponse_ReplaceModeMessage(t *testing.T) {
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: "/"
    actions: [delete]
    message: "Security violation detected"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	content := []anthropicContentBlock{
		{
			Type:  "tool_use",
			ID:    "toolu_1",
			Name:  "Bash",
			Input: json.RawMessage(`{"command": "rm -rf /"}`),
		},
	}
	responseBody := createAnthropicResponse(content)

	result, err := interceptor.InterceptAnthropicResponse(
		responseBody,
		"trace-1",
		"session-1",
		"claude-3-opus",
		types.APITypeAnthropic,
		types.BlockModeReplace,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	var parsedResp anthropicResponse
	if err := json.Unmarshal(result.ModifiedResponse, &parsedResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// In replace mode, should have a text block with the replacement message
	hasReplacementText := false
	for _, block := range parsedResp.Content {
		if block.Type == "text" && strings.Contains(block.Text, "[AgentShepherd]") {
			hasReplacementText = true
			if !strings.Contains(block.Text, "Security violation detected") {
				t.Errorf("Replacement text should contain rule message, got: %s", block.Text)
			}
		}
	}

	if !hasReplacementText {
		t.Error("Replace mode should add text block with AgentShepherd message")
	}

	// Should have no tool_use blocks (was replaced)
	for _, block := range parsedResp.Content {
		if block.Type == "tool_use" {
			t.Error("Replace mode should remove tool_use block")
		}
	}
}

// TestInterceptionResult_Fields tests InterceptionResult field values
func TestInterceptionResult_Fields(t *testing.T) {
	GetMetrics().Reset()

	rulesYAML := `
rules:
  - name: block-rm
    block: ["/", "/important", "/important/**"]
    actions: [delete]
    message: "Blocked rm"
    severity: critical
`
	interceptor, cleanup := createTestInterceptor(t, rulesYAML)
	defer cleanup()

	toolCalls := []openAIToolCall{
		{
			ID:   "call_1",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "rm -rf /important"}`,
			},
		},
		{
			ID:   "call_2",
			Type: "function",
			Function: struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			}{
				Name:      "Bash",
				Arguments: `{"command": "echo hello"}`,
			},
		},
	}
	responseBody := createOpenAIResponse(toolCalls, "")

	result, err := interceptor.InterceptOpenAIResponse(
		responseBody,
		"trace-1",
		"session-1",
		"gpt-4",
		types.APITypeOpenAI,
		types.BlockModeRemove,
	)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Check BlockedToolCalls
	if len(result.BlockedToolCalls) != 1 {
		t.Fatalf("Expected 1 blocked call, got %d", len(result.BlockedToolCalls))
	}

	blocked := result.BlockedToolCalls[0]
	if blocked.ToolCall.Name != "Bash" {
		t.Errorf("Blocked tool name = %s, want Bash", blocked.ToolCall.Name)
	}
	if blocked.ToolCall.ID != "call_1" {
		t.Errorf("Blocked tool ID = %s, want call_1", blocked.ToolCall.ID)
	}
	if blocked.MatchResult.RuleName != "block-rm" {
		t.Errorf("MatchResult.RuleName = %s, want block-rm", blocked.MatchResult.RuleName)
	}
	if blocked.MatchResult.Action != rules.ActionBlock {
		t.Errorf("MatchResult.Action = %s, want %s", blocked.MatchResult.Action, rules.ActionBlock)
	}

	// Check AllowedToolCalls
	if len(result.AllowedToolCalls) != 1 {
		t.Fatalf("Expected 1 allowed call, got %d", len(result.AllowedToolCalls))
	}

	allowed := result.AllowedToolCalls[0]
	if allowed.Name != "Bash" {
		t.Errorf("Allowed tool name = %s, want Bash", allowed.Name)
	}
	if allowed.ID != "call_2" {
		t.Errorf("Allowed tool ID = %s, want call_2", allowed.ID)
	}

	// Check HasBlockedCalls
	if !result.HasBlockedCalls {
		t.Error("HasBlockedCalls should be true")
	}

	// Check ModifiedResponse is not empty
	if len(result.ModifiedResponse) == 0 {
		t.Error("ModifiedResponse should not be empty")
	}
}
