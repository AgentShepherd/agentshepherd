package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

func TestExtractToolCallsFromJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantLen   int
		wantNames []string
	}{
		{
			name:      "OpenAI Chat format",
			input:     `{"messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"Bash","arguments":"{\"command\":\"cat /etc/passwd\"}"}}]}]}`,
			wantLen:   1,
			wantNames: []string{"Bash"},
		},
		{
			name:      "Anthropic format",
			input:     `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"1","name":"Read","input":{"file_path":"/etc/shadow"}}]}]}`,
			wantLen:   1,
			wantNames: []string{"Read"},
		},
		{
			name:      "OpenAI Responses format",
			input:     `{"input":[{"type":"function_call","call_id":"1","name":"Write","arguments":"{\"file_path\":\"/tmp/x\"}"}]}`,
			wantLen:   1,
			wantNames: []string{"Write"},
		},
		{
			name:    "tool definitions not matched",
			input:   `{"tools":[{"type":"function","function":{"name":"Bash","description":"run commands","parameters":{"type":"object"}}}]}`,
			wantLen: 0,
		},
		{
			name:      "multiple tool calls in OpenAI Chat",
			input:     `{"messages":[{"role":"assistant","tool_calls":[{"id":"1","type":"function","function":{"name":"Bash","arguments":"{}"}},{"id":"2","type":"function","function":{"name":"Read","arguments":"{}"}}]}]}`,
			wantLen:   2,
			wantNames: []string{"Bash", "Read"},
		},
		{
			name:      "Anthropic multiple content blocks",
			input:     `{"messages":[{"role":"assistant","content":[{"type":"text","text":"Let me check"},{"type":"tool_use","id":"1","name":"Bash","input":{"command":"ls"}},{"type":"tool_use","id":"2","name":"Read","input":{"file_path":"/tmp/x"}}]}]}`,
			wantLen:   2,
			wantNames: []string{"Bash", "Read"},
		},
		{
			name:    "empty body",
			input:   `{}`,
			wantLen: 0,
		},
		{
			name:    "invalid JSON",
			input:   `not json`,
			wantLen: 0,
		},
		{
			name:    "null body",
			input:   `null`,
			wantLen: 0,
		},
		{
			name:      "deeply nested Anthropic in multi-turn conversation",
			input:     `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"tool_use","id":"1","name":"Edit","input":{"file_path":"/tmp/x","old_string":"a","new_string":"b"}}]},{"role":"user","content":"thanks"}]}`,
			wantLen:   1,
			wantNames: []string{"Edit"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractToolCallsFromJSON([]byte(tt.input))
			if len(got) != tt.wantLen {
				t.Errorf("extractToolCallsFromJSON() returned %d tool calls, want %d", len(got), tt.wantLen)
				for i, tc := range got {
					t.Logf("  [%d] name=%q args=%s", i, tc.Name, string(tc.Arguments))
				}
				return
			}
			for i, wantName := range tt.wantNames {
				if got[i].Name != wantName {
					t.Errorf("tool call [%d] name = %q, want %q", i, got[i].Name, wantName)
				}
			}
		})
	}
}

func TestBuildUpstreamURL_EndpointMode(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		reqPath  string
		model    string
		wantHost string
		wantPath string
	}{
		{
			name:     "dedup /v1 prefix",
			upstream: "http://localhost:11434/v1",
			reqPath:  "/v1/chat/completions",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "dedup /v1/ trailing slash",
			upstream: "http://localhost:11434/v1/",
			reqPath:  "/v1/chat/completions",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "no prefix — plain host",
			upstream: "http://localhost:11434",
			reqPath:  "/v1/chat/completions",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "no false match on partial segment /v1 vs /v1beta",
			upstream: "http://localhost:11434/v1",
			reqPath:  "/v1beta/completions",
			model:    "x",
			wantHost: "localhost:11434",
			wantPath: "/v1beta/completions",
		},
		{
			name:     "responses normalization",
			upstream: "http://localhost:11434/v1",
			reqPath:  "/responses",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/responses",
		},
		{
			name:     "provider model not resolved in endpoint mode",
			upstream: "http://localhost:11434/v1",
			reqPath:  "/v1/chat/completions",
			model:    "gpt-4o",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
		// Issue #19: /api/v1 prefix from clients like PhpStorm
		{
			name:     "issue19: /api/v1 prefix stripped in endpoint mode",
			upstream: "http://localhost:11434/v1",
			reqPath:  "/api/v1/chat/completions",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "issue19: /api/v1 prefix stripped — plain host endpoint",
			upstream: "http://localhost:11434",
			reqPath:  "/api/v1/chat/completions",
			model:    "qwen3",
			wantHost: "localhost:11434",
			wantPath: "/v1/chat/completions",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.upstream)
			p := &Proxy{upstreamURL: u, autoMode: false}

			got, _, err := p.buildUpstreamURL(tt.reqPath, tt.model)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

func TestBuildUpstreamURL_AutoMode(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		reqPath  string
		model    string
		wantHost string
		wantPath string
	}{
		{
			name:     "qwen3 resolves to dashscope",
			upstream: "http://fallback:8080",
			reqPath:  "/v1/chat/completions",
			model:    "qwen3",
			wantHost: "dashscope.aliyuncs.com",
			wantPath: "/compatible-mode/v1/chat/completions",
		},
		{
			name:     "gpt-4o resolves to openai",
			upstream: "http://fallback:8080",
			reqPath:  "/v1/chat/completions",
			model:    "gpt-4o",
			wantHost: "api.openai.com",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "unknown model uses fallback",
			upstream: "http://fallback:8080",
			reqPath:  "/v1/chat/completions",
			model:    "unknown-model",
			wantHost: "fallback:8080",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "codex resolves to chatgpt backend",
			upstream: "http://fallback:8080",
			reqPath:  "/v1/chat/completions",
			model:    "codex-mini",
			wantHost: "chatgpt.com",
			wantPath: "/backend-api/codex/v1/chat/completions",
		},
		{
			name:     "responses normalized for pathless provider",
			upstream: "http://fallback:8080",
			reqPath:  "/responses",
			model:    "gpt-4o",
			wantHost: "api.openai.com",
			wantPath: "/v1/responses",
		},
		{
			name:     "responses NOT normalized for provider with path",
			upstream: "http://fallback:8080",
			reqPath:  "/responses",
			model:    "codex-mini",
			wantHost: "chatgpt.com",
			wantPath: "/backend-api/codex/responses",
		},
		// Issue #19: client sends /api/v1/... — the /api prefix must be
		// stripped so the upstream URL doesn't become
		// https://api.openai.com/api/v1/chat/completions (404).
		{
			name:     "issue19: /api/v1 prefix stripped for openai",
			upstream: "http://fallback:8080",
			reqPath:  "/api/v1/chat/completions",
			model:    "gpt-4o",
			wantHost: "api.openai.com",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "issue19: /api/v1 prefix stripped for anthropic",
			upstream: "http://fallback:8080",
			reqPath:  "/api/v1/messages",
			model:    "claude-sonnet-4-5-20250929",
			wantHost: "api.anthropic.com",
			wantPath: "/v1/messages",
		},
		{
			name:     "issue19: /api/v1 prefix stripped for deepseek",
			upstream: "http://fallback:8080",
			reqPath:  "/api/v1/chat/completions",
			model:    "deepseek-chat",
			wantHost: "api.deepseek.com",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "issue19: /api/v1 prefix stripped for fallback",
			upstream: "http://fallback:8080",
			reqPath:  "/api/v1/chat/completions",
			model:    "unknown-model",
			wantHost: "fallback:8080",
			wantPath: "/v1/chat/completions",
		},
		{
			name:     "issue19: /api prefix stripped for responses endpoint",
			upstream: "http://fallback:8080",
			reqPath:  "/api/responses",
			model:    "gpt-4o",
			wantHost: "api.openai.com",
			wantPath: "/v1/responses",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, _ := url.Parse(tt.upstream)
			p := &Proxy{upstreamURL: u, autoMode: true}

			got, _, err := p.buildUpstreamURL(tt.reqPath, tt.model)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Host != tt.wantHost {
				t.Errorf("host = %q, want %q", got.Host, tt.wantHost)
			}
			if got.Path != tt.wantPath {
				t.Errorf("path = %q, want %q", got.Path, tt.wantPath)
			}
		})
	}
}

// setupTestProxy creates a proxy pointed at the given upstream, with security enabled.
func setupTestProxy(t *testing.T, upstream *httptest.Server) *Proxy {
	t.Helper()
	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	return p
}

// setupSecurityWithRules sets up the global security manager with the given rules.
// Returns a cleanup function to restore original state.
func setupSecurityWithRules(t *testing.T, yamlRules string) func() { //nolint:unparam
	t.Helper()

	// Write rules to temp directory
	tempDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tempDir, "test-rules.yaml"), []byte(yamlRules), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Create rules engine from YAML (no builtin rules)
	engine, err := rules.NewEngine(rules.EngineConfig{
		UserRulesDir:   tempDir,
		DisableBuiltin: true,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Create in-memory storage (no disk I/O)
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	// Create interceptor and lightweight manager
	interceptor := security.NewInterceptor(engine, storage)
	mgr := security.NewManagerForTest(interceptor)
	security.SetGlobalManager(mgr)

	return func() {
		security.SetGlobalManager(nil)
		storage.Close()
	}
}

// SECURITY: Anthropic tool_use blocks in message content must be scanned by Layer 0.
func TestLayer0_AnthropicToolUseInContent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	cleanup := setupSecurityWithRules(t, `
rules:
  - block: "**/.ssh/id_*"
    actions: [read]
    message: "Cannot read SSH keys"
`)
	defer cleanup()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":      "claude-3-opus-20240229",
		"max_tokens": 1024,
		"messages": []map[string]any{
			{
				"role": "assistant",
				"content": []map[string]any{
					{
						"type":  "tool_use",
						"id":    "toolu_01",
						"name":  "Bash",
						"input": map[string]string{"command": "cat ~/.ssh/id_rsa"},
					},
				},
			},
			{
				"role": "user",
				"content": []map[string]any{
					{
						"type":        "tool_result",
						"tool_use_id": "toolu_01",
						"content":     "key contents here",
					},
				},
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("SECURITY: Anthropic tool_use in content was NOT blocked (status %d, body: %s)", rr.Code, rr.Body.String())
	}
}

// SECURITY: OpenAI tool_calls format must still be scanned (regression test).
func TestLayer0_OpenAIToolCallsBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	cleanup := setupSecurityWithRules(t, `
rules:
  - block: "**/.ssh/id_*"
    actions: [read]
    message: "Cannot read SSH keys"
`)
	defer cleanup()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model": "gpt-4",
		"messages": []map[string]any{
			{
				"role":    "assistant",
				"content": "I'll read that file for you.",
				"tool_calls": []map[string]any{
					{
						"id":   "call_1",
						"type": "function",
						"function": map[string]string{
							"name":      "Bash",
							"arguments": `{"command":"cat ~/.ssh/id_rsa"}`,
						},
					},
				},
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("OpenAI tool_calls should be blocked (status %d)", rr.Code)
	}
}

// Normal Anthropic text content must NOT be blocked (false positive check).
func TestLayer0_AnthropicTextContentNotBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	cleanup := setupSecurityWithRules(t, `
rules:
  - block: "**/.ssh/id_*"
    actions: [read]
    message: "Cannot read SSH keys"
`)
	defer cleanup()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":      "claude-3-opus-20240229",
		"max_tokens": 1024,
		"messages": []map[string]any{
			{"role": "user", "content": "Hello, what's the weather?"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Errorf("Normal Anthropic text content should NOT be blocked (status %d, body: %s)", rr.Code, rr.Body.String())
	}
}

// Anthropic tool_use with safe commands must NOT be blocked (false positive check).
func TestLayer0_AnthropicSafeToolUseNotBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	cleanup := setupSecurityWithRules(t, `
rules:
  - block: "**/.ssh/id_*"
    actions: [read]
    message: "Cannot read SSH keys"
`)
	defer cleanup()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":      "claude-3-opus-20240229",
		"max_tokens": 1024,
		"messages": []map[string]any{
			{
				"role": "assistant",
				"content": []map[string]any{
					{
						"type":  "tool_use",
						"id":    "toolu_01",
						"name":  "Bash",
						"input": map[string]string{"command": "ls /tmp"},
					},
				},
			},
			{
				"role": "user",
				"content": []map[string]any{
					{
						"type":        "tool_result",
						"tool_use_id": "toolu_01",
						"content":     "file1.txt\nfile2.txt",
					},
				},
			},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code == http.StatusForbidden {
		t.Errorf("Safe Anthropic tool_use should NOT be blocked (status %d, body: %s)", rr.Code, rr.Body.String())
	}
}

// SECURITY: Unsupported Content-Encoding must be rejected (fail-closed).
func TestLayer0_UnsupportedContentEncodingRejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SECURITY: request with unsupported Content-Encoding reached upstream")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"test"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "br")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Unsupported Content-Encoding 'br' should return 415, got %d", rr.Code)
	}
}

// Supported Content-Encoding (gzip) must pass through.
func TestLayer0_GzipContentEncodingAccepted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(body)
	gw.Close()

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", &buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnsupportedMediaType {
		t.Errorf("Gzip Content-Encoding should be accepted, got 415")
	}
}

// No Content-Encoding at all must pass through normally.
func TestLayer0_NoContentEncodingAccepted(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}`)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code == http.StatusUnsupportedMediaType {
		t.Errorf("No Content-Encoding should be accepted, got 415")
	}
}

// Test: "Trailer" (not "Trailers") is in hop-by-hop header list.
// RFC 7230 §4.1.2 defines the header as "Trailer" (singular).
func TestHopByHopHeaders_TrailerSingular(t *testing.T) {
	if !HopByHopHeaders["Trailer"] {
		t.Error("HopByHopHeaders should contain 'Trailer' (singular per RFC 7230)")
	}
	if HopByHopHeaders["Trailers"] {
		t.Error("HopByHopHeaders should NOT contain 'Trailers' (plural is not a valid HTTP header)")
	}
}

// Test: streaming path must strip hop-by-hop headers (same as non-streaming).
func TestStreamingRequest_StripsHopByHopHeaders(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
		w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Trailer", "X-Checksum")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if receivedHeaders.Get("Connection") != "" {
		t.Error("hop-by-hop header 'Connection' should be stripped in streaming mode")
	}
	if receivedHeaders.Get("Upgrade") != "" {
		t.Error("hop-by-hop header 'Upgrade' should be stripped in streaming mode")
	}
	if receivedHeaders.Get("Trailer") != "" {
		t.Error("hop-by-hop header 'Trailer' should be stripped in streaming mode")
	}
}

// Test: escapeJSON must not return raw unescaped strings on error.
func TestEscapeJSON_SpecialCharacters(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`say "hi"`, `say \"hi\"`},
		{`path\to\file`, `path\\to\\file`},
		{`line1` + "\n" + `line2`, `line1\nline2`},
		{"", ""},
	}
	for _, tt := range tests {
		got := escapeJSON(tt.input)
		if got != tt.want {
			t.Errorf("escapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// detectAPIType tests
func TestDetectAPIType(t *testing.T) {
	tests := []struct {
		path string
		want types.APIType
	}{
		{"/v1/messages", types.APITypeAnthropic},
		{"/anthropic/v1/messages", types.APITypeAnthropic},
		{"/v1/responses", types.APITypeOpenAIResponses},
		{"/api/responses", types.APITypeOpenAIResponses},
		{"/v1/chat/completions", types.APITypeOpenAICompletion},
		{"/v1/completions", types.APITypeOpenAICompletion},
	}
	for _, tt := range tests {
		got := detectAPIType(tt.path)
		if got != tt.want {
			t.Errorf("detectAPIType(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Real AI agent simulation tests
// ---------------------------------------------------------------------------

// TestAgent_ClaudeCode_Streaming simulates Claude Code (Anthropic Messages API)
// streaming a tool_use response with hop-by-hop headers that real HTTP clients send.
func TestAgent_ClaudeCode_Streaming(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		// Simulate Anthropic streaming: message_start → content_block_start → content_block_delta → message_stop
		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":25,"output_tokens":1}}}` + "\n\n",
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\":\"ls /tmp\"}"}}` + "\n\n",
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n",
			`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":42}}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, e := range events {
			w.Write([]byte(e))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":      "claude-sonnet-4-5-20250929",
		"max_tokens": 4096,
		"stream":     true,
		"messages":   []map[string]any{{"role": "user", "content": "list files in /tmp"}},
		"tools": []map[string]any{{
			"name":        "Bash",
			"description": "Run a bash command",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]string{"type": "string"}},
				"required":   []string{"command"},
			},
		}},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test-key")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	// Real HTTP clients send these hop-by-hop headers
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Trailer", "X-Stream-Checksum")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// Verify hop-by-hop headers were stripped before reaching upstream
	if receivedHeaders.Get("Connection") != "" {
		t.Error("Connection header leaked to Anthropic upstream in Claude Code streaming")
	}
	if receivedHeaders.Get("Trailer") != "" {
		t.Error("Trailer header leaked to Anthropic upstream in Claude Code streaming")
	}
	// Verify auth header was forwarded (client-provided)
	if receivedHeaders.Get("X-Api-Key") != "sk-ant-test-key" {
		t.Error("X-Api-Key should be forwarded when client provides auth")
	}
	// Verify response was streamed
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestAgent_Cursor_OpenAI_Streaming simulates Cursor (OpenAI Chat Completions API)
// streaming a function_call with hop-by-hop headers.
func TestAgent_Cursor_OpenAI_Streaming(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"Bash","arguments":""}}]}}]}` + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"command\":"}}]}}]}` + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"echo hello\"}"}}]}}]}` + "\n\n",
			`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":20}}` + "\n\n",
			`data: [DONE]` + "\n\n",
		}
		for _, e := range events {
			w.Write([]byte(e))
		}
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":  "gpt-4o",
		"stream": true,
		"messages": []map[string]any{
			{"role": "user", "content": "run echo hello"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-openai-test-key")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.Header.Set("Trailer", "X-Request-Id")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// Verify ALL hop-by-hop headers stripped
	if receivedHeaders.Get("Connection") != "" {
		t.Error("Connection header leaked to OpenAI upstream")
	}
	if receivedHeaders.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding header leaked to OpenAI upstream")
	}
	if receivedHeaders.Get("Trailer") != "" {
		t.Error("Trailer header leaked to OpenAI upstream")
	}
	// Auth preserved
	if receivedHeaders.Get("Authorization") != "Bearer sk-openai-test-key" {
		t.Error("Authorization header should be forwarded")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestAgent_Codex_NonStreaming simulates OpenAI Codex (non-streaming) with
// response content containing special characters that need JSON escaping.
func TestAgent_Codex_NonStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response with content containing quotes, backslashes, newlines
		resp := map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{
					"role":    "assistant",
					"content": "Here's the file:\n```\npath=\"C:\\Users\\test\"\necho \"hello world\"\n```",
				},
			}},
			"usage": map[string]any{
				"prompt_tokens":     30,
				"completion_tokens": 45,
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":  "gpt-4o",
		"stream": false,
		"messages": []map[string]any{
			{"role": "user", "content": "show me the file"},
		},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify response body is valid JSON (not corrupted by escaping)
	var result map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("response body is not valid JSON: %v\nbody: %s", err, rr.Body.String())
	}
}

// TestAgent_DeepSeek_NonStreaming_HopByHop verifies non-streaming requests
// also strip hop-by-hop headers correctly (regression check).
func TestAgent_DeepSeek_NonStreaming_HopByHop(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"message": map[string]any{"role": "assistant", "content": "Hello!"},
			}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
		})
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"deepseek-chat","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-deepseek-test")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Trailer", "X-Checksum")
	req.Header.Set("Keep-Alive", "timeout=5")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if receivedHeaders.Get("Connection") != "" {
		t.Error("Connection leaked in non-streaming")
	}
	if receivedHeaders.Get("Trailer") != "" {
		t.Error("Trailer leaked in non-streaming")
	}
	if receivedHeaders.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive leaked in non-streaming")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestAgent_Anthropic_StreamingContent_EscapeJSON verifies that streaming
// responses with special characters in content produce valid telemetry JSON.
func TestAgent_Anthropic_StreamingContent_EscapeJSON(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Content with quotes, backslashes, newlines — exercises escapeJSON
		events := []string{
			`event: message_start` + "\n" + `data: {"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":10,"output_tokens":1}}}` + "\n\n",
			`event: content_block_start` + "\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n",
			`event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Here's a path: \"C:\\Users\\test\"\nLine 2"}}` + "\n\n",
			`event: content_block_stop` + "\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n",
			`event: message_delta` + "\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":15}}` + "\n\n",
			`event: message_stop` + "\n" + `data: {"type":"message_stop"}` + "\n\n",
		}
		for _, e := range events {
			w.Write([]byte(e))
		}
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"claude-sonnet-4-5-20250929","max_tokens":1024,"stream":true,"messages":[{"role":"user","content":"show path"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "sk-ant-test")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Verify the SSE stream was relayed (contains event data)
	respBody := rr.Body.String()
	if !strings.Contains(respBody, "message_start") {
		t.Error("streaming response should contain message_start event")
	}
}

// TestAgent_OpenAIResponses_Streaming simulates the OpenAI Responses API format
// used by newer agents, verifying header handling and response relay.
func TestAgent_OpenAIResponses_Streaming(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "text/event-stream")
		events := []string{
			`event: response.created` + "\n" + `data: {"type":"response.created","response":{"id":"resp_01","status":"in_progress"}}` + "\n\n",
			`event: response.output_item.added` + "\n" + `data: {"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_01","name":"Bash","arguments":""}}` + "\n\n",
			`event: response.function_call_arguments.delta` + "\n" + `data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"command\":\"pwd\"}"}` + "\n\n",
			`event: response.function_call_arguments.done` + "\n" + `data: {"type":"response.function_call_arguments.done","output_index":0,"arguments":"{\"command\":\"pwd\"}"}` + "\n\n",
			`event: response.completed` + "\n" + `data: {"type":"response.completed","response":{"id":"resp_01","status":"completed","usage":{"input_tokens":20,"output_tokens":10}}}` + "\n\n",
		}
		for _, e := range events {
			w.Write([]byte(e))
		}
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := map[string]any{
		"model":  "gpt-4o",
		"stream": true,
		"input":  []map[string]any{{"type": "message", "role": "user", "content": "what directory am I in?"}},
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-openai-test")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Trailer", "X-Trace")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// Hop-by-hop stripped
	if receivedHeaders.Get("Connection") != "" {
		t.Error("Connection leaked in OpenAI Responses streaming")
	}
	if receivedHeaders.Get("Trailer") != "" {
		t.Error("Trailer leaked in OpenAI Responses streaming")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// ===========================================================================
// Bug verification tests
// Each test asserts the CORRECT behavior and will FAIL while the bug exists.
// Once fixed, these serve as regression tests.
// ===========================================================================

// Bug 1: handleBufferedStreamingRequest drops the SSE event that triggers
// buffer overflow. When BufferEvent returns an error (buffer full), the code:
//
//	FlushAll()                        // sends previously-buffered events
//	ctx.Writer.Write(data[idx+2:])    // writes data AFTER the separator
//
// The event that caused the overflow (data[:idx+2]) is never written.
func TestBug_BufferOverflowDropsEvent(t *testing.T) {
	// 3-event stream; buffer holds only 2 events → 3rd triggers overflow
	stream := "data: {\"seq\":1}\n\n" +
		"data: {\"seq\":2}\n\n" +
		"data: {\"seq\":3}\n\n"

	w := httptest.NewRecorder()
	buffer := NewBufferedSSEWriter(w, 2, 30*time.Second,
		"t", "s", "m", types.APITypeOpenAICompletion, nil)

	// Replicate the exact read-loop logic from handleBufferedStreamingRequest
	data := []byte(stream)
	var overflowRemainder []byte

	for {
		idx := bytes.Index(data, []byte("\n\n"))
		if idx == -1 {
			break
		}
		eventData := data[:idx]
		raw := data[:idx+2]
		eventType, jsonData := parseSSEEventData(eventData)

		if err := buffer.BufferEvent(eventType, jsonData, raw); err != nil {
			// Fixed pattern: flush buffered events, then write the overflow event + remainder
			_ = buffer.FlushAll()
			overflowRemainder = append(append([]byte{}, raw...), data[idx+2:]...)
			break
		}
		data = data[idx+2:]
	}

	// Combine flushed output + what the caller would write after overflow
	clientReceived := w.Body.String() + string(overflowRemainder)

	if !strings.Contains(clientReceived, `"seq":1`) ||
		!strings.Contains(clientReceived, `"seq":2`) {
		t.Fatal("events 1 and 2 should be in output")
	}

	if !strings.Contains(clientReceived, `"seq":3`) {
		t.Error("BUG: event 3 (the overflow trigger) was silently dropped.\n" +
			"handleBufferedStreamingRequest writes data[idx+2:] (after separator), " +
			"skipping the event itself.\n" +
			"Fix: write the raw event bytes before writing remaining data.")
	}
}

// Bug 2a: extractUsageAndBody leaves stale Content-Encoding: gzip in
// resp.Header when gzip.NewReader fails (invalid gzip data).
// The client then receives Content-Encoding: gzip with an empty body.
func TestBug_ExtractUsageAndBody_StaleContentEncoding_NewReaderError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{encodingGzip},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("not valid gzip data"))),
	}

	_, _, body := extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	// After fix: raw bytes are returned as fallback instead of nil
	if body == nil {
		t.Error("body should not be nil on gzip error; raw bytes should be returned as fallback")
	}

	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding %q should be deleted after gzip.NewReader failure", ce)
	}
}

// Bug 2b: Same stale header when gzip.NewReader succeeds but io.ReadAll
// fails (truncated/corrupted gzip body).
func TestBug_ExtractUsageAndBody_StaleContentEncoding_ReadAllError(t *testing.T) {
	// Build valid gzip then truncate to corrupt the data stream
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	gw.Close()

	full := buf.Bytes()
	if len(full) < 15 {
		t.Skip("gzip output too short for truncation test")
	}
	truncated := full[:15] // valid header, corrupted data

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{encodingGzip},
		},
		Body: io.NopCloser(bytes.NewReader(truncated)),
	}

	_, _, _ = extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("BUG: Content-Encoding %q left in resp.Header after gzip ReadAll failure.\n"+
			"Fix: delete Content-Encoding on all decompression error paths.", ce)
	}
}

// Bug 3a: parseSSEEventData only keeps the last data: line.
// Per SSE spec, multiple data: lines should be concatenated with newlines.
func TestBug_ParseSSEEventData_MultipleDataLines(t *testing.T) {
	event := []byte("event: update\ndata: line1\ndata: line2\ndata: line3")

	eventType, data := parseSSEEventData(event)

	if eventType != "update" {
		t.Errorf("eventType = %q, want %q", eventType, "update")
	}

	got := string(data)
	want := "line1\nline2\nline3"
	if got != want {
		t.Errorf("BUG: parseSSEEventData only keeps last data: line.\n"+
			"got  = %q\n"+
			"want = %q\n"+
			"Per SSE spec, multiple data: lines must be concatenated with newlines.",
			got, want)
	}
}

// Bug 3b: SSEReader.parseSSEEvent has the same multi-data-line bug.
// When an SSE event has multiple data: lines, only the last is parsed.
func TestBug_SSEReader_MultipleDataLines(t *testing.T) {
	// Construct an SSE stream where one event splits data across two lines.
	// The full JSON is: {"choices":[{"delta":{"content":"hello"}}]}
	// Split across two data: lines — per SSE spec these should be joined
	// with newline before parsing.
	sseStream := "" +
		"data: {\"choices\":[{\"delta\":\n" +
		"data: {\"content\":\"hello\"}}]}\n" +
		"\n" // blank line = event separator

	body := io.NopCloser(bytes.NewReader([]byte(sseStream)))

	var capturedContent string
	reader := NewSSEReaderWithSecurity(body, types.APITypeOpenAICompletion,
		"t", "s", "m",
		func(in, out int64, content string, toolCalls []telemetry.ToolCall) {
			capturedContent = content
		})

	readBuf := make([]byte, 4096)
	for {
		_, err := reader.Read(readBuf)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read error: %v", err)
		}
	}
	_ = reader.Close()

	// With correct multi-line concatenation, the parser would see the
	// joined JSON and extract content "hello". With the bug, only the
	// second data: line is parsed, which is not valid JSON on its own,
	// so no content is captured.
	if capturedContent != "hello" {
		t.Errorf("BUG: SSEReader.parseSSEEvent only keeps last data: line.\n"+
			"Expected content %q, got %q.\n"+
			"Multi-line data: fields are not concatenated per SSE spec.",
			"hello", capturedContent)
	}
}

// Bug 4: handleBufferedStreamingRequest doesn't call WriteHeader for 2xx
// responses. If upstream returns a non-200 2xx (e.g. 201 Created), the
// proxy silently changes it to 200 because Go's ResponseWriter sends 200
// implicitly on the first Write call.
func TestBug_BufferedStreamingLosesNon200StatusCode(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusCreated) // 201
		_, _ = w.Write([]byte("data: {\"done\":true}\n\n"))
	}))
	defer upstream.Close()

	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	clientReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	targetURL, _ := url.Parse(upstream.URL + "/v1/chat/completions")
	upstreamReq, err := http.NewRequest(http.MethodPost, targetURL.String(),
		bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatal(err)
	}

	rctx := &RequestContext{
		Writer:      w,
		Request:     clientReq,
		UpstreamReq: upstreamReq,
		BodyBytes:   []byte(`{}`),
		RequestBody: []byte(`{}`),
		StartTime:   time.Now(),
		Model:       "gpt-4",
		TargetURL:   targetURL.String(),
		APIType:     types.APITypeOpenAICompletion,
		Tools:       []ToolDefinition{{Name: "Bash"}},
	}

	secCfg := security.InterceptionConfig{
		BufferStreaming: true,
		MaxBufferEvents: 100,
		BufferTimeout:   30,
		BlockMode:       types.BlockModeRemove,
	}

	p.handleBufferedStreamingRequest(rctx, secCfg)

	if w.Code != http.StatusCreated {
		t.Errorf("BUG: Buffered streaming changed upstream status from 201 to %d.\n"+
			"handleBufferedStreamingRequest doesn't call WriteHeader(resp.StatusCode) for 2xx.\n"+
			"Go's ResponseWriter implicitly sends 200 on first Write.",
			w.Code)
	}
}

// Bug 5a: copyHeaders doesn't parse Connection header values for additional
// hop-by-hop headers. Per RFC 7230 §6.1, "Connection: keep-alive, X-Custom"
// means X-Custom is also hop-by-hop and must not be forwarded.
func TestBug_CopyHeaders_ConnectionValueNotParsed(t *testing.T) {
	src := http.Header{
		"Connection":    []string{"keep-alive, X-Custom-Hop"},
		"X-Custom-Hop":  []string{"should-be-stripped"},
		"Authorization": []string{"Bearer token"},
		"Content-Type":  []string{"application/json"},
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	if dst.Get("Connection") != "" {
		t.Error("Connection header should be stripped")
	}
	if dst.Get("Authorization") != "Bearer token" {
		t.Error("Authorization should be preserved")
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be preserved")
	}

	if dst.Get("X-Custom-Hop") != "" {
		t.Error("BUG: X-Custom-Hop is listed in Connection header value, " +
			"making it hop-by-hop per RFC 7230 §6.1, but it was forwarded.\n" +
			"copyHeaders should parse Connection values and strip listed headers.")
	}
}

// Bug 5b: Full proxy integration — Connection-listed headers leak to upstream.
func TestBug_ProxyForwardsConnectionListedHeaders(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("Connection", "keep-alive, X-Request-Trace")
	req.Header.Set("X-Request-Trace", "trace-value-should-not-leak")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if receivedHeaders.Get("X-Request-Trace") != "" {
		t.Error("BUG: X-Request-Trace was listed in Connection header value " +
			"(hop-by-hop per RFC 7230) but was forwarded to upstream.\n" +
			"The proxy should parse Connection values to find additional " +
			"hop-by-hop headers and strip them.")
	}
}

// ===========================================================================
// Integration tests — real AI agent simulation for bug fix verification
// ===========================================================================

// TestAgent_ClaudeCode_BufferedStreaming_MultiDataLine exercises Bug 3 (multi-data-line)
// and Bug 4 (missing WriteHeader) through the full buffered streaming proxy pipeline.
// Upstream returns Anthropic SSE events where one event splits data across two lines.
func TestAgent_ClaudeCode_BufferedStreaming_MultiDataLine(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusCreated) // 201 to verify status code preservation
		// Event with multiple data: lines (must be concatenated with \n per SSE spec)
		events := []string{
			"event: message_start\n" +
				"data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-4-5-20250929\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
			"event: content_block_start\n" +
				"data: {\"type\":\"content_block_start\",\"index\":0,\n" +
				"data: \"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"Bash\",\"input\":{}}}\n\n",
			"event: content_block_delta\n" +
				"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"ls /tmp\\\"}\"}}\n\n",
			"event: content_block_stop\n" +
				"data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: message_delta\n" +
				"data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":42}}\n\n",
			"event: message_stop\n" +
				"data: {\"type\":\"message_stop\"}\n\n",
		}
		for _, e := range events {
			_, _ = w.Write([]byte(e))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()

	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"model":      "claude-sonnet-4-5-20250929",
		"max_tokens": 4096,
		"stream":     true,
		"messages":   []map[string]any{{"role": "user", "content": "list files"}},
		"tools": []map[string]any{{
			"name":        "Bash",
			"description": "Run a bash command",
			"input_schema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"command": map[string]string{"type": "string"}},
				"required":   []string{"command"},
			},
		}},
	}
	bodyBytes, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	clientReq := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(bodyBytes))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("X-Api-Key", "sk-ant-test")

	targetURL, _ := url.Parse(upstream.URL + "/v1/messages")
	upstreamReq, err := http.NewRequest(http.MethodPost, targetURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatal(err)
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("X-Api-Key", "sk-ant-test")

	rctx := &RequestContext{
		Writer:      w,
		Request:     clientReq,
		UpstreamReq: upstreamReq,
		BodyBytes:   bodyBytes,
		RequestBody: bodyBytes,
		StartTime:   time.Now(),
		Model:       "claude-sonnet-4-5-20250929",
		TargetURL:   targetURL.String(),
		APIType:     types.APITypeAnthropic,
		Tools:       []ToolDefinition{{Name: "Bash"}},
	}

	secCfg := security.InterceptionConfig{
		BufferStreaming: true,
		MaxBufferEvents: 100,
		BufferTimeout:   30,
		BlockMode:       types.BlockModeRemove,
	}

	p.handleBufferedStreamingRequest(rctx, secCfg)

	// Bug 4: status code must be preserved
	if w.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d — WriteHeader not called for buffered 2xx", w.Code)
	}

	// Bug 3: multi-data-line event must be fully relayed
	respBody := w.Body.String()
	if !strings.Contains(respBody, "content_block_start") {
		t.Error("content_block_start event missing — multi-data-line SSE not relayed")
	}
	if !strings.Contains(respBody, "message_stop") {
		t.Error("message_stop event missing from buffered stream")
	}
}

// TestAgent_OpenAI_BufferOverflowRecovery exercises Bug 1 through the full
// buffered streaming pipeline. Configures a small buffer (2 events) and sends
// 5 OpenAI SSE chunks — verifies none are silently dropped during overflow recovery.
func TestAgent_OpenAI_BufferOverflowRecovery(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 1; i <= 5; i++ {
			fmt.Fprintf(w, "data: {\"id\":\"chunk-%d\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"word%d \"},\"finish_reason\":null}]}\n\n", i, i)
		}
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer upstream.Close()

	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	body := map[string]any{
		"model":    "gpt-4o",
		"stream":   true,
		"messages": []map[string]any{{"role": "user", "content": "count"}},
		"tools": []map[string]any{{
			"name":        "Bash",
			"description": "Run a command",
			"parameters":  map[string]any{"type": "object", "properties": map[string]any{"cmd": map[string]string{"type": "string"}}},
		}},
	}
	bodyBytes, _ := json.Marshal(body)

	w := httptest.NewRecorder()
	clientReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(bodyBytes))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("Authorization", "Bearer sk-test")

	targetURL, _ := url.Parse(upstream.URL + "/v1/chat/completions")
	upstreamReq, err := http.NewRequest(http.MethodPost, targetURL.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatal(err)
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Authorization", "Bearer sk-test")

	rctx := &RequestContext{
		Writer:      w,
		Request:     clientReq,
		UpstreamReq: upstreamReq,
		BodyBytes:   bodyBytes,
		RequestBody: bodyBytes,
		StartTime:   time.Now(),
		Model:       "gpt-4o",
		TargetURL:   targetURL.String(),
		APIType:     types.APITypeOpenAICompletion,
		Tools:       []ToolDefinition{{Name: "Bash"}},
	}

	secCfg := security.InterceptionConfig{
		BufferStreaming: true,
		MaxBufferEvents: 2, // Only 2 events fit — overflow on event 3
		BufferTimeout:   30,
		BlockMode:       types.BlockModeRemove,
	}

	p.handleBufferedStreamingRequest(rctx, secCfg)

	respBody := w.Body.String()

	// All 5 events must appear — none silently dropped during overflow recovery
	for i := 1; i <= 5; i++ {
		chunk := fmt.Sprintf("chunk-%d", i)
		if !strings.Contains(respBody, chunk) {
			t.Errorf("event %s missing from response — buffer overflow recovery dropped it", chunk)
		}
	}
}

// TestAgent_GzipResponse_DecompressionError exercises Bug 2 through the full
// non-streaming proxy. Upstream returns Content-Encoding: gzip with invalid
// body — verifies the stale header doesn't leak to the client.
func TestAgent_GzipResponse_DecompressionError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		// Write invalid gzip data
		_, _ = w.Write([]byte("this is not gzip data at all"))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	// The proxy should NOT forward Content-Encoding: gzip when decompression failed
	if ce := rr.Header().Get("Content-Encoding"); ce == "gzip" {
		t.Error("stale Content-Encoding: gzip forwarded to client after decompression failure")
	}
}

// TestAgent_Cursor_ConnectionHopByHop exercises Bug 5 with both request and
// response Connection-listed headers through the full proxy pipeline.
func TestAgent_Cursor_ConnectionHopByHop(t *testing.T) {
	var receivedHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		// Upstream response also has Connection-listed headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "keep-alive, X-Internal-Debug")
		w.Header().Set("X-Internal-Debug", "debug-info-should-not-leak")
		w.Header().Set("X-Request-Id", "req-123") // regular header, should pass through
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer upstream.Close()

	proxy := setupTestProxy(t, upstream)

	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-cursor-test")
	// Client sends Connection-listed custom header
	req.Header.Set("Connection", "keep-alive, X-Client-Trace")
	req.Header.Set("X-Client-Trace", "trace-should-not-leak-to-upstream")
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Bug 5: Request Connection-listed headers must be stripped before upstream
	if receivedHeaders.Get("X-Client-Trace") != "" {
		t.Error("X-Client-Trace (listed in request Connection header) leaked to upstream")
	}
	if receivedHeaders.Get("Connection") != "" {
		t.Error("Connection header leaked to upstream")
	}

	// Bug 5: Response Connection-listed headers must be stripped before client
	if rr.Header().Get("X-Internal-Debug") != "" {
		t.Error("X-Internal-Debug (listed in response Connection header) leaked to client")
	}
	if rr.Header().Get("Connection") != "" {
		t.Error("Connection header from upstream leaked to client response")
	}

	// Regular headers should pass through
	if rr.Header().Get("X-Request-Id") != "req-123" {
		t.Error("X-Request-Id should be forwarded (not Connection-listed)")
	}
}

// ===========================================================================
// Coverage tests — untested code paths
// ===========================================================================

// TestBufferedStreaming_CRLFSeparators verifies the \r\n\r\n separator path
// in handleBufferedStreamingRequest (which has separate code from \n\n).
func TestBufferedStreaming_CRLFSeparators(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Use \r\n\r\n separators
		events := []string{
			"data: {\"seq\":1}\r\n\r\n",
			"data: {\"seq\":2}\r\n\r\n",
			"data: {\"seq\":3}\r\n\r\n",
		}
		for _, e := range events {
			_, _ = w.Write([]byte(e))
		}
	}))
	defer upstream.Close()

	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"Bash"}]}`)

	w := httptest.NewRecorder()
	clientReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("Authorization", "Bearer sk-test")

	targetURL, _ := url.Parse(upstream.URL + "/v1/chat/completions")
	upstreamReq, err2 := http.NewRequest(http.MethodPost, targetURL.String(), bytes.NewReader(body))
	if err2 != nil {
		t.Fatal(err2)
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Authorization", "Bearer sk-test")

	rctx := &RequestContext{
		Writer:      w,
		Request:     clientReq,
		UpstreamReq: upstreamReq,
		BodyBytes:   body,
		RequestBody: body,
		StartTime:   time.Now(),
		Model:       "gpt-4",
		TargetURL:   targetURL.String(),
		APIType:     types.APITypeOpenAICompletion,
		Tools:       []ToolDefinition{{Name: "Bash"}},
	}

	secCfg := security.InterceptionConfig{
		BufferStreaming: true,
		MaxBufferEvents: 100,
		BufferTimeout:   30,
		BlockMode:       types.BlockModeRemove,
	}

	p.handleBufferedStreamingRequest(rctx, secCfg)

	respBody := w.Body.String()
	for i := 1; i <= 3; i++ {
		if !strings.Contains(respBody, fmt.Sprintf(`"seq":%d`, i)) {
			t.Errorf("event seq:%d missing from response with \\r\\n\\r\\n separators", i)
		}
	}
}

// TestBufferedStreaming_TrailingEvent verifies that when the server closes
// the connection right after the last event (no trailing \n\n), the
// trailing event is still flushed to the client.
func TestBufferedStreaming_TrailingEvent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// First event with proper separator, second event WITHOUT trailing \n\n
		_, _ = w.Write([]byte("data: {\"seq\":1}\n\n"))
		_, _ = w.Write([]byte("data: {\"seq\":2}")) // no trailing \n\n
	}))
	defer upstream.Close()

	p, err := NewProxy(upstream.URL, "test-key", 30*time.Second, nil, false)
	if err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"model":"gpt-4","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"Bash"}]}`)

	w := httptest.NewRecorder()
	clientReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	clientReq.Header.Set("Content-Type", "application/json")
	clientReq.Header.Set("Authorization", "Bearer sk-test")

	targetURL, _ := url.Parse(upstream.URL + "/v1/chat/completions")
	upstreamReq, err2 := http.NewRequest(http.MethodPost, targetURL.String(), bytes.NewReader(body))
	if err2 != nil {
		t.Fatal(err2)
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Authorization", "Bearer sk-test")

	rctx := &RequestContext{
		Writer:      w,
		Request:     clientReq,
		UpstreamReq: upstreamReq,
		BodyBytes:   body,
		RequestBody: body,
		StartTime:   time.Now(),
		Model:       "gpt-4",
		TargetURL:   targetURL.String(),
		APIType:     types.APITypeOpenAICompletion,
		Tools:       []ToolDefinition{{Name: "Bash"}},
	}

	secCfg := security.InterceptionConfig{
		BufferStreaming: true,
		MaxBufferEvents: 100,
		BufferTimeout:   30,
		BlockMode:       types.BlockModeRemove,
	}

	p.handleBufferedStreamingRequest(rctx, secCfg)

	respBody := w.Body.String()
	if !strings.Contains(respBody, `"seq":1`) {
		t.Error("event 1 missing")
	}
	if !strings.Contains(respBody, `"seq":2`) {
		t.Error("trailing event (no \\n\\n terminator) was dropped")
	}
}

// TestExtractUsageAndBody_NonJsonContentType verifies that non-JSON responses
// are returned as-is without usage parsing.
func TestExtractUsageAndBody_NonJsonContentType(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("plain text body"))),
	}

	in, out, body := extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	if in != 0 || out != 0 {
		t.Errorf("expected zero tokens for non-JSON, got in=%d out=%d", in, out)
	}
	if string(body) != "plain text body" {
		t.Errorf("body = %q, want %q", body, "plain text body")
	}
}

// TestWalkJSONForToolCalls_MaxDepth verifies the depth limit prevents
// stack overflow on deeply nested JSON.
func TestWalkJSONForToolCalls_MaxDepth(t *testing.T) {
	// Build nested JSON: {"a":{"a":{..."type":"tool_use","name":"Bash","input":{}}...}}
	buildNested := func(depth int) []byte {
		var b bytes.Buffer
		for range depth {
			b.WriteString(`{"a":`)
		}
		b.WriteString(`{"type":"tool_use","name":"Bash","input":{}}`)
		for range depth {
			b.WriteString(`}`)
		}
		return b.Bytes()
	}

	// At depth 63 (within limit), tool call should be found
	results63 := extractToolCallsFromJSON(buildNested(63))
	if len(results63) == 0 {
		t.Error("tool call at depth 63 should be found (within maxJSONWalkDepth=64)")
	}

	// At depth 65 (beyond limit), tool call should NOT be found
	results65 := extractToolCallsFromJSON(buildNested(65))
	if len(results65) != 0 {
		t.Errorf("tool call at depth 65 should NOT be found, but got %d results", len(results65))
	}
}

func TestExtractUsageAndBody_InvalidGzip_ReturnsRawBody(t *testing.T) {
	rawData := []byte("not valid gzip data but still useful")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{encodingGzip},
		},
		Body: io.NopCloser(bytes.NewReader(rawData)),
	}

	_, _, body := extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	if body == nil {
		t.Fatal("body should not be nil on gzip error; should fall back to raw bytes")
	}
	if !bytes.Equal(body, rawData) {
		t.Errorf("body = %q, want raw bytes %q", body, rawData)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be deleted after gzip failure, got %q", ce)
	}
}

func TestExtractUsageAndBody_TruncatedGzip_ReturnsRawBody(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, _ = gw.Write([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5}}`))
	gw.Close()

	full := buf.Bytes()
	if len(full) < 15 {
		t.Skip("gzip output too short for truncation test")
	}
	truncated := full[:15]

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":     []string{"application/json"},
			"Content-Encoding": []string{encodingGzip},
		},
		Body: io.NopCloser(bytes.NewReader(truncated)),
	}

	_, _, body := extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	if body == nil {
		t.Fatal("body should not be nil on truncated gzip; should fall back to raw bytes")
	}
	if !bytes.Equal(body, truncated) {
		t.Errorf("body should be the raw truncated bytes")
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding should be deleted, got %q", ce)
	}
}

func TestExtractUsageAndBody_LargeNonJsonBody(t *testing.T) {
	bigBody := bytes.Repeat([]byte("x"), 1024*1024) // 1MB
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		Body: io.NopCloser(bytes.NewReader(bigBody)),
	}

	_, _, body := extractUsageAndBody(resp, types.APITypeOpenAICompletion)

	if body == nil {
		t.Error("non-JSON body should be returned")
	}
	if len(body) != len(bigBody) {
		t.Errorf("body length = %d, want %d", len(body), len(bigBody))
	}
}
