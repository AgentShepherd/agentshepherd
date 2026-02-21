package proxy

import (
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/config"
)

func TestResolveProvider_SlashSplit(t *testing.T) {
	tests := []struct {
		model   string
		wantURL string
		wantOK  bool
	}{
		{"openai/gpt-4o", "https://api.openai.com", true},
		{"claude/claude-sonnet-4-5-20250929", "https://api.anthropic.com", true},
		{"gpt/gpt-4o", "https://api.openai.com", true},
		{"unknown/model", "", false},
	}
	for _, tt := range tests {
		result, ok := ResolveProvider(tt.model, nil)
		if ok != tt.wantOK {
			t.Errorf("ResolveProvider(%q) ok=%v, want %v", tt.model, ok, tt.wantOK)
			continue
		}
		if ok && result.URL != tt.wantURL {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tt.model, result.URL, tt.wantURL)
		}
	}
}

func TestResolveProvider_BuiltinMatch(t *testing.T) {
	tests := []struct {
		model   string
		wantURL string
	}{
		// Prefix matches
		{"deepseek-chat", "https://api.deepseek.com"},
		{"deepseek-coder-v2", "https://api.deepseek.com"},
		{"claude-sonnet-4-5-20250929", "https://api.anthropic.com"},
		{"claude-3-opus-20240229", "https://api.anthropic.com"},
		{"gpt-4o", "https://api.openai.com"},
		{"gpt-4-turbo", "https://api.openai.com"},
		{"o1-preview", "https://api.openai.com"},
		{"o3-mini", "https://api.openai.com"},
		{"o4-mini", "https://api.openai.com"},
		{"gemini-pro", "https://generativelanguage.googleapis.com"},
		{"llama-3.3-70b-versatile", "https://api.groq.com/openai"},
		{"mistral-large", "https://api.mistral.ai"},
		{"moonshot-v1-8k", "https://api.moonshot.ai"},
		{"kimi-latest", "https://api.moonshot.ai"},
		{"qwen-turbo", "https://dashscope.aliyuncs.com/compatible-mode"},
		{"minimax-abab5.5", "https://api.minimax.io/anthropic"},
		{"groq-llama-3", "https://api.groq.com/openai"},
		// Codex segment matches (segment "codex" len 5 beats prefix "gpt" len 3)
		{"gpt-5.3-codex", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.2-codex", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.1-codex-mini", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.1-codex-max", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5-codex", "https://chatgpt.com/backend-api/codex"},
		{"codex-mini-latest", "https://chatgpt.com/backend-api/codex"},
		// HuggingFace
		{"hf:Meta-Llama-3.1-8B-Instruct", "https://api.synthetic.new/anthropic"},
		{"hf:Qwen2.5-Coder-32B", "https://api.synthetic.new/anthropic"},
		{"hf:moonshotai/Kimi-K2-Thinking", "https://api.synthetic.new/anthropic"},
		{"hf:deepseek-ai/DeepSeek-R1-0528", "https://api.synthetic.new/anthropic"},
	}
	for _, tt := range tests {
		result, ok := ResolveProvider(tt.model, nil)
		if !ok {
			t.Errorf("expected match for %q", tt.model)
			continue
		}
		if result.URL != tt.wantURL {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tt.model, result.URL, tt.wantURL)
		}
	}
}

func TestResolveProvider_NoMatch(t *testing.T) {
	for _, model := range []string{"", "unknown-model"} {
		if _, ok := ResolveProvider(model, nil); ok {
			t.Errorf("expected no match for %q", model)
		}
	}
}

func TestResolveProvider_UserProviders(t *testing.T) {
	tests := []struct {
		name      string
		model     string
		providers map[string]config.ProviderConfig
		wantURL   string
		wantKey   string
	}{
		{
			name:      "user priority over builtin",
			model:     "deepseek-chat",
			providers: map[string]config.ProviderConfig{"deepseek": {URL: "http://localhost:8000"}},
			wantURL:   "http://localhost:8000",
		},
		{
			name:      "custom model prefix",
			model:     "my-llama-70b",
			providers: map[string]config.ProviderConfig{"my-llama": {URL: "http://localhost:11434/v1"}},
			wantURL:   "http://localhost:11434/v1",
		},
		{
			name:      "slash split with user provider",
			model:     "local/llama-70b",
			providers: map[string]config.ProviderConfig{"local": {URL: "http://localhost:11434/v1"}},
			wantURL:   "http://localhost:11434/v1",
		},
		{
			name:  "longest prefix wins",
			model: "o3-mini",
			providers: map[string]config.ProviderConfig{
				"o":  {URL: "http://short.example.com"},
				"o3": {URL: "http://o3.example.com"},
			},
			wantURL: "http://o3.example.com",
		},
		{
			name:      "per-provider API key",
			model:     "deepseek-chat",
			providers: map[string]config.ProviderConfig{"deepseek": {URL: "https://api.deepseek.com", APIKey: "sk-deepseek-test"}},
			wantURL:   "https://api.deepseek.com",
			wantKey:   "sk-deepseek-test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ResolveProvider(tt.model, tt.providers)
			if !ok {
				t.Fatalf("expected match for %q", tt.model)
			}
			if result.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", result.URL, tt.wantURL)
			}
			if result.APIKey != tt.wantKey {
				t.Errorf("APIKey = %q, want %q", result.APIKey, tt.wantKey)
			}
		})
	}
}

func TestResolveProvider_BuiltinHasNoAPIKey(t *testing.T) {
	result, ok := ResolveProvider("gpt-4o", nil)
	if !ok {
		t.Fatal("expected match for gpt-4o")
	}
	if result.APIKey != "" {
		t.Fatalf("expected empty api key for builtin provider, got %s", result.APIKey)
	}
}

func TestRequestContext_String(t *testing.T) {
	ctx := &RequestContext{
		Model:          "gpt-4o",
		TargetURL:      "https://api.openai.com/v1/chat/completions",
		APIType:        "openai",
		ProviderAPIKey: "sk-secret-key-12345",
	}
	s := ctx.String()
	if strings.Contains(s, "sk-secret-key-12345") {
		t.Error("ProviderAPIKey should not appear in String()")
	}
	if !strings.Contains(s, "gpt-4o") {
		t.Error("expected Model in String()")
	}
	if !strings.Contains(s, "https://api.openai.com") {
		t.Error("expected TargetURL in String()")
	}
}
