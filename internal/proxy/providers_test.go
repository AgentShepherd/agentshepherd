package proxy

import "testing"

func TestResolveProvider_SlashSplitOpenAIVendor(t *testing.T) {
	// "openai" is a builtin key, so "openai/gpt-4o" should match
	base, ok := ResolveProvider("openai/gpt-4o", nil)
	if !ok {
		t.Fatal("expected match for openai/gpt-4o")
	}
	if base != "https://api.openai.com" {
		t.Fatalf("expected https://api.openai.com, got %s", base)
	}
}

func TestResolveProvider_SlashSplitClaude(t *testing.T) {
	base, ok := ResolveProvider("claude/claude-sonnet-4-5-20250929", nil)
	if !ok {
		t.Fatal("expected match for claude/claude-sonnet-4-5-20250929")
	}
	if base != "https://api.anthropic.com" {
		t.Fatalf("expected https://api.anthropic.com, got %s", base)
	}
}

func TestResolveProvider_SlashSplitOpenAI(t *testing.T) {
	// "gpt" is a builtin key, so "gpt/gpt-4o" should match
	base, ok := ResolveProvider("gpt/gpt-4o", nil)
	if !ok {
		t.Fatal("expected match for gpt/gpt-4o")
	}
	if base != "https://api.openai.com" {
		t.Fatalf("expected https://api.openai.com, got %s", base)
	}
}

func TestResolveProvider_SlashSplitNoMatch(t *testing.T) {
	// "unknown/model" — "unknown" is not in registry
	_, ok := ResolveProvider("unknown/model", nil)
	if ok {
		t.Fatal("expected no match for unknown/model")
	}
}

func TestResolveProvider_PrefixMatch(t *testing.T) {
	tests := []struct {
		model   string
		wantURL string
	}{
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
	}
	for _, tt := range tests {
		base, ok := ResolveProvider(tt.model, nil)
		if !ok {
			t.Errorf("expected match for %q", tt.model)
			continue
		}
		if base != tt.wantURL {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tt.model, base, tt.wantURL)
		}
	}
}

func TestResolveProvider_UserPriority(t *testing.T) {
	userProviders := map[string]string{
		"deepseek": "http://localhost:8000",
	}
	base, ok := ResolveProvider("deepseek-chat", userProviders)
	if !ok {
		t.Fatal("expected match for deepseek-chat with user provider")
	}
	if base != "http://localhost:8000" {
		t.Fatalf("expected user provider URL, got %s", base)
	}
}

func TestResolveProvider_UserCustomModel(t *testing.T) {
	userProviders := map[string]string{
		"my-llama": "http://localhost:11434/v1",
	}
	base, ok := ResolveProvider("my-llama-70b", userProviders)
	if !ok {
		t.Fatal("expected match for my-llama-70b with user provider")
	}
	if base != "http://localhost:11434/v1" {
		t.Fatalf("expected http://localhost:11434/v1, got %s", base)
	}
}

func TestResolveProvider_UserSlashSplit(t *testing.T) {
	userProviders := map[string]string{
		"local": "http://localhost:11434/v1",
	}
	base, ok := ResolveProvider("local/llama-70b", userProviders)
	if !ok {
		t.Fatal("expected match for local/llama-70b")
	}
	if base != "http://localhost:11434/v1" {
		t.Fatalf("expected http://localhost:11434/v1, got %s", base)
	}
}

func TestResolveProvider_NoMatch(t *testing.T) {
	_, ok := ResolveProvider("unknown-model", nil)
	if ok {
		t.Fatal("expected no match for unknown-model")
	}
}

func TestResolveProvider_EmptyModel(t *testing.T) {
	_, ok := ResolveProvider("", nil)
	if ok {
		t.Fatal("expected no match for empty model")
	}
}

func TestResolveProvider_LongestPrefixWins(t *testing.T) {
	// If user has both "o" and "o3", "o3-mini" should match "o3"
	userProviders := map[string]string{
		"o":  "http://short.example.com",
		"o3": "http://o3.example.com",
	}
	base, ok := ResolveProvider("o3-mini", userProviders)
	if !ok {
		t.Fatal("expected match for o3-mini")
	}
	if base != "http://o3.example.com" {
		t.Fatalf("expected http://o3.example.com (longest prefix), got %s", base)
	}
}

func TestResolveProvider_GroqPrefix(t *testing.T) {
	base, ok := ResolveProvider("groq-llama-3", nil)
	if !ok {
		t.Fatal("expected match for groq-llama-3")
	}
	if base != "https://api.groq.com/openai" {
		t.Fatalf("expected https://api.groq.com/openai, got %s", base)
	}
}

func TestResolveProvider_CodexSegmentMatch(t *testing.T) {
	// Codex model names like "gpt-5.3-codex" start with "gpt" but should
	// match the "codex" segment (len 5) over the "gpt" prefix (len 3).
	tests := []struct {
		model   string
		wantURL string
	}{
		{"gpt-5.3-codex", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.2-codex", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.1-codex-mini", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5.1-codex-max", "https://chatgpt.com/backend-api/codex"},
		{"gpt-5-codex", "https://chatgpt.com/backend-api/codex"},
		{"codex-mini-latest", "https://chatgpt.com/backend-api/codex"},
		// Plain gpt models should still go to OpenAI
		{"gpt-4o", "https://api.openai.com"},
		{"gpt-4-turbo", "https://api.openai.com"},
	}
	for _, tt := range tests {
		base, ok := ResolveProvider(tt.model, nil)
		if !ok {
			t.Errorf("expected match for %q", tt.model)
			continue
		}
		if base != tt.wantURL {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tt.model, base, tt.wantURL)
		}
	}
}

func TestResolveProvider_HuggingFace(t *testing.T) {
	// HuggingFace models use "hf:" prefix format
	// Supports both "hf:model" and "hf:org/model" formats
	tests := []struct {
		model   string
		wantURL string
	}{
		// Simple format (no slashes)
		{"hf:Meta-Llama-3.1-8B-Instruct", "https://api.synthetic.new/anthropic"},
		{"hf:Qwen2.5-Coder-32B", "https://api.synthetic.new/anthropic"},
		// Org/model format (with slashes)
		{"hf:moonshotai/Kimi-K2-Thinking", "https://api.synthetic.new/anthropic"},
		{"hf:zai-org/GLM-4.7", "https://api.synthetic.new/anthropic"},
		{"hf:deepseek-ai/DeepSeek-R1-0528", "https://api.synthetic.new/anthropic"},
		{"hf:deepseek-ai/DeepSeek-V3-0324", "https://api.synthetic.new/anthropic"},
		{"hf:deepseek-ai/DeepSeek-V3.1", "https://api.synthetic.new/anthropic"},
	}
	for _, tt := range tests {
		base, ok := ResolveProvider(tt.model, nil)
		if !ok {
			t.Errorf("expected match for %q", tt.model)
			continue
		}
		if base != tt.wantURL {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tt.model, base, tt.wantURL)
		}
	}
}
