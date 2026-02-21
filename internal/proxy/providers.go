package proxy

import (
	"slices"
	"strings"

	"github.com/BakeLens/crust/internal/config"
)

// builtinProviders maps model keyword to provider config.
// Matching logic: slash-split first (e.g. "openai/gpt-4o" → "openai"),
// then combined prefix + hyphen-segment matching (longest wins).
var builtinProviders = map[string]config.ProviderConfig{
	"claude":       {URL: "https://api.anthropic.com"},
	"gpt":          {URL: "https://api.openai.com"},
	"o1":           {URL: "https://api.openai.com"},
	"o3":           {URL: "https://api.openai.com"},
	"o4":           {URL: "https://api.openai.com"},
	"openai":       {URL: "https://api.openai.com"},
	"codex":        {URL: "https://chatgpt.com/backend-api/codex"},
	"openai-codex": {URL: "https://chatgpt.com/backend-api/codex"},
	"deepseek":     {URL: "https://api.deepseek.com"},
	"qwen":         {URL: "https://dashscope.aliyuncs.com/compatible-mode"},
	"moonshot":     {URL: "https://api.moonshot.ai"},
	"kimi":         {URL: "https://api.moonshot.ai"},
	"gemini":       {URL: "https://generativelanguage.googleapis.com"},
	"mistral":      {URL: "https://api.mistral.ai"},
	"groq":         {URL: "https://api.groq.com/openai"},
	"llama":        {URL: "https://api.groq.com/openai"},
	"minimax":      {URL: "https://api.minimax.io/anthropic"},
	"hf:":          {URL: "https://api.synthetic.new/anthropic"}, // HuggingFace
}

// ResolveProvider resolves a model name to a provider config (URL + optional API key).
//
// Matching order:
//  1. If model starts with "hf:", route to HuggingFace provider
//  2. If model contains "/", take the part before "/" and do exact match
//  3. Otherwise, combined prefix + hyphen-segment matching, longest wins
//
// User-defined providers are checked first (higher priority), then builtins.
func ResolveProvider(model string, userProviders map[string]config.ProviderConfig) (config.ProviderConfig, bool) {
	if model == "" {
		return config.ProviderConfig{}, false
	}

	if strings.HasPrefix(model, "hf:") {
		return lookupExact("hf:", userProviders)
	}

	if vendor, _, ok := strings.Cut(model, "/"); ok && vendor != "" {
		return lookupExact(vendor, userProviders)
	}

	return lookupBestMatch(model, userProviders)
}

// lookupExact checks user providers then builtins for an exact key match.
func lookupExact(key string, userProviders map[string]config.ProviderConfig) (config.ProviderConfig, bool) {
	key = strings.ToLower(key)
	if prov, ok := userProviders[key]; ok {
		return prov, true
	}
	if prov, ok := builtinProviders[key]; ok {
		return prov, true
	}
	return config.ProviderConfig{}, false
}

// lookupBestMatch finds the best matching provider using both prefix and
// hyphen-delimited segment matching. The longest match wins.
// User-defined providers are checked first; any user match wins over builtins.
func lookupBestMatch(model string, userProviders map[string]config.ProviderConfig) (config.ProviderConfig, bool) {
	lower := strings.ToLower(model)
	segments := strings.Split(lower, "-")

	bestIn := func(m map[string]config.ProviderConfig) (config.ProviderConfig, int) {
		best := config.ProviderConfig{}
		bestLen := 0
		for key, prov := range m {
			if (strings.HasPrefix(lower, key) || slices.Contains(segments, key)) && len(key) > bestLen {
				best = prov
				bestLen = len(key)
			}
		}
		return best, bestLen
	}

	if result, n := bestIn(userProviders); n > 0 {
		return result, true
	}
	if result, n := bestIn(builtinProviders); n > 0 {
		return result, true
	}
	return config.ProviderConfig{}, false
}
