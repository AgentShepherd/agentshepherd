package proxy

import (
	"slices"
	"strings"
)

// builtinProviders maps model keyword to provider base URL.
// Matching logic: slash-split first (e.g. "openai/gpt-4o" → "openai"),
// then combined prefix + hyphen-segment matching (longest wins).
var builtinProviders = map[string]string{
	"claude":       "https://api.anthropic.com",
	"gpt":          "https://api.openai.com",
	"o1":           "https://api.openai.com",
	"o3":           "https://api.openai.com",
	"o4":           "https://api.openai.com",
	"openai":       "https://api.openai.com",
	"codex":        "https://chatgpt.com/backend-api/codex",
	"openai-codex": "https://chatgpt.com/backend-api/codex",
	"deepseek":     "https://api.deepseek.com",
	"qwen":         "https://dashscope.aliyuncs.com/compatible-mode",
	"moonshot":     "https://api.moonshot.ai",
	"kimi":         "https://api.moonshot.ai",
	"gemini":       "https://generativelanguage.googleapis.com",
	"mistral":      "https://api.mistral.ai",
	"groq":         "https://api.groq.com/openai",
	"llama":        "https://api.groq.com/openai",
	"minimax":      "https://api.minimax.io/anthropic",
	"hf:":          "https://api.synthetic.new/anthropic", // HuggingFace
}

// ResolveProvider resolves a model name to a provider base URL.
//
// Matching order:
//  1. If model starts with "hf:", route to HuggingFace provider
//     (e.g. "hf:org/model" or "hf:model-name")
//  2. If model contains "/", take the part before "/" and do exact match
//     (e.g. "openai/gpt-4o" → key "openai")
//  3. Otherwise, combined prefix + hyphen-segment matching, longest wins
//     (e.g. "deepseek-chat" → prefix "deepseek";
//     "gpt-5.3-codex" → segment "codex" beats prefix "gpt")
//
// User-defined providers are checked first (higher priority), then builtins.
// Returns ("", false) if no match is found.
func ResolveProvider(model string, userProviders map[string]string) (baseURL string, ok bool) {
	if model == "" {
		return "", false
	}

	// Step 1: HuggingFace prefix check (handles "hf:org/model" and "hf:model")
	if strings.HasPrefix(model, "hf:") {
		// If model has hf: prefix, only check "hf:" mapping (don't fall through to slash-split)
		return lookupExact("hf:", userProviders)
	}

	// Step 2: slash-split (e.g. "openai/gpt-4o" → vendor "openai")
	if vendor, _, ok := strings.Cut(model, "/"); ok && vendor != "" {
		if url, found := lookupExact(vendor, userProviders); found {
			return url, true
		}
		return "", false
	}

	// Step 3: combined prefix + hyphen-segment matching
	return lookupBestMatch(model, userProviders)
}

// lookupExact checks user providers then builtins for an exact key match.
func lookupExact(key string, userProviders map[string]string) (string, bool) {
	key = strings.ToLower(key)
	if userProviders != nil {
		if url, ok := userProviders[key]; ok {
			return url, true
		}
	}
	if url, ok := builtinProviders[key]; ok {
		return url, true
	}
	return "", false
}

// lookupBestMatch finds the best matching provider using both prefix and
// hyphen-delimited segment matching. The longest match wins.
// User-defined providers are checked first; any user match wins over builtins.
func lookupBestMatch(model string, userProviders map[string]string) (string, bool) {
	lower := strings.ToLower(model)
	segments := strings.Split(lower, "-")

	// bestMatchIn finds the longest matching key in m via prefix or segment.
	bestMatchIn := func(m map[string]string) (string, int) {
		bestURL := ""
		bestLen := 0
		for key, url := range m {
			matched := false
			// Prefix match (e.g. "deepseek" is prefix of "deepseek-chat")
			if strings.HasPrefix(lower, key) {
				matched = true
			}
			// Segment match (e.g. "codex" is a segment of "gpt-5.3-codex")
			if !matched {
				if slices.Contains(segments, key) {
					matched = true
				}
			}
			if matched && len(key) > bestLen {
				bestURL = url
				bestLen = len(key)
			}
		}
		return bestURL, bestLen
	}

	// User providers first (higher priority)
	if userProviders != nil {
		if url, n := bestMatchIn(userProviders); n > 0 {
			return url, true
		}
	}

	// Then builtins
	if url, n := bestMatchIn(builtinProviders); n > 0 {
		return url, true
	}

	return "", false
}
