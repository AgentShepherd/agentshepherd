// Package types defines common type-safe enums used across the codebase.
package types

// APIType represents the LLM API format being proxied.
type APIType string

const (
	// APITypeOpenAICompletion is the OpenAI-compatible API format (Chat Completions).
	APITypeOpenAICompletion APIType = "openai"
	// APITypeAnthropic is the Anthropic API format.
	APITypeAnthropic APIType = "anthropic"
	// APITypeOpenAIResponses is the OpenAI Responses API format (/v1/responses).
	APITypeOpenAIResponses APIType = "openai_responses"
)

// Valid returns true if the APIType is a known valid value.
func (t APIType) Valid() bool {
	return t == APITypeOpenAICompletion || t == APITypeAnthropic || t == APITypeOpenAIResponses
}

// IsAnthropic returns true if this is the Anthropic API format.
func (t APIType) IsAnthropic() bool {
	return t == APITypeAnthropic
}

// IsOpenAICompletion returns true if this is the OpenAI Chat Completions API format.
func (t APIType) IsOpenAICompletion() bool {
	return t == APITypeOpenAICompletion
}

// IsOpenAIResponses returns true if this is the OpenAI Responses API format.
func (t APIType) IsOpenAIResponses() bool {
	return t == APITypeOpenAIResponses
}

// BlockMode represents how blocked tool calls are handled in responses.
type BlockMode string

const (
	// BlockModeRemove removes blocked tool calls from the response.
	BlockModeRemove BlockMode = "remove"
	// BlockModeReplace substitutes blocked tool calls with an error message.
	BlockModeReplace BlockMode = "replace"
)

// Valid returns true if the BlockMode is a known valid value.
func (m BlockMode) Valid() bool {
	return m == BlockModeRemove || m == BlockModeReplace
}

// IsReplace returns true if blocked calls should be replaced with error messages.
func (m BlockMode) IsReplace() bool {
	return m == BlockModeReplace
}

// IsRemove returns true if blocked calls should be removed from the response.
func (m BlockMode) IsRemove() bool {
	return m == BlockModeRemove
}
