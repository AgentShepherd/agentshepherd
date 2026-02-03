// Package types defines common type-safe enums used across the codebase.
package types

// APIType represents the LLM API format being proxied.
type APIType string

const (
	// APITypeOpenAI is the OpenAI-compatible API format.
	APITypeOpenAI APIType = "openai"
	// APITypeAnthropic is the Anthropic API format.
	APITypeAnthropic APIType = "anthropic"
)

// Valid returns true if the APIType is a known valid value.
func (t APIType) Valid() bool {
	return t == APITypeOpenAI || t == APITypeAnthropic
}

// IsAnthropic returns true if this is the Anthropic API format.
func (t APIType) IsAnthropic() bool {
	return t == APITypeAnthropic
}

// IsOpenAI returns true if this is the OpenAI API format.
func (t APIType) IsOpenAI() bool {
	return t == APITypeOpenAI
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
