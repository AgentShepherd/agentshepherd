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

// LogLevel represents a log verbosity level.
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Valid returns true if the LogLevel is a known valid value.
// Empty string is valid (defaults to info).
func (l LogLevel) Valid() bool {
	switch l {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, "":
		return true
	}
	return false
}

// MessageRole represents the role of a message in an LLM conversation.
type MessageRole string

const (
	RoleSystem    MessageRole = "system"
	RoleUser      MessageRole = "user"
	RoleAssistant MessageRole = "assistant"
)

// Agent represents a known AI coding agent brand.
type Agent string

const (
	AgentClaudeCode Agent = "claude-code"
	AgentCodex      Agent = "codex"
	AgentCline      Agent = "cline"
	AgentCursor     Agent = "cursor"
	AgentOpenClaw   Agent = "openclaw"
	AgentOpenCode   Agent = "opencode"
	AgentWindsurf   Agent = "windsurf"
	AgentUnknown    Agent = "unknown"
)

// Valid returns true if the Agent is a known value (not unknown).
func (a Agent) Valid() bool {
	switch a {
	case AgentClaudeCode, AgentCodex, AgentCline, AgentCursor,
		AgentOpenClaw, AgentOpenCode, AgentWindsurf:
		return true
	case AgentUnknown:
		return false
	}
	return false
}

// String returns the agent name.
func (a Agent) String() string {
	return string(a)
}

// AllAgents returns all known agent brands.
func AllAgents() []Agent {
	return []Agent{
		AgentClaudeCode,
		AgentCodex,
		AgentCline,
		AgentCursor,
		AgentOpenClaw,
		AgentOpenCode,
		AgentWindsurf,
	}
}

// ParseAgent converts a string to an Agent, returning AgentUnknown if not recognized.
func ParseAgent(s string) Agent {
	a := Agent(s)
	if a.Valid() {
		return a
	}
	return AgentUnknown
}
