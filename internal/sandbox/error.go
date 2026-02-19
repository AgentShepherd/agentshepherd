package sandbox

import (
	"encoding/json"
	"fmt"
)

// ExitSandboxError is the exit code used by bakelens-sandbox for setup failures.
// Distinct from target command exit codes (0-124) and signal deaths (128+N).
const ExitSandboxError = 125

// ErrorCode classifies sandbox setup failures.
type ErrorCode string

const (
	ErrParse                  ErrorCode = "parse_error"
	ErrEnforcementUnavailable ErrorCode = "enforcement_unavailable"
	ErrCommandNotFound        ErrorCode = "command_not_found"
	ErrExecFailed             ErrorCode = "exec_failed"
	ErrSandbox                ErrorCode = "sandbox_error"
)

// Error represents a structured error from bakelens-sandbox.
// Returned when the helper exits with code 125 and writes a JSON error to stderr.
type Error struct {
	Code    ErrorCode `json:"error"`
	Message string    `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// parseSandboxError extracts a structured error from the last line of stderr.
// Returns nil if the line is not valid JSON or doesn't match the error schema.
func parseSandboxError(lastLine []byte) *Error {
	lastLine = trimTrailingNewlines(lastLine)
	if len(lastLine) == 0 || lastLine[0] != '{' {
		return nil
	}
	var se Error
	if err := json.Unmarshal(lastLine, &se); err != nil {
		return nil //nolint:nilerr // not a valid error JSON, ignore
	}
	if se.Code == "" || se.Message == "" {
		return nil
	}
	return &se
}

func trimTrailingNewlines(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
