package security

import "strings"

// EscapeForShellEcho escapes a string for safe use in shell echo commands.
func EscapeForShellEcho(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `'`, `'\''`)
	return s
}
