package security

import (
	"strings"
	"testing"
)

func TestEscapeForShellEcho_Backslashes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single backslash", `\`, `\\`},
		{"double backslash", `\\`, `\\\\`},
		{"backslash in middle", `a\b`, `a\\b`},
		{"multiple backslashes", `\\\`, `\\\\\\`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_Newlines(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single newline", "hello\nworld", "hello world"},
		{"multiple newlines", "a\nb\nc", "a b c"},
		{"leading newline", "\nhello", " hello"},
		{"trailing newline", "hello\n", "hello "},
		{"consecutive newlines", "hello\n\nworld", "hello  world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_CarriageReturns(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single CR", "hello\rworld", "helloworld"},
		{"CRLF", "hello\r\nworld", "hello world"},
		{"multiple CR", "a\r\rb", "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_DoubleQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single double quote", `"`, `\"`},
		{"quoted string", `"hello"`, `\"hello\"`},
		{"nested quotes", `say "hello"`, `say \"hello\"`},
		{"multiple quotes", `"""`, `\"\"\"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_SingleQuotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"single quote", `'`, `'\''`},
		{"quoted string", `'hello'`, `'\''hello'\''`},
		{"nested quotes", `it's`, `it'\''s`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_CombinedSpecialChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"backslash and quote",
			`\"`,
			`\\\"`,
		},
		{
			"newline and quote",
			"say\n\"hello\"",
			`say \"hello\"`,
		},
		{
			"all special chars",
			"hello\nworld\r\"test\"'it's'\\\n",
			`hello world\"test\"'\''it'\''s'\''\\ `,
		},
		{
			"shell injection attempt",
			`$(rm -rf /)`,
			`$(rm -rf /)`,
		},
		{
			"backtick injection",
			"`rm -rf /`",
			"`rm -rf /`",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_EmptyString(t *testing.T) {
	result := EscapeForShellEcho("")
	if result != "" {
		t.Errorf("EscapeForShellEcho(\"\") = %q, want \"\"", result)
	}
}

func TestEscapeForShellEcho_UnicodeChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"emoji", "hello 🚀 world", "hello 🚀 world"},
		{"chinese", "你好世界", "你好世界"},
		{"mixed unicode and special", "hello\n世界", "hello 世界"},
		{"unicode with quote", `"你好"`, `\"你好\"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EscapeForShellEcho(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeForShellEcho(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEscapeForShellEcho_LongString(t *testing.T) {
	// Test with a long string to ensure no buffer issues
	input := ""
	for i := 0; i < 10000; i++ {
		input += "a"
	}
	result := EscapeForShellEcho(input)
	if len(result) != 10000 {
		t.Errorf("EscapeForShellEcho(long string) returned length %d, want 10000", len(result))
	}
}

func FuzzEscapeForShellEcho(f *testing.F) {
	// Seed corpus with interesting inputs
	f.Add("")
	f.Add(`\`)
	f.Add(`"`)
	f.Add(`'`)
	f.Add("\n")
	f.Add("\r")
	f.Add(`\"'\\`)
	f.Add("hello\nworld")
	f.Add("$(rm -rf /)")
	f.Add("`cmd`")
	f.Add("\x00")
	f.Add("a\tb\nc")
	f.Add(`'; rm -rf / #`)
	f.Add(`" ; rm -rf / #`)

	f.Fuzz(func(t *testing.T, input string) {
		result := EscapeForShellEcho(input)

		// INVARIANT 1: Result must not contain raw newlines.
		if strings.ContainsRune(result, '\n') {
			t.Errorf("result contains newline: input=%q result=%q", input, result)
		}

		// INVARIANT 2: Result must not contain carriage returns.
		if strings.ContainsRune(result, '\r') {
			t.Errorf("result contains carriage return: input=%q result=%q", input, result)
		}

		// INVARIANT 3: All double quotes must be escaped (preceded by \).
		for i := 0; i < len(result); i++ {
			if result[i] == '"' {
				// Count preceding backslashes
				nBackslashes := 0
				for j := i - 1; j >= 0 && result[j] == '\\'; j-- {
					nBackslashes++
				}
				// Escaped if preceded by odd number of backslashes
				if nBackslashes%2 == 0 {
					t.Errorf("unescaped double quote at position %d: input=%q result=%q", i, input, result)
				}
			}
		}

		// INVARIANT 4: Idempotent for "safe" content.
		// If input has no special chars, output must equal input.
		hasSpecial := false
		for _, c := range input {
			if c == '\\' || c == '\n' || c == '\r' || c == '"' || c == '\'' {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial && result != input {
			t.Errorf("no special chars but result differs: input=%q result=%q", input, result)
		}

		// INVARIANT 5: Result length must be >= input length after \r removal.
		// Escaping only adds chars; only \r is removed entirely.
		minLen := len(strings.ReplaceAll(strings.ReplaceAll(input, "\r", ""), "\n", " "))
		if len(result) < minLen {
			t.Errorf("result too short: len(result)=%d < %d: input=%q result=%q", len(result), minLen, input, result)
		}
	})
}

// Benchmark for performance testing
func BenchmarkEscapeForShellEcho(b *testing.B) {
	b.ReportAllocs()
	testCases := []struct {
		name  string
		input string
	}{
		{"short_clean", "hello world"},
		{"short_special", `hello "world" it's\n`},
		{"long_clean", string(make([]byte, 1000))},
		{"long_special", "hello\nworld\r\"test\"'it's'\\\n" + string(make([]byte, 1000))},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				EscapeForShellEcho(tc.input)
			}
		})
	}
}
