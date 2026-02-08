package rules

import (
	"testing"
)

func TestNormalizer_Normalize(t *testing.T) {
	// Define test environment
	homeDir := "/home/testuser"
	workDir := "/home/testuser/project"
	env := map[string]string{
		"HOME":    "/home/testuser",
		"PROJECT": "/opt/myproject",
		"TMPDIR":  "/tmp",
		"USER":    "testuser",
	}

	n := NewNormalizerWithEnv(homeDir, workDir, env)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// 1. Tilde expansion
		{
			name:     "tilde alone expands to home dir",
			input:    "~",
			expected: "/home/testuser",
		},
		{
			name:     "tilde with subpath expands correctly",
			input:    "~/foo",
			expected: "/home/testuser/foo",
		},
		{
			name:     "tilde with nested subpath",
			input:    "~/foo/bar/baz",
			expected: "/home/testuser/foo/bar/baz",
		},
		{
			name:     "tilde with hidden file",
			input:    "~/.env",
			expected: "/home/testuser/.env",
		},
		{
			name:     "tilde in middle of path not expanded",
			input:    "/foo/~/bar",
			expected: "/foo/~/bar",
		},

		// 2. $HOME expansion
		{
			name:     "$HOME expands to home dir",
			input:    "$HOME",
			expected: "/home/testuser",
		},
		{
			name:     "$HOME with subpath",
			input:    "$HOME/.env",
			expected: "/home/testuser/.env",
		},
		{
			name:     "$HOME with nested subpath",
			input:    "$HOME/foo/bar",
			expected: "/home/testuser/foo/bar",
		},

		// 3. ${HOME} expansion (braced syntax)
		{
			name:     "${HOME} expands to home dir",
			input:    "${HOME}",
			expected: "/home/testuser",
		},
		{
			name:     "${HOME} with subpath",
			input:    "${HOME}/.env",
			expected: "/home/testuser/.env",
		},
		{
			name:     "${HOME} with nested subpath",
			input:    "${HOME}/foo/bar",
			expected: "/home/testuser/foo/bar",
		},
		{
			name:     "${HOME} followed by text without slash",
			input:    "${HOME}suffix",
			expected: "/home/testusersuffix",
		},

		// 4. Other environment variables
		{
			name:     "$PROJECT expands correctly",
			input:    "$PROJECT/file",
			expected: "/opt/myproject/file",
		},
		{
			name:     "${PROJECT} expands correctly",
			input:    "${PROJECT}/src/main.go",
			expected: "/opt/myproject/src/main.go",
		},
		{
			name:     "$TMPDIR expands correctly",
			input:    "$TMPDIR/cache",
			expected: "/tmp/cache",
		},
		{
			name:     "multiple env vars in path",
			input:    "$TMPDIR/$USER/cache",
			expected: "/tmp/testuser/cache",
		},
		{
			name:     "mixed braced and unbraced vars",
			input:    "${TMPDIR}/$USER/data",
			expected: "/tmp/testuser/data",
		},

		// 5. Relative paths
		{
			name:     "dot-slash relative path",
			input:    "./foo",
			expected: "/home/testuser/project/foo",
		},
		{
			name:     "plain relative path",
			input:    "foo",
			expected: "/home/testuser/project/foo",
		},
		{
			name:     "dot-dot relative path",
			input:    "../foo",
			expected: "/home/testuser/foo",
		},
		{
			name:     "nested relative path",
			input:    "foo/bar/baz",
			expected: "/home/testuser/project/foo/bar/baz",
		},
		{
			name:     "dot-slash with nested path",
			input:    "./foo/bar",
			expected: "/home/testuser/project/foo/bar",
		},
		{
			name:     "multiple parent refs",
			input:    "../../foo",
			expected: "/home/foo",
		},

		// 6. Path traversal normalization
		{
			name:     "absolute path with parent ref",
			input:    "/tmp/../home/user",
			expected: "/home/user",
		},
		{
			name:     "absolute path with multiple parent refs",
			input:    "/a/b/c/../../d",
			expected: "/a/d",
		},
		{
			name:     "absolute path with dot",
			input:    "/foo/./bar",
			expected: "/foo/bar",
		},
		{
			name:     "parent ref at root level",
			input:    "/../foo",
			expected: "/foo",
		},

		// 7. Double slashes
		{
			name:     "double slash at start",
			input:    "//foo",
			expected: "/foo",
		},
		{
			name:     "double slash in middle",
			input:    "/foo//bar",
			expected: "/foo/bar",
		},
		{
			name:     "multiple double slashes",
			input:    "/foo//bar//baz",
			expected: "/foo/bar/baz",
		},
		{
			name:     "triple slash",
			input:    "///foo",
			expected: "/foo",
		},

		// 8. Combinations
		{
			name:     "$HOME with parent ref",
			input:    "$HOME/../other",
			expected: "/home/other",
		},
		{
			name:     "tilde with parent ref",
			input:    "~/../other",
			expected: "/home/other",
		},
		{
			name:     "${HOME} with double slash",
			input:    "${HOME}//foo",
			expected: "/home/testuser/foo",
		},
		{
			name:     "env var with parent ref and double slash",
			input:    "$PROJECT/..//other",
			expected: "/opt/other",
		},
		{
			name:     "relative path with double slash",
			input:    "./foo//bar",
			expected: "/home/testuser/project/foo/bar",
		},
		{
			name:     "complex combination",
			input:    "$HOME/../$USER//./data",
			expected: "/home/testuser/data",
		},

		// 9. Edge cases
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "already absolute path",
			input:    "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "root path",
			input:    "/",
			expected: "/",
		},
		{
			name:     "non-existent var with $ syntax becomes empty",
			input:    "$NONEXISTENT/foo",
			expected: "/foo", // var expands to empty, /foo is already absolute
		},
		{
			name:     "non-existent var with ${} syntax becomes empty",
			input:    "${NONEXISTENT}/foo",
			expected: "/foo", // var expands to empty, /foo is already absolute
		},
		{
			name:     "path with trailing slash",
			input:    "/foo/bar/",
			expected: "/foo/bar",
		},
		{
			name:     "just a dot",
			input:    ".",
			expected: "/home/testuser/project",
		},
		{
			name:     "just dot-dot",
			input:    "..",
			expected: "/home/testuser",
		},
		{
			name:     "hidden file relative",
			input:    ".hidden",
			expected: "/home/testuser/project/.hidden",
		},
		{
			name:     "hidden directory with subpath",
			input:    ".config/app/settings",
			expected: "/home/testuser/project/.config/app/settings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := n.Normalize(tt.input)
			if result != tt.expected {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizer_NormalizeAll(t *testing.T) {
	homeDir := "/home/testuser"
	workDir := "/home/testuser/project"
	env := map[string]string{
		"HOME": "/home/testuser",
	}

	n := NewNormalizerWithEnv(homeDir, workDir, env)

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "nil input returns nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "empty slice returns empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "single path",
			input:    []string{"~/.env"},
			expected: []string{"/home/testuser/.env"},
		},
		{
			name:     "multiple paths",
			input:    []string{"~/.env", "$HOME/.ssh", "./config", "/absolute"},
			expected: []string{"/home/testuser/.env", "/home/testuser/.ssh", "/home/testuser/project/config", "/absolute"},
		},
		{
			name:     "paths with empty string",
			input:    []string{"~/foo", "", "bar"},
			expected: []string{"/home/testuser/foo", "", "/home/testuser/project/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := n.NormalizeAll(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("NormalizeAll(%v) = %v, want nil", tt.input, result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("NormalizeAll(%v) returned %d items, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, r := range result {
				if r != tt.expected[i] {
					t.Errorf("NormalizeAll(%v)[%d] = %q, want %q", tt.input, i, r, tt.expected[i])
				}
			}
		})
	}
}

func TestNormalizer_EnvVarEdgeCases(t *testing.T) {
	env := map[string]string{
		"A":         "/a",
		"AB":        "/ab",
		"A_B":       "/a_b",
		"A1":        "/a1",
		"_VAR":      "/underscore",
		"VAR_":      "/var_underscore",
		"VAR123":    "/var123",
		"EMPTY_VAR": "",
	}

	n := NewNormalizerWithEnv("/home/user", "/workdir", env)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single char var",
			input:    "$A/foo",
			expected: "/a/foo",
		},
		{
			name:     "var with numbers",
			input:    "$A1/foo",
			expected: "/a1/foo",
		},
		{
			name:     "var with underscore",
			input:    "$A_B/foo",
			expected: "/a_b/foo",
		},
		{
			name:     "var starting with underscore",
			input:    "$_VAR/foo",
			expected: "/underscore/foo",
		},
		{
			name:     "var ending with underscore",
			input:    "$VAR_/foo",
			expected: "/var_underscore/foo",
		},
		{
			name:     "var with trailing numbers",
			input:    "$VAR123/foo",
			expected: "/var123/foo",
		},
		{
			name:     "empty var value",
			input:    "$EMPTY_VAR/foo",
			expected: "/foo", // empty var results in /foo which is absolute
		},
		{
			name:     "braced empty var value",
			input:    "${EMPTY_VAR}/foo",
			expected: "/foo", // empty var results in /foo which is absolute
		},
		{
			name:     "adjacent vars",
			input:    "$A$AB",
			expected: "/a/ab",
		},
		{
			name:     "braced var allows adjacent text",
			input:    "${A}B",
			expected: "/aB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := n.Normalize(tt.input)
			if result != tt.expected {
				t.Errorf("Normalize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
