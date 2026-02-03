package rules

import (
	"os"
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

func TestNormalizer_EmptyHomeDir(t *testing.T) {
	// Test behavior when homeDir is empty
	n := NewNormalizerWithEnv("", "/workdir", map[string]string{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "tilde not expanded when homeDir empty - becomes relative then absolute",
			input:    "~",
			expected: "/workdir/~",
		},
		{
			name:     "tilde path not expanded when homeDir empty - becomes relative then absolute",
			input:    "~/foo",
			expected: "/workdir/~/foo",
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

func TestNormalizer_EmptyWorkDir(t *testing.T) {
	// Test behavior when workDir is empty
	n := NewNormalizerWithEnv("/home/user", "", map[string]string{})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "relative path stays relative when workDir empty",
			input:    "foo",
			expected: "foo",
		},
		{
			name:     "dot-slash path cleaned when workDir empty",
			input:    "./foo",
			expected: "foo",
		},
		{
			name:     "absolute path works without workDir",
			input:    "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "tilde still works without workDir",
			input:    "~/foo",
			expected: "/home/user/foo",
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

func TestNormalizer_NilEnv(t *testing.T) {
	// Test that passing nil env map doesn't panic
	n := NewNormalizerWithEnv("/home/user", "/workdir", nil)

	result := n.Normalize("$NONEXISTENT/foo")
	// Should not panic, var expands to empty, resulting in /foo
	expected := "/foo"
	if result != expected {
		t.Errorf("Normalize with nil env map: got %q, want %q", result, expected)
	}
}

func TestNormalizer_GetHomeDir(t *testing.T) {
	homeDir := "/custom/home"
	n := NewNormalizerWithEnv(homeDir, "/workdir", nil)

	if got := n.GetHomeDir(); got != homeDir {
		t.Errorf("GetHomeDir() = %q, want %q", got, homeDir)
	}
}

func TestNormalizer_GetWorkDir(t *testing.T) {
	workDir := "/custom/workdir"
	n := NewNormalizerWithEnv("/home", workDir, nil)

	if got := n.GetWorkDir(); got != workDir {
		t.Errorf("GetWorkDir() = %q, want %q", got, workDir)
	}
}

func TestNormalizer_SpecialCharactersInEnvVar(t *testing.T) {
	// Test env vars with special path characters
	env := map[string]string{
		"PATH_WITH_SPACES": "/path/with spaces",
		"PATH_WITH_DOTS":   "/path/./with/../dots",
	}

	n := NewNormalizerWithEnv("/home/user", "/workdir", env)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "env var with spaces in value",
			input:    "$PATH_WITH_SPACES/file",
			expected: "/path/with spaces/file",
		},
		{
			name:     "env var with dots gets cleaned",
			input:    "$PATH_WITH_DOTS/file",
			expected: "/path/dots/file",
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

func TestNewNormalizer(t *testing.T) {
	// Test that NewNormalizer creates a valid normalizer
	// We can't test exact values since they depend on the environment
	n := NewNormalizer()

	if n == nil {
		t.Fatal("NewNormalizer() returned nil")
	}

	// Should have non-nil env map
	if n.env == nil {
		t.Error("NewNormalizer() created normalizer with nil env map")
	}

	// HOME should be in the env if it's set in the actual environment
	// This is a soft check - it might not be set in all environments
	if n.homeDir != "" {
		// If homeDir is set, normalizing ~ should work
		result := n.Normalize("~")
		if result != n.homeDir {
			t.Errorf("Normalize(~) = %q, want %q", result, n.homeDir)
		}
	}
}

func TestResolveSymlink(t *testing.T) {
	n := NewNormalizer()

	// Test with non-existent path (should return original)
	nonExistent := "/nonexistent/path/that/does/not/exist"
	result := n.ResolveSymlink(nonExistent)
	if result != nonExistent {
		t.Errorf("ResolveSymlink(%q) = %q, want original path", nonExistent, result)
	}

	// Test with empty string
	result = n.ResolveSymlink("")
	if result != "" {
		t.Errorf("ResolveSymlink(\"\") = %q, want empty string", result)
	}

	// Test with real path (should work if file exists)
	// Using /etc/hosts which exists on most Unix systems
	if _, err := os.Stat("/etc/hosts"); err == nil {
		result = n.ResolveSymlink("/etc/hosts")
		// Should return resolved path (might be same if not a symlink)
		if result == "" {
			t.Error("ResolveSymlink(/etc/hosts) returned empty string")
		}
	}
}

func TestNormalizeWithSymlinks(t *testing.T) {
	n := NewNormalizerWithEnv("/home/user", "/work", map[string]string{
		"HOME": "/home/user",
	})

	// Test that it combines normalize and symlink resolution
	result := n.NormalizeWithSymlinks("~/test")
	// Should at least normalize the tilde
	if result == "~/test" {
		t.Error("NormalizeWithSymlinks should expand tilde")
	}

	// Test with empty string
	result = n.NormalizeWithSymlinks("")
	if result != "" {
		t.Errorf("NormalizeWithSymlinks(\"\") = %q, want empty string", result)
	}
}

func TestNormalizeAllWithSymlinks(t *testing.T) {
	n := NewNormalizerWithEnv("/home/user", "/work", map[string]string{
		"HOME": "/home/user",
	})

	paths := []string{"~/test", "$HOME/file", "./relative"}
	results := n.NormalizeAllWithSymlinks(paths)

	if len(results) != len(paths) {
		t.Errorf("NormalizeAllWithSymlinks returned %d results, want %d", len(results), len(paths))
	}

	// First path should have tilde expanded
	if results[0] == "~/test" {
		t.Error("NormalizeAllWithSymlinks should expand tilde in first path")
	}

	// Test with nil
	results = n.NormalizeAllWithSymlinks(nil)
	if results != nil {
		t.Error("NormalizeAllWithSymlinks(nil) should return nil")
	}
}
