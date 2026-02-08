package sandbox

import (
	"testing"
)

func TestContainsGlob(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{".env", false},
		{"id_*", true},
		{"file?.txt", true},
		{"[abc]", true},
		{"credentials", false},
		{"**", true},
		{"", false},
		{"normal.file.name", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := containsGlob(tt.input)
			if got != tt.want {
				t.Errorf("containsGlob(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestClassifyPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		wantType string
		wantKey  string
	}{
		// Filename-based patterns (basename match via BPF hash map)
		{
			name:     "double-star env file",
			pattern:  "**/.env",
			wantType: "filename",
			wantKey:  ".env",
		},
		{
			name:     "double-star bashrc",
			pattern:  "**/.bashrc",
			wantType: "filename",
			wantKey:  ".bashrc",
		},
		{
			name:     "double-star with subdirectory",
			pattern:  "**/.ssh/authorized_keys",
			wantType: "inode",
			wantKey:  "**/.ssh/authorized_keys",
		},
		{
			name:     "double-star git credentials",
			pattern:  "**/.git-credentials",
			wantType: "filename",
			wantKey:  ".git-credentials",
		},
		{
			name:     "double-star deep path",
			pattern:  "**/.config/git/credentials",
			wantType: "inode",
			wantKey:  "**/.config/git/credentials",
		},
		{
			name:     "double-star npmrc",
			pattern:  "**/.npmrc",
			wantType: "filename",
			wantKey:  ".npmrc",
		},
		{
			name:     "double-star Login Data with space (nested **)",
			pattern:  "**/Library/Application Support/Google/Chrome/**/Login Data",
			wantType: "inode",
			wantKey:  "**/Library/Application Support/Google/Chrome/**/Login Data",
		},

		// Inode-based patterns (absolute/home paths, resolved at load time)
		{
			name:     "absolute path",
			pattern:  "/etc/shadow",
			wantType: "inode",
			wantKey:  "/etc/shadow",
		},
		{
			name:     "home-expanded ssh key",
			pattern:  "/home/user/.ssh/id_rsa",
			wantType: "inode",
			wantKey:  "/home/user/.ssh/id_rsa",
		},
		{
			name:     "directory wildcard",
			pattern:  "/home/user/.config/gcloud/**",
			wantType: "inode",
			wantKey:  "/home/user/.config/gcloud/**",
		},

		// Glob in basename → inode (can't use BPF hash for wildcard)
		{
			name:     "glob star in basename",
			pattern:  "**/.ssh/id_*",
			wantType: "inode",
			wantKey:  "**/.ssh/id_*",
		},
		{
			name:     "glob star in filename",
			pattern:  "**/.env.*",
			wantType: "inode",
			wantKey:  "**/.env.*",
		},
		{
			name:     "firefox key db glob",
			pattern:  "**/.mozilla/firefox/**/key*.db",
			wantType: "inode",
			wantKey:  "**/.mozilla/firefox/**/key*.db",
		},

		// Nested double-star → inode (rest contains **/)
		{
			name:     "nested double-star",
			pattern:  "**/.config/google-chrome/**/Login Data",
			wantType: "inode",
			wantKey:  "**/.config/google-chrome/**/Login Data",
		},

		// Fallback (no **/ prefix, not absolute)
		{
			name:     "bare relative path",
			pattern:  "some/relative/path",
			wantType: "inode",
			wantKey:  "some/relative/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := classifyPattern(tt.pattern, 1, "test-rule")
			if entry.Type != tt.wantType {
				t.Errorf("classifyPattern(%q).Type = %q, want %q", tt.pattern, entry.Type, tt.wantType)
			}
			if entry.Key != tt.wantKey {
				t.Errorf("classifyPattern(%q).Key = %q, want %q", tt.pattern, entry.Key, tt.wantKey)
			}
		})
	}
}

func TestExtractBasename(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    string
	}{
		{"simple double-star", "**/.env", ".env"},
		{"double-star with dir", "**/.ssh/authorized_keys", "authorized_keys"},
		{"double-star example", "**/.env.example", ".env.example"},
		{"double-star pub key", "**/.ssh/id_*.pub", ""}, // glob in basename
		{"absolute path", "/etc/shadow", "shadow"},
		{"home path", "~/.ssh/config", "config"},
		{"glob in basename", "**/.env.*", ""},     // glob
		{"directory pattern", "**/.azure/**", ""}, // can't reduce
		{"empty", "", ""},
		{"double-star gnupg conf", "**/.gnupg/*.conf", ""}, // glob
		{"double-star pubring", "**/.gnupg/pubring.gpg", "pubring.gpg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBasename(tt.pattern)
			if got != tt.want {
				t.Errorf("extractBasename(%q) = %q, want %q", tt.pattern, got, tt.want)
			}
		})
	}
}

func TestTranslateToBPF_BasicRules(t *testing.T) {
	bpfTestRules := []SecurityRule{
		&testRule{
			name:   "protect-env-files",
			paths:  []string{"**/.env", "**/.env.*"},
			except: []string{"**/.env.example", "**/.env.template"},
		},
		&testRule{
			name:   "protect-ssh-keys",
			paths:  []string{"**/.ssh/id_*"},
			except: []string{"**/.ssh/id_*.pub"},
		},
		&testRule{
			name:  "protect-bashrc",
			paths: []string{"**/.bashrc"},
		},
	}

	ds := TranslateToBPF(bpfTestRules)

	// **/.env → filename ".env"
	// **/.env.* → inode (glob in basename)
	// **/.ssh/id_* → inode (glob in basename)
	// **/.bashrc → filename ".bashrc"
	if len(ds.Filenames) != 2 {
		t.Errorf("expected 2 filename entries, got %d: %+v", len(ds.Filenames), ds.Filenames)
	}
	if len(ds.InodePaths) != 2 {
		t.Errorf("expected 2 inode entries, got %d: %+v", len(ds.InodePaths), ds.InodePaths)
	}

	// Check filename entries
	filenameKeys := make(map[string]bool)
	for _, e := range ds.Filenames {
		filenameKeys[e.Key] = true
	}
	if !filenameKeys[".env"] {
		t.Error("expected filename entry for .env")
	}
	if !filenameKeys[".bashrc"] {
		t.Error("expected filename entry for .bashrc")
	}

	// Check exceptions: .env.example, .env.template
	// .ssh/id_*.pub has glob → empty from extractBasename
	if len(ds.Exceptions) != 2 {
		t.Errorf("expected 2 exceptions, got %d: %v", len(ds.Exceptions), ds.Exceptions)
	}
}

func TestTranslateToBPF_SkipsDisabledRules(t *testing.T) {
	disabled := false
	disabledRules := []SecurityRule{
		&testRule{
			name:    "disabled-rule",
			enabled: &disabled,
			paths:   []string{"**/.env"},
		},
	}

	ds := TranslateToBPF(disabledRules)
	if len(ds.Filenames) != 0 {
		t.Errorf("expected 0 entries for disabled rule, got %d", len(ds.Filenames))
	}
}

func TestTranslateToBPF_SkipsContentOnlyRules(t *testing.T) {
	contentRules := []SecurityRule{
		&testRule{
			name: "detect-private-key-write",
			// No paths → should be skipped
		},
	}

	ds := TranslateToBPF(contentRules)
	if len(ds.Filenames) != 0 || len(ds.InodePaths) != 0 {
		t.Errorf("expected 0 entries for content-only rule, got filenames=%d inodes=%d",
			len(ds.Filenames), len(ds.InodePaths))
	}
}

func TestTranslateToBPF_RuleIDsIncrement(t *testing.T) {
	idRules := []SecurityRule{
		&testRule{name: "rule-a", paths: []string{"**/.env"}},
		&testRule{name: "rule-b", paths: []string{"**/.bashrc"}},
		&testRule{name: "rule-c", paths: []string{"**/.zshrc"}},
	}

	ds := TranslateToBPF(idRules)

	ids := make(map[uint32]string)
	for _, e := range ds.Filenames {
		if prev, ok := ids[e.RuleID]; ok && prev != e.RuleName {
			// same rule can have multiple entries with same ID, but different rules should have different IDs
			continue
		}
		ids[e.RuleID] = e.RuleName
	}

	if len(ids) != 3 {
		t.Errorf("expected 3 distinct rule IDs, got %d: %v", len(ids), ids)
	}
}

func TestTranslateToBPF_BuiltinSecurityRules(t *testing.T) {
	// Simulate the key builtin rules from security.yaml
	builtinSimRules := []SecurityRule{
		&testRule{
			name:   "protect-env-files",
			paths:  []string{"**/.env", "**/.env.*"},
			except: []string{"**/.env.example", "**/.env.template"},
		},
		&testRule{
			name:   "protect-ssh-keys",
			paths:  []string{"**/.ssh/id_*"},
			except: []string{"**/.ssh/id_*.pub"},
		},
		&testRule{
			name:  "protect-crust",
			paths: []string{"**/.crust/**", "**/crust*.db"},
		},
		&testRule{
			name: "protect-shell-history",
			paths: []string{
				"**/.bash_history", "**/.zsh_history", "**/.sh_history",
				"**/.history", "**/.python_history", "**/.node_repl_history",
			},
		},
		&testRule{
			name: "protect-cloud-credentials",
			paths: []string{
				"**/.aws/credentials", "**/.aws/config",
				"**/.config/gcloud/**", "**/.kube/config",
				"**/.docker/config.json", "**/terraform.tfstate",
			},
		},
		&testRule{
			name:  "protect-shell-rc",
			paths: []string{"**/.bashrc", "**/.zshrc", "**/.profile"},
		},
		&testRule{
			name:  "protect-git-credentials",
			paths: []string{"**/.git-credentials", "**/.config/git/credentials"},
		},
	}

	ds := TranslateToBPF(builtinSimRules)

	// Verify some key filenames are extracted
	filenameKeys := make(map[string]bool)
	for _, e := range ds.Filenames {
		filenameKeys[e.Key] = true
	}

	expectedFilenames := []string{
		".env",
		".bash_history", ".zsh_history", ".sh_history",
		".history", ".python_history", ".node_repl_history",
		".bashrc", ".zshrc", ".profile",
		".git-credentials",
		// NOTE: "credentials", "config", "config.json" are now inode-based
		// because their patterns have directory components (e.g. **/.aws/credentials).
		// Basename-only matching would block ALL files with those common names system-wide.
		"terraform.tfstate",
	}

	for _, name := range expectedFilenames {
		if !filenameKeys[name] {
			t.Errorf("expected filename entry for %q, not found in %v", name, filenameKeys)
		}
	}

	// Verify inode entries exist for glob/directory patterns
	if len(ds.InodePaths) == 0 {
		t.Error("expected some inode entries for glob/directory patterns")
	}

	// Verify exceptions
	exceptionSet := make(map[string]bool)
	for _, ex := range ds.Exceptions {
		exceptionSet[ex] = true
	}
	if !exceptionSet[".env.example"] {
		t.Error("expected .env.example in exceptions")
	}
	if !exceptionSet[".env.template"] {
		t.Error("expected .env.template in exceptions")
	}
}

func TestTranslateToBPF_EmptyRules(t *testing.T) {
	ds := TranslateToBPF(nil)
	if ds == nil {
		t.Fatal("expected non-nil BPFDenySet")
	}
	if len(ds.Filenames) != 0 || len(ds.InodePaths) != 0 || len(ds.Exceptions) != 0 {
		t.Errorf("expected empty sets, got filenames=%d inodes=%d exceptions=%d",
			len(ds.Filenames), len(ds.InodePaths), len(ds.Exceptions))
	}
}

func TestClassifyPattern_BarePatterns(t *testing.T) {
	tests := []struct {
		pattern  string
		wantType string
	}{
		{"", "inode"},         // empty → fallback
		{"/", "inode"},        // root → absolute
		{"**", "inode"},       // bare double-star (no /) → fallback
		{"**/", "filename"},   // double-star with trailing / → basename=""
		{"file.txt", "inode"}, // bare relative → fallback
	}
	for _, tt := range tests {
		entry := classifyPattern(tt.pattern, 1, "test")
		if entry.Type != tt.wantType {
			t.Errorf("classifyPattern(%q).Type = %q, want %q", tt.pattern, entry.Type, tt.wantType)
		}
	}
}

func TestClassifyPattern_NoBasenameConfusion(t *testing.T) {
	// These patterns have directory components — must NOT use basename-only matching
	// because it would block all files with that name system-wide
	confusingPatterns := []struct {
		pattern  string
		basename string // the basename that would be falsely blocked
	}{
		{"**/.aws/credentials", "credentials"},
		{"**/.aws/config", "config"},
		{"**/.ssh/authorized_keys", "authorized_keys"},
		{"**/.docker/config.json", "config.json"},
		{"**/.kube/config", "config"},
		{"**/.config/git/credentials", "credentials"},
	}

	for _, tt := range confusingPatterns {
		t.Run(tt.pattern, func(t *testing.T) {
			entry := classifyPattern(tt.pattern, 1, "test")
			if entry.Type == "filename" {
				t.Errorf("classifyPattern(%q) = filename with key %q — "+
					"this blocks ALL files named %q system-wide!",
					tt.pattern, entry.Key, tt.basename)
			}
			if entry.Type != "inode" {
				t.Errorf("classifyPattern(%q).Type = %q, want inode", tt.pattern, entry.Type)
			}
		})
	}
}

func TestClassifyPattern_PureBasenameStillWorks(t *testing.T) {
	// Patterns WITHOUT directory components should still use filename matching
	safePatterns := []struct {
		pattern string
		key     string
	}{
		{"**/.env", ".env"},
		{"**/.bashrc", ".bashrc"},
		{"**/.zshrc", ".zshrc"},
		{"**/.git-credentials", ".git-credentials"},
		{"**/.npmrc", ".npmrc"},
		{"**/.bash_history", ".bash_history"},
	}

	for _, tt := range safePatterns {
		t.Run(tt.pattern, func(t *testing.T) {
			entry := classifyPattern(tt.pattern, 1, "test")
			if entry.Type != "filename" {
				t.Errorf("classifyPattern(%q).Type = %q, want filename", tt.pattern, entry.Type)
			}
			if entry.Key != tt.key {
				t.Errorf("classifyPattern(%q).Key = %q, want %q", tt.pattern, entry.Key, tt.key)
			}
		})
	}
}

func TestClassifyPattern_AllAbsolutePathsAreInode(t *testing.T) {
	paths := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/home/user/.ssh/id_rsa",
		"/var/log/auth.log",
	}
	for _, p := range paths {
		entry := classifyPattern(p, 1, "test")
		if entry.Type != "inode" {
			t.Errorf("classifyPattern(%q).Type = %q, want inode", p, entry.Type)
		}
	}
}
