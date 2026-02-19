package rules

import "testing"

func TestHasProcPath(t *testing.T) {
	tests := []struct {
		name      string
		paths     []string
		wantBlock bool
		wantPath  string
	}{
		// Positive: must block
		{"proc/self/environ", []string{"/proc/self/environ"}, true, "/proc/self/environ"},
		{"proc/pid/environ", []string{"/proc/1234/environ"}, true, "/proc/1234/environ"},
		{"proc/self/cmdline", []string{"/proc/self/cmdline"}, true, "/proc/self/cmdline"},
		{"proc/self/mem", []string{"/proc/self/mem"}, true, "/proc/self/mem"},
		{"proc/self/maps", []string{"/proc/self/maps"}, true, "/proc/self/maps"},
		{"proc/self/fd/3", []string{"/proc/self/fd/3"}, true, "/proc/self/fd/3"},
		{"proc/self/root/etc/passwd", []string{"/proc/self/root/etc/passwd"}, true, "/proc/self/root/etc/passwd"},
		{"proc/self/status", []string{"/proc/self/status"}, true, "/proc/self/status"},
		{"mixed safe and proc", []string{"/tmp/safe.txt", "/proc/self/environ"}, true, "/proc/self/environ"},

		// Negative: must not block
		{"empty paths", nil, false, ""},
		{"safe path only", []string{"/tmp/safe.txt"}, false, ""},
		{"/process prefix", []string{"/process/foo"}, false, ""},
		{"/var/proc nested", []string{"/var/proc/x"}, false, ""},
		{"/procurement", []string{"/procurement/file"}, false, ""},
		{"bare /proc no slash", []string{"/proc"}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, path := hasProcPath(tt.paths)
			if blocked != tt.wantBlock {
				t.Errorf("hasProcPath(%v) blocked = %v, want %v", tt.paths, blocked, tt.wantBlock)
			}
			if path != tt.wantPath {
				t.Errorf("hasProcPath(%v) path = %q, want %q", tt.paths, path, tt.wantPath)
			}
		})
	}
}
