package earlyinit

import "testing"

func TestShouldSuppress(t *testing.T) {
	tests := []struct {
		name       string
		foreground bool
		isTTY      bool
		want       bool
	}{
		{"not foreground, no TTY", false, false, false},
		{"not foreground, with TTY", false, true, false},
		{"foreground, no TTY", true, false, true},
		{"foreground, with TTY", true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldSuppress(tt.foreground, tt.isTTY); got != tt.want {
				t.Errorf("ShouldSuppress(%v, %v) = %v, want %v", tt.foreground, tt.isTTY, got, tt.want)
			}
		})
	}
}

func TestHasForeground(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"nil args", nil, false},
		{"empty args", []string{}, false},
		{"only program name", []string{"crust"}, false},
		{"foreground present", []string{"crust", "--foreground"}, true},
		{"foreground with other flags", []string{"crust", "--port", "8080", "--foreground"}, true},
		{"foreground first", []string{"crust", "--foreground", "--port", "8080"}, true},
		{"no foreground", []string{"crust", "--port", "8080"}, false},
		{"double dash stops scan", []string{"crust", "--", "--foreground"}, false},
		{"foreground before double dash", []string{"crust", "--foreground", "--", "extra"}, true},
		{"similar but wrong flag", []string{"crust", "--foregrounds"}, false},
		{"substring not matched", []string{"crust", "foreground"}, false},
		{"flag with equals", []string{"crust", "--foreground=true"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasForeground(tt.args); got != tt.want {
				t.Errorf("HasForeground(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
