package earlyinit

import "testing"

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
