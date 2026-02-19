package sandbox

import "testing"

func TestParseSandboxError(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		wantCode ErrorCode
		wantMsg  string
		wantNil  bool
	}{
		{
			name:     "valid enforcement_unavailable",
			input:    []byte(`{"error":"enforcement_unavailable","message":"Landlock not supported on this kernel"}`),
			wantCode: ErrEnforcementUnavailable,
			wantMsg:  "Landlock not supported on this kernel",
		},
		{
			name:     "valid command_not_found",
			input:    []byte(`{"error":"command_not_found","message":"python3: not found in PATH"}`),
			wantCode: ErrCommandNotFound,
			wantMsg:  "python3: not found in PATH",
		},
		{
			name:     "valid parse_error",
			input:    []byte("{\"error\":\"parse_error\",\"message\":\"invalid version field\"}\n"),
			wantCode: ErrParse,
			wantMsg:  "invalid version field",
		},
		{
			name:    "empty input",
			input:   []byte(""),
			wantNil: true,
		},
		{
			name:    "non-JSON",
			input:   []byte("bakelens-sandbox: some error message"),
			wantNil: true,
		},
		{
			name:    "JSON missing error field",
			input:   []byte(`{"message":"something"}`),
			wantNil: true,
		},
		{
			name:    "JSON missing message field",
			input:   []byte(`{"error":"sandbox_error"}`),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSandboxError(tt.input)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil Error")
			}
			if got.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", got.Code, tt.wantCode)
			}
			if got.Message != tt.wantMsg {
				t.Errorf("message = %q, want %q", got.Message, tt.wantMsg)
			}
		})
	}
}

func TestErrorInterface(t *testing.T) {
	se := &Error{Code: ErrExecFailed, Message: "permission denied"}
	want := "exec_failed: permission denied"
	if got := se.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
