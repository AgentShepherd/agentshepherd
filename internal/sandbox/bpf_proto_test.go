package sandbox

import (
	"encoding/json"
	"testing"
)

func TestBPFRequest_JSONRoundtrip(t *testing.T) {
	req := BPFRequest{
		Type: BPFMsgRules,
		Rules: &BPFDenySet{
			Filenames: []BPFDenyEntry{
				{Type: "filename", Key: ".env", RuleID: 1, RuleName: "protect-env"},
			},
			InodePaths: []BPFDenyEntry{
				{Type: "inode", Key: "/home/user/.ssh/id_rsa", RuleID: 2, RuleName: "protect-ssh"},
			},
			Exceptions: []string{".env.example"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BPFRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != BPFMsgRules {
		t.Errorf("Type = %q, want %q", decoded.Type, BPFMsgRules)
	}
	if decoded.Rules == nil {
		t.Fatal("Rules is nil after roundtrip")
	}
	if len(decoded.Rules.Filenames) != 1 {
		t.Errorf("Filenames count = %d, want 1", len(decoded.Rules.Filenames))
	}
	if decoded.Rules.Filenames[0].Key != ".env" {
		t.Errorf("Filenames[0].Key = %q, want .env", decoded.Rules.Filenames[0].Key)
	}
	if len(decoded.Rules.InodePaths) != 1 {
		t.Errorf("InodePaths count = %d, want 1", len(decoded.Rules.InodePaths))
	}
	if len(decoded.Rules.Exceptions) != 1 || decoded.Rules.Exceptions[0] != ".env.example" {
		t.Errorf("Exceptions = %v, want [.env.example]", decoded.Rules.Exceptions)
	}
}

func TestBPFResponse_JSONRoundtrip_OK(t *testing.T) {
	resp := BPFResponse{
		Type:  BPFMsgOK,
		Count: 42,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BPFResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != BPFMsgOK {
		t.Errorf("Type = %q, want %q", decoded.Type, BPFMsgOK)
	}
	if decoded.Count != 42 {
		t.Errorf("Count = %d, want 42", decoded.Count)
	}
}

func TestBPFResponse_JSONRoundtrip_Violation(t *testing.T) {
	resp := BPFResponse{
		Type: BPFMsgViolation,
		Violation: &BPFViolation{
			RuleID:    1,
			RuleName:  "protect-env",
			Filename:  ".env",
			PID:       12345,
			Inode:     67890,
			Timestamp: 1700000000,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BPFResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Violation == nil {
		t.Fatal("Violation is nil after roundtrip")
	}
	v := decoded.Violation
	if v.RuleID != 1 || v.Filename != ".env" || v.PID != 12345 || v.Inode != 67890 {
		t.Errorf("Violation mismatch: %+v", v)
	}
}

func TestBPFResponse_JSONRoundtrip_Error(t *testing.T) {
	resp := BPFResponse{
		Type:  BPFMsgError,
		Error: "something went wrong",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BPFResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != BPFMsgError {
		t.Errorf("Type = %q, want %q", decoded.Type, BPFMsgError)
	}
	if decoded.Error != "something went wrong" {
		t.Errorf("Error = %q, want %q", decoded.Error, "something went wrong")
	}
}

func TestBPFRequest_PID(t *testing.T) {
	req := BPFRequest{
		Type: BPFMsgPID,
		PID:  9999,
		Add:  true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded BPFRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != BPFMsgPID {
		t.Errorf("Type = %q, want %q", decoded.Type, BPFMsgPID)
	}
	if decoded.PID != 9999 {
		t.Errorf("PID = %d, want 9999", decoded.PID)
	}
	if !decoded.Add {
		t.Error("Add = false, want true")
	}
}

func TestBPFMsgType_Constants(t *testing.T) {
	// Ensure constants match expected protocol strings
	if BPFMsgRules != "RULES" {
		t.Errorf("BPFMsgRules = %q", BPFMsgRules)
	}
	if BPFMsgReload != "RELOAD" {
		t.Errorf("BPFMsgReload = %q", BPFMsgReload)
	}
	if BPFMsgPID != "PID" {
		t.Errorf("BPFMsgPID = %q", BPFMsgPID)
	}
	if BPFMsgOK != "OK" {
		t.Errorf("BPFMsgOK = %q", BPFMsgOK)
	}
	if BPFMsgViolation != "VIOLATION" {
		t.Errorf("BPFMsgViolation = %q", BPFMsgViolation)
	}
	if BPFMsgError != "ERROR" {
		t.Errorf("BPFMsgError = %q", BPFMsgError)
	}
}
