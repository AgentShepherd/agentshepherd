package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer returns an httptest.Server that handles management API routes.
func newTestServer(status any, stats any, sessions any, events any) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/api/security/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(status) //nolint:errcheck
	})
	mux.HandleFunc("/api/security/stats", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(stats) //nolint:errcheck
	})
	mux.HandleFunc("/api/telemetry/sessions", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(sessions) //nolint:errcheck
	})
	mux.HandleFunc("/api/telemetry/sessions/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(events) //nolint:errcheck
	})
	return httptest.NewServer(mux)
}

func TestFetchStatus(t *testing.T) {
	srv := newTestServer(
		map[string]any{"enabled": true, "rules_count": 14},
		SecurityStats{TotalToolCalls: 100, BlockedCalls: 5, AllowedCalls: 95},
		nil, nil,
	)
	defer srv.Close()

	client := srv.Client()
	data := FetchStatus(client, srv.URL, srv.URL, 42, "/tmp/test.log")

	if !data.Running {
		t.Error("expected Running=true")
	}
	if data.PID != 42 {
		t.Errorf("PID = %d, want 42", data.PID)
	}
	if !data.Healthy {
		t.Error("expected Healthy=true")
	}
	if !data.Enabled {
		t.Error("expected Enabled=true")
	}
	if data.RuleCount != 14 {
		t.Errorf("RuleCount = %d, want 14", data.RuleCount)
	}
	if data.Stats.TotalToolCalls != 100 {
		t.Errorf("TotalToolCalls = %d, want 100", data.Stats.TotalToolCalls)
	}
	if data.Stats.BlockedCalls != 5 {
		t.Errorf("BlockedCalls = %d, want 5", data.Stats.BlockedCalls)
	}
	if data.LogFile != "/tmp/test.log" {
		t.Errorf("LogFile = %q, want /tmp/test.log", data.LogFile)
	}
}

func TestFetchStatusUsesAPIBase(t *testing.T) {
	// Verify that FetchStatus uses the provided apiBase, not a hardcoded host.
	// A plain http.Client with no socket transport must reach the test server.
	srv := newTestServer(
		map[string]any{"enabled": true, "rules_count": 7},
		SecurityStats{TotalToolCalls: 10, BlockedCalls: 2, AllowedCalls: 8},
		nil, nil,
	)
	defer srv.Close()

	// Use a plain client (no custom transport) — same as newRemoteAPIClient
	client := &http.Client{}
	data := FetchStatus(client, srv.URL, srv.URL, 0, "")

	if data.RuleCount != 7 {
		t.Errorf("RuleCount = %d, want 7 (apiBase not used?)", data.RuleCount)
	}
	if data.Stats.TotalToolCalls != 10 {
		t.Errorf("TotalToolCalls = %d, want 10 (apiBase not used?)", data.Stats.TotalToolCalls)
	}
}

func TestFetchStatusServerDown(t *testing.T) {
	// Unreachable server — should return zero values, not panic.
	client := &http.Client{}
	data := FetchStatus(client, "http://127.0.0.1:1", "http://127.0.0.1:1", 0, "")

	if data.Healthy {
		t.Error("expected Healthy=false for unreachable server")
	}
	if data.Enabled {
		t.Error("expected Enabled=false for unreachable server")
	}
	if data.RuleCount != 0 {
		t.Errorf("RuleCount = %d, want 0", data.RuleCount)
	}
}

func TestFetchSessions(t *testing.T) {
	sessions := []SessionSummary{
		{SessionID: "s1", Model: "claude-3", TotalCalls: 10, BlockedCalls: 1},
		{SessionID: "s2", Model: "gpt-4", TotalCalls: 5, BlockedCalls: 0},
	}
	srv := newTestServer(nil, nil, sessions, nil)
	defer srv.Close()

	result := FetchSessions(&http.Client{}, srv.URL)
	if len(result) != 2 {
		t.Fatalf("got %d sessions, want 2", len(result))
	}
	if result[0].SessionID != "s1" {
		t.Errorf("sessions[0].SessionID = %q, want s1", result[0].SessionID)
	}
	if result[1].Model != "gpt-4" {
		t.Errorf("sessions[1].Model = %q, want gpt-4", result[1].Model)
	}
}

func TestFetchSessionsServerDown(t *testing.T) {
	result := FetchSessions(&http.Client{}, "http://127.0.0.1:1")
	if result != nil {
		t.Errorf("expected nil for unreachable server, got %v", result)
	}
}

func TestFetchSessionEvents(t *testing.T) {
	events := []SessionEvent{
		{ToolName: "read_file", WasBlocked: false, Layer: "L1"},
		{ToolName: "bash", WasBlocked: true, BlockedByRule: "block-rm-rf", Layer: "L1"},
	}
	srv := newTestServer(nil, nil, nil, events)
	defer srv.Close()

	result := FetchSessionEvents(&http.Client{}, srv.URL, "s1")
	if len(result) != 2 {
		t.Fatalf("got %d events, want 2", len(result))
	}
	if result[0].ToolName != "read_file" {
		t.Errorf("events[0].ToolName = %q, want read_file", result[0].ToolName)
	}
	if !result[1].WasBlocked {
		t.Error("expected events[1].WasBlocked=true")
	}
	if result[1].BlockedByRule != "block-rm-rf" {
		t.Errorf("events[1].BlockedByRule = %q, want block-rm-rf", result[1].BlockedByRule)
	}
}

func TestFetchSessionEventsServerDown(t *testing.T) {
	result := FetchSessionEvents(&http.Client{}, "http://127.0.0.1:1", "s1")
	if result != nil {
		t.Errorf("expected nil for unreachable server, got %v", result)
	}
}

func TestRenderPlain(t *testing.T) {
	data := StatusData{
		Running:   true,
		PID:       1234,
		Healthy:   true,
		Enabled:   true,
		RuleCount: 14,
		LogFile:   "/tmp/crust.log",
		Stats:     SecurityStats{TotalToolCalls: 100, BlockedCalls: 10, AllowedCalls: 90},
	}
	out := RenderPlain(data)
	for _, want := range []string{"PID 1234", "healthy", "enabled", "14 loaded", "100 total", "10 blocked", "/tmp/crust.log"} {
		if !contains(out, want) {
			t.Errorf("RenderPlain missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderPlainNotRunning(t *testing.T) {
	out := RenderPlain(StatusData{Running: false})
	if !contains(out, "not running") {
		t.Errorf("expected 'not running' in: %s", out)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
