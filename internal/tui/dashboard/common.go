package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionSummary holds aggregate stats for one conversation session (dashboard view type).
// Stats are isolated to a single session_id — never mixed with Overview metrics.
type SessionSummary struct {
	SessionID    string    `json:"session_id"`
	Model        string    `json:"model"`
	TotalCalls   int64     `json:"total_calls"`
	BlockedCalls int64     `json:"blocked_calls"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// SessionEvent holds a single tool call event for display in the Sessions tab.
type SessionEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	ToolName      string    `json:"tool_name"`
	WasBlocked    bool      `json:"was_blocked"`
	BlockedByRule string    `json:"blocked_by_rule,omitempty"`
	Layer         string    `json:"layer,omitempty"`
}

// FetchSessions fetches recent sessions from the management API.
// Returns nil on any error so the TUI can degrade gracefully.
func FetchSessions(mgmtClient *http.Client) []SessionSummary {
	resp, err := mgmtClient.Get(apiBaseURL + "/api/telemetry/sessions") //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	var sessions []SessionSummary
	if json.NewDecoder(resp.Body).Decode(&sessions) != nil {
		return nil
	}
	return sessions
}

// FetchSessionEvents fetches recent events for a specific session from the management API.
// Returns nil on any error so the TUI can degrade gracefully.
func FetchSessionEvents(mgmtClient *http.Client, sessionID string) []SessionEvent {
	resp, err := mgmtClient.Get(apiBaseURL + "/api/telemetry/sessions/" + sessionID + "/events") //nolint:noctx
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()

	// Decode subset of fields needed by the TUI — avoids importing the telemetry package.
	var raw []struct {
		Timestamp     time.Time `json:"timestamp"`
		ToolName      string    `json:"tool_name"`
		WasBlocked    bool      `json:"was_blocked"`
		BlockedByRule string    `json:"blocked_by_rule"`
		Layer         string    `json:"layer"`
	}
	if json.NewDecoder(resp.Body).Decode(&raw) != nil {
		return nil
	}

	events := make([]SessionEvent, len(raw))
	for i, r := range raw {
		events[i] = SessionEvent{
			Timestamp:     r.Timestamp,
			ToolName:      r.ToolName,
			WasBlocked:    r.WasBlocked,
			BlockedByRule: r.BlockedByRule,
			Layer:         r.Layer,
		}
	}
	return events
}

// StatusData holds all data for the dashboard display.
type StatusData struct {
	Running   bool
	PID       int
	Healthy   bool
	LogFile   string
	RuleCount int
	Enabled   bool
	Stats     SecurityStats
}

// SecurityStats mirrors API response data for security metrics.
type SecurityStats struct {
	TotalToolCalls int64 `json:"total_tool_calls"`
	BlockedCalls   int64 `json:"blocked_tool_calls"`
	AllowedCalls   int64 `json:"allowed_tool_calls"`
}

// apiBaseURL is the dummy host for socket-based API requests.
// The actual routing happens via the http.Client transport (Unix socket / named pipe).
const apiBaseURL = "http://crust-api"

// proxyClient is a plain HTTP client for proxy health checks (still TCP).
var proxyClient = &http.Client{Timeout: 2 * time.Second}

// FetchStatus fetches health, security status, and stats from the Crust API.
// The mgmtClient uses a Unix socket / named pipe transport for management API calls.
func FetchStatus(mgmtClient *http.Client, proxyBaseURL string, pid int, logFile string) StatusData {
	data := StatusData{Running: true, PID: pid, LogFile: logFile}

	// Fetch health from proxy (still TCP)
	if resp, err := proxyClient.Get(proxyBaseURL + "/health"); err == nil && resp != nil { //nolint:noctx
		resp.Body.Close()
		data.Healthy = resp.StatusCode == http.StatusOK
	}

	// Fetch security status via management socket
	if resp, err := mgmtClient.Get(apiBaseURL + "/api/security/status"); err == nil && resp != nil { //nolint:noctx
		defer resp.Body.Close()
		var result struct {
			Enabled    bool `json:"enabled"`
			RulesCount int  `json:"rules_count"`
		}
		if json.NewDecoder(resp.Body).Decode(&result) == nil {
			data.Enabled = result.Enabled
			data.RuleCount = result.RulesCount
		}
	}

	// Fetch security stats via management socket
	if resp, err := mgmtClient.Get(apiBaseURL + "/api/security/stats"); err == nil && resp != nil { //nolint:noctx
		defer resp.Body.Close()
		var stats SecurityStats
		if json.NewDecoder(resp.Body).Decode(&stats) == nil {
			data.Stats = stats
		}
	}

	return data
}

// RenderPlain renders a plain text status display (no colors, no TUI).
func RenderPlain(data StatusData) string {
	var sb strings.Builder
	if data.Running {
		fmt.Fprintf(&sb, "[crust] Status:   running (PID %d)\n", data.PID)
		if data.Healthy {
			sb.WriteString("[crust] Health:   healthy\n")
		} else {
			sb.WriteString("[crust] Health:   unhealthy\n")
		}
		if data.Enabled {
			sb.WriteString("[crust] Security: enabled\n")
		} else {
			sb.WriteString("[crust] Security: disabled\n")
		}
		fmt.Fprintf(&sb, "[crust] Rules:    %d loaded\n", data.RuleCount)
		if data.Stats.TotalToolCalls > 0 {
			pct := float64(data.Stats.BlockedCalls) / float64(data.Stats.TotalToolCalls) * 100
			fmt.Fprintf(&sb, "[crust] Calls:    %d total, %d blocked (%.1f%%)\n",
				data.Stats.TotalToolCalls, data.Stats.BlockedCalls, pct)
		}
		sb.WriteString("[crust] Logs:     " + data.LogFile)
	} else {
		sb.WriteString("[crust] Status: not running")
	}
	return sb.String()
}
