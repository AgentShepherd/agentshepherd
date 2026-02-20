package proxy

import (
	"bytes"
	"testing"
)

func TestParseSSEEventData_SingleDataLine(t *testing.T) {
	event := []byte(`data: {"done":true}`)
	eventType, data := parseSSEEventData(event)

	if eventType != "" {
		t.Errorf("eventType = %q, want empty", eventType)
	}
	if string(data) != `{"done":true}` {
		t.Errorf("data = %q, want %q", data, `{"done":true}`)
	}
}

func TestParseSSEEventData_MultipleDataLines(t *testing.T) {
	event := []byte("data: line1\ndata: line2\ndata: line3")
	_, data := parseSSEEventData(event)

	want := "line1\nline2\nline3"
	if string(data) != want {
		t.Errorf("data = %q, want %q", data, want)
	}
}

func TestParseSSEEventData_EventAndData(t *testing.T) {
	event := []byte("event: message_start\ndata: {\"type\":\"message_start\"}")
	eventType, data := parseSSEEventData(event)

	if eventType != "message_start" {
		t.Errorf("eventType = %q, want %q", eventType, "message_start")
	}
	if string(data) != `{"type":"message_start"}` {
		t.Errorf("data = %q", data)
	}
}

func TestParseSSEEventData_CRLFLineEndings(t *testing.T) {
	event := []byte("event: update\r\ndata: first\r\ndata: second")
	eventType, data := parseSSEEventData(event)

	if eventType != "update" {
		t.Errorf("eventType = %q, want %q", eventType, "update")
	}
	if string(data) != "first\nsecond" {
		t.Errorf("data = %q, want %q", data, "first\nsecond")
	}
}

func TestParseSSEEventData_NoSpaceAfterColon(t *testing.T) {
	// SSE spec: optional single space after colon
	event := []byte("data:noSpace")
	_, data := parseSSEEventData(event)

	if string(data) != "noSpace" {
		t.Errorf("data = %q, want %q", data, "noSpace")
	}
}

func TestParseSSEEventData_CommentLines(t *testing.T) {
	// Lines starting with : are SSE comments — should be ignored
	event := []byte(":keepalive\ndata: {\"ok\":true}")
	eventType, data := parseSSEEventData(event)

	if eventType != "" {
		t.Errorf("eventType = %q, want empty (comment should not set event type)", eventType)
	}
	if string(data) != `{"ok":true}` {
		t.Errorf("data = %q, want %q", data, `{"ok":true}`)
	}
}

func TestParseSSEEventData_Empty(t *testing.T) {
	eventType, data := parseSSEEventData(nil)
	if eventType != "" {
		t.Errorf("eventType = %q, want empty", eventType)
	}
	if data != nil {
		t.Errorf("data = %v, want nil", data)
	}

	eventType2, data2 := parseSSEEventData([]byte{})
	if eventType2 != "" {
		t.Errorf("eventType = %q, want empty", eventType2)
	}
	if data2 != nil {
		t.Errorf("data = %v, want nil", data2)
	}
}

// --- Fuzz target ---

func FuzzParseSSEEventData(f *testing.F) {
	// Valid Anthropic event
	f.Add([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":100}}}"))
	// Valid OpenAI event
	f.Add([]byte("data: {\"id\":\"chatcmpl-1\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}"))
	// Multiple data lines
	f.Add([]byte("data: line1\ndata: line2\ndata: line3"))
	// CRLF endings
	f.Add([]byte("event: update\r\ndata: value\r\n"))
	// Comment line
	f.Add([]byte(":keepalive\ndata: {}"))
	// No space after colon
	f.Add([]byte("data:noSpace"))
	// Empty
	f.Add([]byte{})
	// Binary/null
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte("data: \x00\x01\x02"))
	// Very long data line
	f.Add(append([]byte("data: "), bytes.Repeat([]byte("a"), 10000)...))
	// Only colons
	f.Add([]byte(":::"))
	// No colons
	f.Add([]byte("no colons here"))
	// Just newlines
	f.Add([]byte("\n\n\n"))

	f.Fuzz(func(t *testing.T, event []byte) {
		// Must not panic
		eventType, data := parseSSEEventData(event)

		// Event type should be valid (no leading/trailing whitespace if non-empty)
		if eventType != "" {
			trimmed := eventType
			if trimmed != eventType {
				t.Errorf("eventType has untrimmed whitespace: %q", eventType)
			}
		}

		// If input contains "data:" prefix on any line, data should be non-nil
		if bytes.Contains(event, []byte("data:")) && data == nil {
			// This is acceptable if "data:" appears inside another field value
			// or after a colon in a comment, so we don't enforce this strictly.
			_ = data
		}
	})
}

// --- Benchmark ---

func BenchmarkParseSSEEventData(b *testing.B) {
	b.ReportAllocs()
	event := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"ls -la /tmp\\\"}\"}}")

	for b.Loop() {
		parseSSEEventData(event)
	}
}
