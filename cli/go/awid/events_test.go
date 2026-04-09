package awid

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseAgentEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventName string
		data      string
		check     func(t *testing.T, evt AgentEvent)
	}{
		{
			name:      "connected",
			eventName: "connected",
			data:      `{"agent_id":"a1","team_id":"backend:acme.com"}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventConnected || evt.AgentID != "a1" || evt.TeamID != "backend:acme.com" {
					t.Fatalf("unexpected connected event: %#v", evt)
				}
			},
		},
		{
			name:      "actionable mail",
			eventName: "actionable_mail",
			data:      `{"type":"actionable_mail","message_id":"m2","from_alias":"alice","subject":"hello","wake_mode":"prompt","unread_count":3}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventActionableMail || evt.MessageID != "m2" || evt.FromAlias != "alice" || evt.Subject != "hello" {
					t.Fatalf("unexpected actionable mail event: %#v", evt)
				}
				if evt.WakeMode != "prompt" || evt.Channel != "mail" || evt.UnreadCount != 3 {
					t.Fatalf("unexpected actionable mail metadata: %#v", evt)
				}
			},
		},
		{
			name:      "actionable chat",
			eventName: "actionable_chat",
			data:      `{"type":"actionable_chat","message_id":"m3","from_alias":"mia","session_id":"s2","wake_mode":"interrupt","unread_count":1,"sender_waiting":true}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventActionableChat || evt.MessageID != "m3" || evt.FromAlias != "mia" || evt.SessionID != "s2" {
					t.Fatalf("unexpected actionable chat event: %#v", evt)
				}
				if evt.WakeMode != "interrupt" || evt.Channel != "chat" || evt.UnreadCount != 1 || !evt.SenderWaiting {
					t.Fatalf("unexpected actionable chat metadata: %#v", evt)
				}
			},
		},
		{
			name:      "claim removed",
			eventName: "claim_removed",
			data:      `{"type":"claim_removed","task_id":"t1"}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventClaimRemoved || evt.TaskID != "t1" {
					t.Fatalf("unexpected claim_removed event: %#v", evt)
				}
			},
		},
		{
			name:      "control interrupt",
			eventName: "control_interrupt",
			data:      `{"type":"control_interrupt","signal_id":"sig1"}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventControlInterrupt || evt.SignalID != "sig1" {
					t.Fatalf("unexpected control event: %#v", evt)
				}
			},
		},
		{
			name:      "error",
			eventName: "error",
			data:      `{"detail":"nope"}`,
			check: func(t *testing.T, evt AgentEvent) {
				t.Helper()
				if evt.Type != AgentEventError || evt.Text != `{"detail":"nope"}` {
					t.Fatalf("unexpected error event: %#v", evt)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			evt, ok, err := parseAgentEvent(tt.eventName, tt.data)
			if err != nil {
				t.Fatalf("parseAgentEvent returned error: %v", err)
			}
			if !ok {
				t.Fatal("expected parsed event")
			}
			tt.check(t, evt)
		})
	}
}

func TestParseAgentEventUnknown(t *testing.T) {
	t.Parallel()

	_, ok, err := parseAgentEvent("unknown_type", `{"x":1}`)
	if err != nil {
		t.Fatalf("parseAgentEvent returned error: %v", err)
	}
	if ok {
		t.Fatal("expected unknown event to be ignored")
	}
}

func TestEventStreamRequestsEventStream(t *testing.T) {
	t.Parallel()

	var (
		gotAccept    string
		gotAuth      string
		gotCache     string
		gotDeadline  string
		capturedTime time.Time
		deadlineErr  error
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		gotAuth = r.Header.Get("Authorization")
		gotCache = r.Header.Get("Cache-Control")
		gotDeadline = r.URL.Query().Get("deadline")
		if gotDeadline != "" {
			capturedTime, deadlineErr = time.Parse(time.RFC3339, gotDeadline)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, ": keepalive\n\n")
		_, _ = io.WriteString(w, "event: connected\n")
		_, _ = io.WriteString(w, "data: {\"agent_id\":\"a1\",\"team_id\":\"backend:acme.com\"}\n\n")
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	wantDeadline := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)

	stream, err := c.EventStream(context.Background(), wantDeadline)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if gotAccept != "text/event-stream" {
		t.Fatalf("accept=%q", gotAccept)
	}
	if gotAuth != "" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if gotCache != "no-cache" {
		t.Fatalf("cache-control=%q", gotCache)
	}
	if gotDeadline == "" {
		t.Fatal("missing deadline query parameter")
	}
	if deadlineErr != nil {
		t.Fatalf("deadline parse error: %v", deadlineErr)
	}
	if !capturedTime.Equal(wantDeadline) {
		t.Fatalf("deadline=%v want %v", capturedTime, wantDeadline)
	}

	ev, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != AgentEventConnected {
		t.Fatalf("event=%q", ev.Type)
	}
	if ev.AgentID != "a1" || ev.TeamID != "backend:acme.com" {
		t.Fatalf("unexpected event payload: %#v", ev)
	}
}

func TestEventStreamSkipsUnknownEventsAndSurfacesErrorEvent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: ignored_event\n")
		_, _ = io.WriteString(w, "data: {\"x\":1}\n\n")
		_, _ = io.WriteString(w, "event: error\n")
		_, _ = io.WriteString(w, "data: {\"detail\":\"wake failed\"}\n\n")
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := c.EventStream(context.Background(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	ev, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != AgentEventError {
		t.Fatalf("event=%q", ev.Type)
	}
	if ev.Text != `{"detail":"wake failed"}` {
		t.Fatalf("text=%q", ev.Text)
	}
}

func TestEventStreamHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"nope"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.EventStream(context.Background(), time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("expected stream error")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAgentEventStreamNextNilStream(t *testing.T) {
	t.Parallel()

	var stream *AgentEventStream
	_, err := stream.Next(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEventStreamReturnsEOFOnCleanClose(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: connected\n")
		_, _ = fmt.Fprint(w, "data: {\"agent_id\":\"a1\",\"team_id\":\"backend:acme.com\"}\n\n")
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	stream, err := c.EventStream(context.Background(), time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	ev, err := stream.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ev.Type != AgentEventConnected {
		t.Fatalf("event=%q", ev.Type)
	}
	_, err = stream.Next(context.Background())
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}
