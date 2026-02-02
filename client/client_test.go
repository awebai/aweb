package aweb

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIntrospectAddsBearerHeader(t *testing.T) {
	t.Parallel()

	wantProjectID := "11111111-1111-1111-1111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/auth/introspect" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"project_id": wantProjectID})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Introspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProjectID != wantProjectID {
		t.Fatalf("project_id=%s", resp.ProjectID)
	}
}

func TestChatStreamRequestsEventStream(t *testing.T) {
	t.Parallel()

	var gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message\ndata: {\"ok\":true}\n\n"))
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.ChatStream(context.Background(), "sess", time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	if gotAccept != "text/event-stream" {
		t.Fatalf("accept=%q", gotAccept)
	}

	ev, err := stream.Next()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Event != "message" {
		t.Fatalf("event=%q", ev.Event)
	}
	if !strings.Contains(ev.Data, "\"ok\":true") {
		t.Fatalf("data=%q", ev.Data)
	}
}

func TestChatSendMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions/test-session/messages" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Body != "hello" {
			t.Fatalf("body=%q", body.Body)
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-1",
			Delivered:          true,
			ExtendsWaitSeconds: 0,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.MessageID != "msg-1" {
		t.Fatalf("message_id=%s", resp.MessageID)
	}
	if !resp.Delivered {
		t.Fatal("delivered=false")
	}
}

func TestChatSendMessageHangOn(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body ChatSendMessageRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !body.HangOn {
			t.Fatal("expected hang_on=true")
		}
		_ = json.NewEncoder(w).Encode(ChatSendMessageResponse{
			MessageID:          "msg-2",
			Delivered:          true,
			ExtendsWaitSeconds: 300,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatSendMessage(context.Background(), "test-session", &ChatSendMessageRequest{
		Body:   "thinking...",
		HangOn: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ExtendsWaitSeconds != 300 {
		t.Fatalf("extends_wait_seconds=%d", resp.ExtendsWaitSeconds)
	}
}

func TestChatListSessions(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/chat/sessions" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ChatListSessionsResponse{
			Sessions: []ChatSessionItem{
				{SessionID: "s1", Participants: []string{"alice", "bob"}, CreatedAt: "2025-01-01T00:00:00Z"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ChatListSessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Sessions) != 1 {
		t.Fatalf("sessions=%d", len(resp.Sessions))
	}
	if resp.Sessions[0].SessionID != "s1" {
		t.Fatalf("session_id=%s", resp.Sessions[0].SessionID)
	}
	if len(resp.Sessions[0].Participants) != 2 {
		t.Fatalf("participants=%d", len(resp.Sessions[0].Participants))
	}
}

func TestChatPendingItemNullTimeRemaining(t *testing.T) {
	t.Parallel()

	raw := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":false,"time_remaining_seconds":null}`
	var item ChatPendingItem
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatal(err)
	}
	if item.TimeRemainingSeconds != nil {
		t.Fatalf("expected nil, got %d", *item.TimeRemainingSeconds)
	}

	raw2 := `{"session_id":"s1","participants":["a","b"],"last_message":"hi","last_from":"a","unread_count":1,"last_activity":"2025-01-01T00:00:00Z","sender_waiting":true,"time_remaining_seconds":42}`
	var item2 ChatPendingItem
	if err := json.Unmarshal([]byte(raw2), &item2); err != nil {
		t.Fatal(err)
	}
	if item2.TimeRemainingSeconds == nil || *item2.TimeRemainingSeconds != 42 {
		t.Fatalf("expected 42, got %v", item2.TimeRemainingSeconds)
	}
}
