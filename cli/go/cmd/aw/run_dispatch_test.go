package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
)

func mustWebClient(t *testing.T, url string) *aweb.Client {
	t.Helper()
	c, err := aweb.New(url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestResolveMailWakeMarksRead verifies that resolveMailWake acks the message
// after fetching it from the inbox.
func TestResolveMailWakeMarksRead(t *testing.T) {
	t.Parallel()

	var ackedMessageID string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{MessageID: "msg-1", FromAlias: "alice", Subject: "hello", Body: "world"},
				},
			})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			parts := strings.Split(r.URL.Path, "/")
			ackedMessageID = parts[3] // /v1/messages/{id}/ack
			json.NewEncoder(w).Encode(awid.AckResponse{MessageID: ackedMessageID})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveMailWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		MessageID: "msg-1",
		FromAlias: "alice",
		Subject:   "hello",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatal("should not skip")
	}
	if ackedMessageID != "msg-1" {
		t.Fatalf("expected ack for msg-1, got %q", ackedMessageID)
	}
}

// TestResolveChatWakeMarksRead verifies that resolveChatWake marks messages
// as read after fetching the pending conversation.
func TestResolveChatWakeMarksRead(t *testing.T) {
	t.Parallel()

	var markedReadSessionID string
	var markedReadUpTo string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"alice", "bob"}, LastMessage: "hey", LastFrom: "alice", SenderWaiting: true, UnreadCount: 1},
				},
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "chat-msg-1", FromAgent: "alice", Body: "hey"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			// /v1/chat/sessions/{id}/read → parts: ["", "v1", "chat", "sessions", "{id}", "read"]
			parts := strings.Split(r.URL.Path, "/")
			markedReadSessionID = parts[4]
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			markedReadUpTo = req.UpToMessageID
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatal("should not skip")
	}
	if markedReadSessionID != "s1" {
		t.Fatalf("expected mark-read for session s1, got %q", markedReadSessionID)
	}
	if markedReadUpTo != "chat-msg-1" {
		t.Fatalf("expected mark-read up to chat-msg-1, got %q", markedReadUpTo)
	}
}

func TestResolveChatWakeForAliasSkipsSelfAuthoredExactMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "chat-msg-1", FromAgent: "rose", Body: "thanks, got it"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		MessageID: "chat-msg-1",
		FromAlias: "eve",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored chat wake to skip, got %+v", result)
	}
}

func TestResolveChatWakeForAliasSkipsPendingFallbackWhenUnreadHistoryIsOnlySelfAuthored(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"eve", "rose"}, LastMessage: "thanks, got it", LastFrom: "eve", SenderWaiting: true, UnreadCount: 1},
				},
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "chat-msg-2", FromAgent: "rose", Body: "thanks, got it"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "eve",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected pending self-echo to skip, got %+v", result)
	}
}
