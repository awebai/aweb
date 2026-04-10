package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

func mustWebClient(t *testing.T, url string) *aweb.Client {
	t.Helper()
	c, err := aweb.New(url)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustIdentityWebClient(t *testing.T, url string, alias string) *aweb.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := awid.NewWithIdentity(url, priv, awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	raw.SetStableID("did:aw:self-" + alias)
	raw.SetAddress("example.com/" + alias)
	return &aweb.Client{Client: raw}
}

func deliveredIDsTestPath(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	prev, hadPrev := os.LookupEnv(chat.DeliveredIDsPathEnv)
	path := filepath.Join(tmp, ".aw", chat.DeliveredIDsFileName)
	if err := os.Setenv(chat.DeliveredIDsPathEnv, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if hadPrev {
			_ = os.Setenv(chat.DeliveredIDsPathEnv, prev)
			return
		}
		_ = os.Unsetenv(chat.DeliveredIDsPathEnv)
	})
	return tmp
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

func TestResolveMailWakeUsesFromAddressWhenAliasMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:   "msg-1",
						FromAlias:   "",
						FromAddress: "otherco/alice",
						Subject:     "hello",
						Body:        "world",
					},
				},
			})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveMailWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		MessageID: "msg-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from otherco/alice (mail)") {
		t.Fatalf("expected wake context to use sender address, got %q", result.CycleContext)
	}
}

func TestResolveMailWakeSkipsSelfAuthoredMessageByAddress(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:   "msg-self-mail",
						FromAlias:   "",
						FromAddress: "example.com/rose",
						Subject:     "note",
						Body:        "self reminder",
					},
				},
			})
		case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-self-mail"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")
	result, err := resolveMailWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		MessageID: "msg-self-mail",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored mail wake to skip, got %+v", result)
	}
}

func TestFormatFallbackCommsContextPrefersFromAddress(t *testing.T) {
	t.Parallel()

	chatCtx := formatFallbackCommsContext(awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		FromAlias:   "alice",
		FromAddress: "otherco/alice",
	})
	if !strings.Contains(chatCtx, "from otherco/alice (chat)") {
		t.Fatalf("expected chat fallback to prefer address, got %q", chatCtx)
	}

	mailCtx := formatFallbackCommsContext(awid.AgentEvent{
		Type:        awid.AgentEventActionableMail,
		FromAlias:   "alice",
		FromAddress: "otherco/alice",
		Subject:     "hello",
	})
	if !strings.Contains(mailCtx, "from otherco/alice (mail)") {
		t.Fatalf("expected mail fallback to prefer address, got %q", mailCtx)
	}
}

// TestResolveChatWakeMarksRead verifies that resolveChatWake marks messages
// as read after fetching the pending conversation.
func TestResolveChatWakeMarksRead(t *testing.T) {
	_ = deliveredIDsTestPath(t)

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
					{MessageID: "markread-msg-1", FromAgent: "alice", Body: "hey"},
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
	if markedReadUpTo != "markread-msg-1" {
		t.Fatalf("expected mark-read up to markread-msg-1, got %q", markedReadUpTo)
	}
}

func TestResolveChatWakeUsesFromAddressWhenAliasMissing(t *testing.T) {
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{
						MessageID:   "chat-msg-1",
						FromAgent:   "",
						FromAddress: "otherco/alice",
						Body:        "hey",
					},
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
	result, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		MessageID: "chat-msg-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from otherco/alice (chat)") {
		t.Fatalf("expected wake context to use sender address, got %q", result.CycleContext)
	}
}

func TestResolveChatWakePendingFallsBackToEventFromAddress(t *testing.T) {
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:     "s1",
						Participants:  []string{"alice", "carol"},
						LastMessage:   "hey",
						LastFrom:      "carol",
						SenderWaiting: true,
						UnreadCount:   1,
					},
				},
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: []awid.ChatMessage{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		FromAlias:   "carol",
		FromAddress: "otherco/carol",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from otherco/carol (chat)") {
		t.Fatalf("expected pending wake context to fall back to event from_address, got %q", result.CycleContext)
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

func TestResolveChatWakeForAliasSkipsSelfAuthoredAddressMessage(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "chat-msg-self-address", FromAgent: "", FromAddress: "example.com/rose", Body: "thanks, got it"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")
	result, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		MessageID: "chat-msg-self-address",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored address chat wake to skip, got %+v", result)
	}
}

func TestResolveChatWakeForAliasDoesNotSkipDifferentIdentityWithSameAlias(t *testing.T) {
	t.Parallel()
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{
						MessageID:    "chat-msg-foreign-rose",
						FromAgent:    "rose",
						FromDID:      "did:aw:other-rose",
						FromStableID: "did:aw:other-rose",
						Body:         "hello from another rose",
					},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")
	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		MessageID: "chat-msg-foreign-rose",
		FromAlias: "rose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected different identity with same alias to wake, got %+v", result)
	}
}

func TestResolveChatWakeForAliasDoesNotSkipPendingFallbackForDifferentIdentitySameAlias(t *testing.T) {
	t.Parallel()
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{SessionID: "s1", Participants: []string{"rose", "bob"}, LastMessage: "hello from another rose", LastFrom: "rose", SenderWaiting: true, UnreadCount: 1},
				},
			})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			http.Error(w, "boom", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")
	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "rose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected pending fallback from different identity with same alias to wake, got %+v", result)
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

func TestResolveChatWakeRetriesMarkReadAndCachesDeliveredIDs(t *testing.T) {
	tmp := deliveredIDsTestPath(t)

	var markedReadCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{MessageID: "dedup-msg-1", FromAgent: "alice", Body: "hey"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			markedReadCalls++
			http.Error(w, "still failing", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	first, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "dedup-msg-1",
		FromAlias:   "alice",
		UnreadCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Skip {
		t.Fatalf("first delivery unexpectedly skipped: %+v", first)
	}
	if markedReadCalls != 2 {
		t.Fatalf("mark_read_calls=%d, want 2", markedReadCalls)
	}

	delivered, err := chat.LoadDeliveredIDsForDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := delivered["dedup-msg-1"]; !ok {
		t.Fatalf("missing delivered id dedup-msg-1: %#v", delivered)
	}

	second, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "dedup-msg-1",
		FromAlias:   "alice",
		UnreadCount: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.Skip {
		t.Fatalf("expected duplicate wake to be skipped, got %+v", second)
	}
}
