package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
	path := filepath.Join(tmp, ".aw", chat.DeliveredIDsFileName)
	t.Setenv(chat.DeliveredIDsPathEnv, path)
	return tmp
}

func TestRunDispatcherPromptsDurableCatchUpAfterStreamRecovery(t *testing.T) {
	dispatcher := runDispatcher{}
	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{Type: awid.AgentEventChannelReconnected})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip || !strings.Contains(decision.CycleContext, "aw mail inbox") || !strings.Contains(decision.CycleContext, "aw chat pending") {
		t.Fatalf("recovery decision=%+v", decision)
	}
	if len(decision.DisplayLines) != 1 || decision.DisplayLines[0].Text != "aweb: event stream reconnected; catching up" {
		t.Fatalf("recovery display=%v", decision.DisplayLines)
	}
}

func TestRunDispatcherRendersAppEventWakeSummary(t *testing.T) {
	dispatcher := runDispatcher{}
	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:         awid.AgentEventAppEvent,
		EventID:      "evt-1",
		AppEventType: "folio/doc.changed",
		ResourceRef:  "aaai-m22-proof-1781686412",
		Raw:          []byte(`{"event_id":"evt-1","app_event_type":"folio/doc.changed","resource_ref":"aaai-m22-proof-1781686412","delivery_intent":"wake","payload":{"version":8,"source":"api"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Skip {
		t.Fatal("app_event wake should not skip")
	}
	if len(decision.DisplayLines) != 1 {
		t.Fatalf("expected one display line, got %d", len(decision.DisplayLines))
	}
	want := "folio/doc.changed — aaai-m22-proof-1781686412 — version=8, source=api"
	if decision.DisplayLines[0].Text != want {
		t.Fatalf("display line = %q, want %q", decision.DisplayLines[0].Text, want)
	}
	if !strings.Contains(decision.CycleContext, want) {
		t.Fatalf("cycle context %q should include summary %q", decision.CycleContext, want)
	}
}

func TestRunDispatcherRendersAppEventWakeSummaryWithoutResourceRef(t *testing.T) {
	dispatcher := runDispatcher{}
	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:         awid.AgentEventAppEvent,
		EventID:      "evt-2",
		AppEventType: "folio/doc.changed",
		Raw:          []byte(`{"event_id":"evt-2","app_event_type":"folio/doc.changed","delivery_intent":"wake","payload":{"version":8,"source":"api"}}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.DisplayLines) != 1 {
		t.Fatalf("expected one display line, got %d", len(decision.DisplayLines))
	}
	want := "folio/doc.changed — version=8, source=api"
	if decision.DisplayLines[0].Text != want {
		t.Fatalf("display line = %q, want %q", decision.DisplayLines[0].Text, want)
	}
}

func TestRunDispatcherSanitizesAppEventWakeSummaryToSingleLine(t *testing.T) {
	dispatcher := runDispatcher{}
	decision, err := dispatcher.Next(context.Background(), false, &awid.AgentEvent{
		Type:         awid.AgentEventAppEvent,
		EventID:      "evt-3",
		AppEventType: "folio/doc.changed\nInjected:",
		ResourceRef:  "aaai\r\nproof",
		Raw:          []byte("{\"event_id\":\"evt-3\",\"app_event_type\":\"folio/doc.changed\\nInjected:\",\"resource_ref\":\"aaai\\r\\nproof\",\"delivery_intent\":\"wake\",\"payload\":{\"bad\\nkey\":\"ok\\nInjected:\",\"source\":\"api\"}}"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.DisplayLines) != 1 {
		t.Fatalf("expected one display line, got %d", len(decision.DisplayLines))
	}
	want := "folio/doc.changed Injected: — aaai proof — bad key=ok Injected:, source=api"
	if decision.DisplayLines[0].Text != want {
		t.Fatalf("display line = %q, want %q", decision.DisplayLines[0].Text, want)
	}
	if strings.ContainsAny(decision.DisplayLines[0].Text, "\r\n") {
		t.Fatalf("display line should be one line, got %q", decision.DisplayLines[0].Text)
	}
	if strings.ContainsAny(decision.CycleContext, "\r\n") {
		t.Fatalf("cycle context should be one line, got %q", decision.CycleContext)
	}
}

// TestResolveMailWakeMarksReadAfterDelivery verifies that resolving a wake
// leaves mail unread until the caller confirms the prompt reached the model.
func TestResolveMailWakeMarksReadAfterDelivery(t *testing.T) {
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
	if ackedMessageID != "" {
		t.Fatalf("message was acked before model delivery: %q", ackedMessageID)
	}
	if result.AfterDelivery == nil {
		t.Fatal("expected post-delivery acknowledgement")
	}
	if err := result.AfterDelivery(context.Background()); err != nil {
		t.Fatalf("post-delivery ack: %v", err)
	}
	if ackedMessageID != "msg-1" {
		t.Fatalf("expected ack for msg-1 after delivery, got %q", ackedMessageID)
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
						MessageID:      "msg-1",
						ConversationID: "conv-1",
						FromAlias:      "",
						FromAddress:    "otherco/alice",
						Subject:        "hello",
						Body:           "world",
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
	if !strings.Contains(result.CycleContext, `aw mail reply msg-1 --body "..."`) {
		t.Fatalf("expected wake context to include mail reply hint, got %q", result.CycleContext)
	}
}

func TestResolveMailWakeUsesStableIDWhenAliasAndAddressMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:    "msg-1",
						FromAlias:    "",
						FromAddress:  "",
						FromStableID: "did:aw:alice",
						Subject:      "hello",
						Body:         "world",
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
	if !strings.Contains(result.CycleContext, "from did:aw:alice (mail)") {
		t.Fatalf("expected wake context to use sender stable id, got %q", result.CycleContext)
	}
}

func TestResolveMailWakePrefersStableIDOverAliasWhenAddressMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:    "msg-1",
						FromAlias:    "alice",
						FromAddress:  "",
						FromStableID: "did:aw:alice",
						Subject:      "hello",
						Body:         "world",
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
	if !strings.Contains(result.CycleContext, "from did:aw:alice (mail)") {
		t.Fatalf("expected wake context to prefer stable id over alias, got %q", result.CycleContext)
	}
}

func TestResolveMailWakeFallsBackToEventStableIDWhenInboxIdentityMissing(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:   "msg-1",
						FromAlias:   "",
						FromAddress: "",
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
		FromDID:   "did:aw:alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:alice (mail)") {
		t.Fatalf("expected wake context to fall back to event stable id, got %q", result.CycleContext)
	}
}

func TestResolveMailWakeFallsBackToEventFromStableIDWhenCurrentDIDAlsoPresent(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:   "msg-1",
						FromAlias:   "",
						FromAddress: "",
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
		Type:         awid.AgentEventActionableMail,
		MessageID:    "msg-1",
		FromStableID: "did:aw:alice",
		FromDID:      "did:key:z6MkAliceCurrent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:alice (mail)") {
		t.Fatalf("expected wake context to prefer event stable id, got %q", result.CycleContext)
	}
}

func TestResolveMailWakeSkipsSelfWhenOnlyEventCarriesStableID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/messages/inbox":
			json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:   "msg-1",
						FromAlias:   "",
						FromAddress: "",
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

	client := mustIdentityWebClient(t, server.URL, "rose")
	result, err := resolveMailWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableMail,
		MessageID: "msg-1",
		FromDID:   "did:aw:self-rose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored mail wake to skip when only event carries stable id, got %+v", result)
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

// TestResolveChatWakeMarksReadAfterDelivery verifies that resolving a chat wake
// leaves both suppression layers untouched until the provider accepts the
// prompt, matching the mail delivery contract.
func TestResolveChatWakeMarksReadAfterDelivery(t *testing.T) {
	deliveredDir := deliveredIDsTestPath(t)

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
			parts := strings.Split(r.URL.Path, "/")
			markedReadSessionID = parts[4]
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			markedReadUpTo = strings.Join(req.MessageIDs, ",")
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
	if markedReadSessionID != "" {
		t.Fatalf("chat was marked read before provider delivery: %q", markedReadSessionID)
	}
	if delivered, err := chat.LoadDeliveredIDsForDir(deliveredDir); err != nil {
		t.Fatal(err)
	} else if len(delivered) != 0 {
		t.Fatalf("chat was locally suppressed before provider delivery: %#v", delivered)
	}
	if result.AfterDelivery == nil {
		t.Fatal("expected post-delivery chat acknowledgement")
	}
	if err := result.AfterDelivery(context.Background()); err != nil {
		t.Fatalf("post-delivery acknowledgement: %v", err)
	}
	if markedReadSessionID != "s1" || markedReadUpTo != "markread-msg-1" {
		t.Fatalf("mark-read=(%q, %q), want (s1, markread-msg-1)", markedReadSessionID, markedReadUpTo)
	}
	if delivered, err := chat.LoadDeliveredIDsForDir(deliveredDir); err != nil {
		t.Fatal(err)
	} else if _, ok := delivered["markread-msg-1"]; !ok {
		t.Fatalf("presented chat was not durably marked: %#v", delivered)
	}
}

func TestResolveChatWakePresentsAndAcknowledgesWholeIncomingBatch(t *testing.T) {
	deliveredDir := deliveredIDsTestPath(t)
	var markedReadUpTo string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: []awid.ChatMessage{
				{MessageID: "incoming-1", FromAgent: "alice", Body: "first request"},
				{MessageID: "self-1", FromAgent: "rose", Body: "my earlier reply"},
				{MessageID: "incoming-2", FromAgent: "bob", Body: "second request"},
			}})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			markedReadUpTo = strings.Join(req.MessageIDs, ",")
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 2})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "incoming-2",
		FromAlias:   "bob",
		UnreadCount: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected batch delivery, got %+v", result)
	}
	for _, body := range []string{"first request", "second request"} {
		if !strings.Contains(result.CycleContext, body) {
			t.Fatalf("provider context omitted %q: %q", body, result.CycleContext)
		}
	}
	if strings.Contains(result.CycleContext, "my earlier reply") {
		t.Fatalf("provider context included self-authored message: %q", result.CycleContext)
	}
	if result.AfterDelivery == nil {
		t.Fatal("expected batch post-delivery acknowledgement")
	}
	if err := result.AfterDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if markedReadUpTo != "incoming-1,incoming-2" {
		t.Fatalf("marked IDs %q, want incoming-1,incoming-2", markedReadUpTo)
	}
	delivered, err := chat.LoadDeliveredIDsForDir(deliveredDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"incoming-1", "incoming-2"} {
		if _, ok := delivered[id]; !ok {
			t.Fatalf("presented id %q missing from local delivery store: %#v", id, delivered)
		}
	}
	if _, ok := delivered["self-1"]; ok {
		t.Fatalf("self-authored id was locally suppressed: %#v", delivered)
	}
}

func TestResolveChatWakeBoundsBatchAndLeavesRemainderRetryable(t *testing.T) {
	const expectedBatchLimit = 20
	if maxChatMessagesPerWake != expectedBatchLimit {
		t.Fatalf("maxChatMessagesPerWake=%d, want reviewed bound %d", maxChatMessagesPerWake, expectedBatchLimit)
	}
	deliveredDir := deliveredIDsTestPath(t)
	messages := make([]awid.ChatMessage, 121)
	for i := range messages {
		messages[i] = awid.ChatMessage{
			MessageID: fmt.Sprintf("batch-%02d", i),
			FromAgent: "alice",
			Body:      fmt.Sprintf("request-%02d", i),
		}
	}
	acked := -1

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			unread := messages[acked+1:]
			limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil || limit < 1 {
				t.Fatalf("invalid history limit %q", r.URL.Query().Get("limit"))
			}
			// Production selects newest LIMIT rows, then returns that suffix in
			// chronological order.
			if len(unread) > limit {
				unread = unread[len(unread)-limit:]
			}
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: unread})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			for offset, messageID := range req.MessageIDs {
				want := messages[acked+1+offset].MessageID
				if messageID != want {
					t.Fatalf("message_ids[%d]=%q, want %q", offset, messageID, want)
				}
			}
			acked += len(req.MessageIDs)
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	first, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   messages[len(messages)-1].MessageID,
		FromAlias:   "alice",
		UnreadCount: len(messages),
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < expectedBatchLimit; i++ {
		if !strings.Contains(first.CycleContext, messages[i].Body) {
			t.Fatalf("bounded context omitted index %d", i)
		}
	}
	if strings.Contains(first.CycleContext, messages[expectedBatchLimit].Body) {
		t.Fatalf("bounded context included index %d", expectedBatchLimit)
	}
	if first.AfterDelivery == nil {
		t.Fatal("expected bounded batch acknowledgement")
	}
	if err := first.AfterDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if acked != expectedBatchLimit-1 {
		t.Fatalf("acked index=%d, want %d", acked, expectedBatchLimit-1)
	}

	delivered, err := chat.LoadDeliveredIDsForDir(deliveredDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(delivered) != expectedBatchLimit {
		t.Fatalf("delivered count=%d, want %d", len(delivered), expectedBatchLimit)
	}
	second, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   messages[len(messages)-1].MessageID,
		FromAlias:   "alice",
		UnreadCount: len(messages) - expectedBatchLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := expectedBatchLimit; i < expectedBatchLimit*2; i++ {
		if !strings.Contains(second.CycleContext, messages[i].Body) {
			t.Fatalf("next batch omitted index %d: %q", i, second.CycleContext)
		}
	}
	if strings.Contains(second.CycleContext, messages[expectedBatchLimit*2].Body) {
		t.Fatalf("next batch exceeded reviewed bound: %q", second.CycleContext)
	}
}

func TestResolveChatWakePendingDoesNotAckOmittedOlderPrefix(t *testing.T) {
	const expectedBatchLimit = 20
	deliveredIDsTestPath(t)
	messages := make([]awid.ChatMessage, 121)
	for i := range messages {
		messages[i] = awid.ChatMessage{
			MessageID: fmt.Sprintf("pending-%03d", i),
			FromAgent: "alice",
			Body:      fmt.Sprintf("pending-request-%03d", i),
		}
	}
	markedReadUpTo := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{
				SessionID: "s1", LastFrom: "alice", LastMessage: messages[len(messages)-1].Body,
				UnreadCount: len(messages), SenderWaiting: true,
			}}})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
			if err != nil || limit < 1 {
				t.Fatalf("invalid history limit %q", r.URL.Query().Get("limit"))
			}
			selected := messages
			if len(selected) > limit {
				selected = selected[len(selected)-limit:]
			}
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: selected})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			var req awid.ChatMarkReadRequest
			json.NewDecoder(r.Body).Decode(&req)
			markedReadUpTo = strings.Join(req.MessageIDs, ",")
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	resolved, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < expectedBatchLimit; i++ {
		if !strings.Contains(resolved.CycleContext, messages[i].Body) {
			t.Fatalf("pending context omitted oldest index %d: %q", i, resolved.CycleContext)
		}
	}
	if strings.Contains(resolved.CycleContext, messages[expectedBatchLimit].Body) {
		t.Fatalf("pending context exceeded reviewed bound: %q", resolved.CycleContext)
	}
	if resolved.AfterDelivery == nil {
		t.Fatal("expected pending batch acknowledgement")
	}
	if err := resolved.AfterDelivery(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantMarkedIDs := make([]string, 0, expectedBatchLimit)
	for _, message := range messages[:expectedBatchLimit] {
		wantMarkedIDs = append(wantMarkedIDs, message.MessageID)
	}
	if markedReadUpTo != strings.Join(wantMarkedIDs, ",") {
		t.Fatalf("marked IDs %q, want %q", markedReadUpTo, strings.Join(wantMarkedIDs, ","))
	}
}

func TestResolveChatWakePendingIncompleteHistoryReturnsRetryableError(t *testing.T) {
	deliveredIDsTestPath(t)
	var readCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{
				SessionID: "s1", LastFrom: "alice", LastMessage: "newest summary",
				UnreadCount: 121, SenderWaiting: true,
			}}})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			messages := make([]awid.ChatMessage, 100)
			for i := range messages {
				messages[i] = awid.ChatMessage{MessageID: fmt.Sprintf("suffix-%03d", i+21), FromAgent: "alice", Body: "suffix"}
			}
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: messages})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			readCalls++
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	_, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		FromAlias: "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to acknowledge an omitted prefix") {
		t.Fatalf("incomplete history error=%v", err)
	}
	if readCalls != 0 {
		t.Fatalf("incomplete history marked %d times", readCalls)
	}
}

func TestResolveChatWakeEventIncompleteHistoryReturnsRetryableError(t *testing.T) {
	deliveredIDsTestPath(t)
	var pendingCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			pendingCalls++
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			messages := make([]awid.ChatMessage, 100)
			for i := range messages {
				messages[i] = awid.ChatMessage{MessageID: fmt.Sprintf("suffix-%03d", i+21), FromAgent: "alice", Body: "suffix"}
			}
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: messages})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	_, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "suffix-120",
		FromAlias:   "alice",
		UnreadCount: 121,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to acknowledge an omitted prefix") {
		t.Fatalf("incomplete event history error=%v", err)
	}
	if pendingCalls != 1 {
		t.Fatalf("safe pending fallback calls=%d, want 1", pendingCalls)
	}
}

func TestUnreadChatHistoryLimitRejectsUnpageableBacklog(t *testing.T) {
	if _, err := unreadChatHistoryLimit(maxChatHistoryFetch + 1); err == nil {
		t.Fatal("backlog beyond fetch limit must fail rather than watermark an omitted prefix")
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

func TestResolveChatWakeUsesStableIDWhenAliasAndAddressMissing(t *testing.T) {
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{
						MessageID:    "chat-msg-1",
						FromAgent:    "",
						FromAddress:  "",
						FromStableID: "did:aw:alice",
						Body:         "hey",
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
	if !strings.Contains(result.CycleContext, "from did:aw:alice (chat)") {
		t.Fatalf("expected wake context to use sender stable id, got %q", result.CycleContext)
	}
}

func TestResolveChatWakeFallsBackToEventFromStableIDWhenCurrentDIDAlsoPresent(t *testing.T) {
	_ = deliveredIDsTestPath(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{
					{
						MessageID: "chat-msg-1",
						Body:      "hey",
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
		Type:         awid.AgentEventActionableChat,
		SessionID:    "s1",
		MessageID:    "chat-msg-1",
		FromStableID: "did:aw:alice",
		FromDID:      "did:key:z6MkAliceCurrent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:alice (chat)") {
		t.Fatalf("expected wake context to prefer event stable id, got %q", result.CycleContext)
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
						UnreadCount:   0,
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

func TestResolveChatWakeForAliasPendingFallsBackToStableID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{"did:aw:rose", "did:aw:carol"},
						LastMessage:     "follow up",
						LastFrom:        "",
						LastFromDID:     "did:aw:carol",
						UnreadCount:     1,
						SenderWaiting:   true,
					},
				},
				MessagesWaiting: 1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")

	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "chat-msg-1",
		FromAlias:   "",
		FromAddress: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:carol (chat)") {
		t.Fatalf("expected pending wake context to preserve stable identity fallback, got %q", result.CycleContext)
	}
}

func TestResolveChatWakeForAliasPendingPrefersParticipantStableIDOverLastFromCurrentDID(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{"did:aw:rose", "did:aw:carol"},
						LastMessage:     "follow up",
						LastFrom:        "",
						LastFromDID:     "did:key:z6MkCarolCurrent",
						UnreadCount:     1,
						SenderWaiting:   true,
					},
				},
				MessagesWaiting: 1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")

	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:        awid.AgentEventActionableChat,
		SessionID:   "s1",
		MessageID:   "chat-msg-1",
		FromAlias:   "",
		FromAddress: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:carol (chat)") {
		t.Fatalf("expected pending wake context to prefer participant stable identity, got %q", result.CycleContext)
	}
	if strings.Contains(result.CycleContext, "did:key:z6MkCarolCurrent") {
		t.Fatalf("pending wake context should not leak current did, got %q", result.CycleContext)
	}
}

func TestResolveChatWakeForAliasPendingFallsBackToEventStableIDWhenPendingIsAmbiguous(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"", "", ""},
						ParticipantDIDs: []string{"did:aw:rose", "did:aw:carol", "did:aw:dave"},
						LastMessage:     "follow up",
						LastFrom:        "",
						LastFromDID:     "",
						UnreadCount:     1,
						SenderWaiting:   true,
					},
				},
				MessagesWaiting: 1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")

	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:         awid.AgentEventActionableChat,
		SessionID:    "s1",
		MessageID:    "chat-msg-1",
		FromAlias:    "",
		FromAddress:  "",
		FromStableID: "did:aw:carol",
		FromDID:      "did:key:z6MkCarolCurrent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip {
		t.Fatalf("expected wake, got %+v", result)
	}
	if strings.Contains(result.CycleContext, "from another agent (chat)") {
		t.Fatalf("expected event stable id to disambiguate sparse pending wake, got %q", result.CycleContext)
	}
	if !strings.Contains(result.CycleContext, "from did:aw:carol (chat)") {
		t.Fatalf("expected pending wake context to use event stable identity fallback, got %q", result.CycleContext)
	}
}

func TestResolveChatWakeForAliasSkipsSelfWhenOnlyEventStableIDIdentifiesSender(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{"did:aw:self-rose", "did:aw:carol"},
						LastMessage:     "self echo",
						LastFrom:        "",
						LastFromDID:     "",
						UnreadCount:     1,
						SenderWaiting:   true,
					},
				},
				MessagesWaiting: 1,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustIdentityWebClient(t, server.URL, "rose")

	result, err := resolveChatWakeForAlias(context.Background(), client, "rose", awid.AgentEvent{
		Type:         awid.AgentEventActionableChat,
		SessionID:    "s1",
		MessageID:    "chat-msg-self",
		FromAlias:    "",
		FromAddress:  "",
		FromStableID: "did:aw:self-rose",
		FromDID:      "did:key:z6MkSelfRoseCurrent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored sparse pending wake to skip, got %+v", result)
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

func TestResolveChatWakeForAliasSkipsPendingFallbackForSelfStableIDWhenHistoryUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"", ""},
						ParticipantDIDs: []string{"did:aw:self-rose", "did:aw:bob"},
						LastMessage:     "note to self",
						LastFrom:        "",
						LastFromDID:     "did:aw:self-rose",
						SenderWaiting:   true,
						UnreadCount:     1,
					},
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
		FromAlias: "",
		FromDID:   "did:aw:self-rose",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Skip {
		t.Fatalf("expected self-authored pending stable-id fallback to skip, got %+v", result)
	}
}

func TestResolveChatWakeForAliasSkipsPendingFallbackForSelfParticipantAddressWhenHistoryUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:            "s1",
						Participants:         []string{"rose", "bob"},
						ParticipantAddresses: []string{"example.com/rose", "otherco/bob"},
						LastMessage:          "note to self",
						LastFrom:             "rose",
						LastFromAddress:      "",
						SenderWaiting:        true,
						UnreadCount:          1,
					},
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
	if !result.Skip {
		t.Fatalf("expected self-authored pending participant-address fallback to skip, got %+v", result)
	}
}

func TestResolveChatWakeForAliasSkipsPendingFallbackForSelfParticipantStableIDWhenHistoryUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:       "s1",
						Participants:    []string{"rose", "bob"},
						ParticipantDIDs: []string{"did:aw:self-rose", "did:aw:bob"},
						LastMessage:     "note to self",
						LastFrom:        "rose",
						LastFromDID:     "",
						SenderWaiting:   true,
						UnreadCount:     1,
					},
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
	if !result.Skip {
		t.Fatalf("expected self-authored pending participant-stable-id fallback to skip, got %+v", result)
	}
}

func TestResolveChatWakeForAliasDoesNotSkipPendingFallbackForDifferentAddressHandleWhenHistoryUnavailable(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/v1/chat/pending":
			json.NewEncoder(w).Encode(awid.ChatPendingResponse{
				Pending: []awid.ChatPendingItem{
					{
						SessionID:            "s1",
						Participants:         []string{"rose", "bob"},
						ParticipantAddresses: []string{"otherco/rose", "acme.com/bob"},
						LastMessage:          "hello from another rose",
						LastFrom:             "rose",
						LastFromAddress:      "",
						SenderWaiting:        true,
						UnreadCount:          1,
					},
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
		t.Fatalf("expected different-address same-handle pending fallback to wake, got %+v", result)
	}
}

func TestResolveChatWakePropagatesLocalDeliveryMarkFailure(t *testing.T) {
	deliveredDir := deliveredIDsTestPath(t)
	deliveredPath := filepath.Join(deliveredDir, ".aw", chat.DeliveredIDsFileName)
	if err := os.MkdirAll(deliveredPath, 0o700); err != nil {
		t.Fatal(err)
	}
	var markedRead bool

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/chat/sessions/s1/messages"):
			json.NewEncoder(w).Encode(awid.ChatHistoryResponse{Messages: []awid.ChatMessage{
				{MessageID: "persist-failure-1", FromAgent: "alice", Body: "hey"},
			}})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/read"):
			markedRead = true
			json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := mustWebClient(t, server.URL)
	resolved, err := resolveChatWake(context.Background(), client, awid.AgentEvent{
		Type:      awid.AgentEventActionableChat,
		SessionID: "s1",
		MessageID: "persist-failure-1",
		FromAlias: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolved.AfterDelivery == nil {
		t.Fatal("expected post-delivery acknowledgement")
	}
	if err := resolved.AfterDelivery(context.Background()); err == nil {
		t.Fatal("expected local delivery-mark error")
	}
	if !markedRead {
		t.Fatal("local persistence was attempted before the upstream read acknowledgement")
	}
}

func TestRunDispatcherDoesNotRepeatRejectedMalformedChatIDs(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "authoritative malformed uuid", http.StatusUnprocessableEntity)
	}))
	t.Cleanup(server.Close)

	err := markChatMessagesRead(
		context.Background(),
		mustWebClient(t, server.URL),
		"session-bad",
		[]string{"not-a-uuid"},
	)
	if err == nil || !strings.Contains(err.Error(), "authoritative malformed uuid") {
		t.Fatalf("error=%v, want authoritative server rejection", err)
	}
	if calls != 1 {
		t.Fatalf("mark_read_calls=%d, want exactly one", calls)
	}
}

func TestResolveChatWakeFailedMarkReadLeavesMessageRetryable(t *testing.T) {
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
	if markedReadCalls != 0 {
		t.Fatalf("chat was marked read before provider delivery: calls=%d", markedReadCalls)
	}
	if first.AfterDelivery == nil {
		t.Fatal("expected post-delivery acknowledgement")
	}
	if err := first.AfterDelivery(context.Background()); err == nil {
		t.Fatal("expected mark-read failure")
	}
	if markedReadCalls != 2 {
		t.Fatalf("mark_read_calls=%d, want 2", markedReadCalls)
	}

	delivered, err := chat.LoadDeliveredIDsForDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := delivered["dedup-msg-1"]; ok {
		t.Fatalf("failed upstream ack must not suppress message locally: %#v", delivered)
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
	if second.Skip {
		t.Fatalf("failed acknowledgement made the message non-retryable: %+v", second)
	}
}
