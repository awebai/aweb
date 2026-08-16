package awid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInboxSendsCursorAndPreservesPaginationMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/inbox" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		if got := r.URL.Query().Get("cursor"); got != "page-two" {
			t.Fatalf("cursor=%q", got)
		}
		_ = json.NewEncoder(w).Encode(InboxResponse{
			Messages:   []InboxMessage{{MessageID: "message-2"}},
			HasMore:    true,
			NextCursor: "page-three",
		})
	}))
	defer server.Close()

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Inbox(context.Background(), InboxParams{Limit: 1, Cursor: "page-two"})
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasMore || page.NextCursor != "page-three" || len(page.Messages) != 1 {
		t.Fatalf("page=%+v", page)
	}
}

func TestMessageUsesParticipantVisibleExactRoute(t *testing.T) {
	t.Parallel()
	messageID := "11111111-1111-4111-8111-111111111111"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/"+messageID {
			t.Fatalf("path=%q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(InboxMessage{MessageID: messageID, Body: "sent mail"})
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Message(context.Background(), messageID)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Messages) != 1 || response.Messages[0].Body != "sent mail" {
		t.Fatalf("response=%+v", response)
	}
}

func TestMessageFallsBackToRecipientInboxOnOlderServer(t *testing.T) {
	t.Parallel()
	messageID := "22222222-2222-4222-8222-222222222222"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/v1/messages/" + messageID:
			http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)
		case "/v1/messages/inbox":
			if got := r.URL.Query().Get("message_id"); got != messageID {
				t.Fatalf("message_id=%q", got)
			}
			_ = json.NewEncoder(w).Encode(InboxResponse{Messages: []InboxMessage{{MessageID: messageID}}})
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Message(context.Background(), messageID)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 || len(response.Messages) != 1 {
		t.Fatalf("requests=%d response=%+v", requests, response)
	}
}

func TestMessagePreservesParticipantFilteredNotFound(t *testing.T) {
	t.Parallel()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, `{"detail":"Message not found"}`, http.StatusNotFound)
	}))
	defer server.Close()
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Message(context.Background(), "33333333-3333-4333-8333-333333333333")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("error=%v, want API 404", err)
	}
	if requests != 1 {
		t.Fatalf("requests=%d, want no recipient-inbox fallback", requests)
	}
}

func TestMailConversationTargetPrefersAddressForE2EE(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	item := ConversationItem{
		ConversationID:       "conv-1",
		ParticipantDIDs:      []string{"did:aw:self", "did:aw:other"},
		ParticipantAddresses: []string{"alpha.test.local/alice", "beta.test.local/bob"},
	}

	legacy := client.mailConversationItemTarget(item, false)
	if legacy.kind != "did" || legacy.value != "did:aw:other" {
		t.Fatalf("legacy target=(%q,%q), want did/did:aw:other", legacy.kind, legacy.value)
	}

	encrypted := client.mailConversationItemTarget(item, true)
	if encrypted.kind != "address" || encrypted.value != "beta.test.local/bob" {
		t.Fatalf("encrypted target=(%q,%q), want address/beta.test.local/bob", encrypted.kind, encrypted.value)
	}
}

func TestMailConversationTargetUsesLocalDIDForE2EEHistoryLookup(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	item := ConversationItem{
		ConversationID:  "conv-1",
		Participants:    []string{"alice", "bob"},
		ParticipantDIDs: []string{"did:aw:self", "did:key:bob"},
	}

	legacy := client.mailConversationItemTarget(item, false)
	if legacy.kind != "did" || legacy.value != "did:key:bob" {
		t.Fatalf("legacy target=(%q,%q), want did/did:key:bob", legacy.kind, legacy.value)
	}

	encrypted := client.mailConversationItemTarget(item, true)
	if encrypted.kind != "did" || encrypted.value != "did:key:bob" {
		t.Fatalf("encrypted target=(%q,%q), want did/did:key:bob", encrypted.kind, encrypted.value)
	}
}

func TestMailInboxTargetPrefersAddressForE2EE(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	messages := []InboxMessage{{
		ConversationID: "conv-1",
		FromStableID:   "did:aw:self",
		FromDID:        "did:key:self",
		FromAddress:    "alpha.test.local/alice",
		ToStableID:     "did:aw:other",
		ToDID:          "did:key:other",
		ToAddress:      "beta.test.local/bob",
	}}

	legacy := client.mailInboxTarget(messages, false)
	if legacy.kind != "did" || legacy.value != "did:aw:other" {
		t.Fatalf("legacy target=(%q,%q), want did/did:aw:other", legacy.kind, legacy.value)
	}

	encrypted := client.mailInboxTarget(messages, true)
	if encrypted.kind != "address" || encrypted.value != "beta.test.local/bob" {
		t.Fatalf("encrypted target=(%q,%q), want address/beta.test.local/bob", encrypted.kind, encrypted.value)
	}
}

func TestMailInboxTargetPrefersAliasBeforeDIDForE2EE(t *testing.T) {
	t.Parallel()

	client := &Client{
		stableID: "did:aw:self",
		did:      "did:key:self",
		address:  "alpha.test.local/alice",
	}
	messages := []InboxMessage{{
		ConversationID: "conv-1",
		FromAlias:      "alice",
		FromStableID:   "did:aw:self",
		FromDID:        "did:key:self",
		ToAlias:        "bob",
		ToDID:          "did:key:bob",
	}}

	legacy := client.mailInboxTarget(messages, false)
	if legacy.kind != "did" || legacy.value != "did:key:bob" {
		t.Fatalf("legacy target=(%q,%q), want did/did:key:bob", legacy.kind, legacy.value)
	}

	encrypted := client.mailInboxTarget(messages, true)
	if encrypted.kind != "alias" || encrypted.value != "bob" {
		t.Fatalf("encrypted target=(%q,%q), want alias/bob", encrypted.kind, encrypted.value)
	}
}
