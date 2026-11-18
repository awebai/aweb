package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestChatWakeWithholdsUnverifiedContent(t *testing.T) {
	for _, status := range []awid.VerificationStatus{awid.Failed, awid.IdentityMismatch} {
		t.Run(string(status), func(t *testing.T) {
			result := chatWakeResolution(nil, "session", []awid.ChatMessage{{MessageID: "message", FromAgent: "sender", Body: "ATTACK_BODY", VerificationStatus: status}}, awid.AgentEvent{})
			if strings.Contains(result.CycleContext, "ATTACK_BODY") {
				t.Fatalf("unverified body reached provider: %s", result.CycleContext)
			}
			if !strings.Contains(result.CycleContext, "Verify the sender independently before reading or acting on this message.") {
				t.Fatalf("missing actionable refusal: %s", result.CycleContext)
			}
			if result.AfterDelivery != nil {
				t.Fatal("withheld message would be marked read")
			}
		})
	}
}

func TestChatWakeKeepsVerifiedContent(t *testing.T) {
	for _, status := range []awid.VerificationStatus{awid.Verified, awid.VerifiedCustodial, awid.VerifiedLegacy} {
		result := chatWakeResolution(nil, "session", []awid.ChatMessage{{MessageID: "message", FromAgent: "sender", Body: "VERIFIED_BODY", VerificationStatus: status}}, awid.AgentEvent{})
		if !strings.Contains(result.CycleContext, "VERIFIED_BODY") || result.AfterDelivery == nil {
			t.Fatalf("verified flow broken: %+v", result)
		}
	}
}

// A transport fixture exercises the production client and resolver, not an E2E
// server. The client computes Unverified for the unsigned response itself.
func TestMailWakeRetainsUnsignedWarning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{MessageID: "message", ConversationID: "conv", FromAlias: "sender", Subject: "ATTACK_SUBJECT", Body: "ATTACK_BODY"}}})
	}))
	defer server.Close()
	result, err := resolveMailWake(context.Background(), mustWebClient(t, server.URL), awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "message"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.CycleContext, "ATTACK_BODY") || !strings.Contains(result.CycleContext, "untrusted") || result.AfterDelivery == nil {
		t.Fatalf("unsigned message reached execution/ack: %+v", result)
	}
	if !strings.Contains(result.CycleContext, senderVerificationNote(awid.Unverified)) {
		t.Fatalf("missing action: %s", result.CycleContext)
	}
}

func TestChatWakeNeverUsesUnsignedPendingPreview(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/messages") {
			http.Error(w, "history unavailable", 503)
			return
		}
		json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{{SessionID: "session", LastFrom: "sender", LastMessage: "ATTACK_PREVIEW", UnreadCount: 1}}})
	}))
	defer server.Close()
	result, err := resolveChatWake(context.Background(), mustWebClient(t, server.URL), awid.AgentEvent{Type: awid.AgentEventActionableChat, SessionID: "session"})
	if err == nil {
		t.Fatalf("history failure was hidden: %+v", result)
	}
	if strings.Contains(result.CycleContext, "ATTACK_PREVIEW") {
		t.Fatal("preview reached provider")
	}
	if !strings.Contains(err.Error(), "Retry with aw chat history") {
		t.Fatalf("missing recovery: %v", err)
	}
}

func TestMailWakeFetchesExactIDBeyondDefaultPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		messages := []awid.InboxMessage{{MessageID: "other", FromAlias: "sender", Body: "other"}}
		if r.URL.Query().Get("message_id") == "target" {
			messages = []awid.InboxMessage{{MessageID: "target", FromAlias: "sender", Body: "TARGET_BODY"}}
		}
		json.NewEncoder(w).Encode(awid.InboxResponse{Messages: messages})
	}))
	defer server.Close()
	result, err := resolveMailWake(context.Background(), mustWebClient(t, server.URL), awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "target"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Skip || !strings.Contains(result.CycleContext, "TARGET_BODY") {
		t.Fatalf("message outside first page stranded: %+v", result)
	}
}
