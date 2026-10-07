package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMailReaderRecipientDisplay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	const stable = "did:aw:reader"
	for _, mode := range []string{"own_key", "own_stable", "other_key", "other_stable", "no_identity", "empty_stable", "null_stable", "number_stable", "other_signed_stable", "null_recipient", "number_recipient", "nonempty_recipient", "empty_sender", "body", "subject", "message_id", "conversation_id", "invalid_signature"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := New("http://unused.invalid")
			c.did = did
			c.stableID = stable
			signed := map[string]any{"type": "mail", "from_did": did, "to": "reader", "to_did": "", "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation"}
			raw := map[string]any{"from_did": did, "to_did": did, "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation"}
			switch mode {
			case "own_stable":
				raw["to_did"] = stable
			case "other_key":
				raw["to_did"] = "did:key:other"
			case "other_stable":
				raw["to_did"] = "did:aw:other"
			case "no_identity":
				c.did = ""
				c.stableID = ""
			case "empty_stable":
				signed["to_stable_id"] = ""
			case "null_stable":
				signed["to_stable_id"] = nil
			case "number_stable":
				signed["to_stable_id"] = 7
			case "other_signed_stable":
				signed["to_stable_id"] = "did:aw:other"
			case "null_recipient":
				signed["to_did"] = nil
			case "number_recipient":
				signed["to_did"] = 7
			case "nonempty_recipient":
				signed["to_did"] = "did:key:other"
			case "empty_sender":
				signed["from_did"] = ""
			case "body", "subject", "message_id", "conversation_id":
				raw[mode] = "tampered"
			}
			payload, _ := json.Marshal(signed)
			raw["signed_payload"] = string(payload)
			raw["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
			if mode == "invalid_signature" {
				raw["signature"] = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
			}
			bytes, _ := json.Marshal(raw)
			var m InboxMessage
			_ = json.Unmarshal(bytes, &m)
			out, err := c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{m}})
			if err != nil {
				t.Fatal(err)
			}
			want := Failed
			if mode == "own_key" || mode == "own_stable" {
				want = Verified
			}
			got := out.Messages[0]
			if got.VerificationStatus != want {
				t.Fatalf("status=%s want=%s", got.VerificationStatus, want)
			}
			if got.ToDID != raw["to_did"] || got.Body != raw["body"] || got.MessageID != raw["message_id"] {
				t.Fatal("raw display changed")
			}
			fields := map[string]string{"type": "mail", "from_did": did, "to_did": raw["to_did"].(string), "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation"}
			if (mode == "own_key" || mode == "own_stable") && signedDisplayMatches(string(payload), fields) {
				t.Fatal("mail-only exception leaked into common chat binding")
			}
		})
	}
}

func TestOwnSentLegacyMailDisplay(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	for _, surface := range []string{"message", "conversation", "inbox"} {
		for _, mode := range []string{"matching", "stable_sender", "unrelated_sender", "unsigned_sender", "body", "recipient_claim", "present_empty_stable", "bad_signature"} {
			t.Run(surface+"/"+mode, func(t *testing.T) {
				signed := map[string]any{"type": "mail", "from_did": did, "to_did": "", "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation"}
				raw := map[string]any{"from_did": did, "to_did": "did:key:other-recipient", "body": "body", "subject": "subject", "message_id": "message", "conversation_id": "conversation"}
				switch mode {
				case "stable_sender":
					signed["from_stable_id"] = "did:aw:sender"
					raw["from_did"] = "did:aw:sender"
				case "unrelated_sender":
					raw["from_did"] = "did:key:other"
				case "unsigned_sender":
					delete(signed, "from_did")
				case "body":
					raw["body"] = "tampered"
				case "recipient_claim":
					signed["to_did"] = "did:key:different-recipient"
				case "present_empty_stable":
					signed["to_stable_id"] = ""
				}
				payload, _ := json.Marshal(signed)
				raw["signed_payload"] = string(payload)
				raw["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, payload))
				if mode == "bad_signature" {
					raw["signature"] = base64.RawStdEncoding.EncodeToString(make([]byte, 64))
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/messages/message" {
						_ = json.NewEncoder(w).Encode(raw)
					} else {
						_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{raw}})
					}
				}))
				defer server.Close()
				c, _ := New(server.URL)
				c.did = did
				c.stableID = "did:aw:sender"
				var out *InboxResponse
				var err error
				switch surface {
				case "message":
					out, err = c.Message(context.Background(), "message")
				case "conversation":
					out, err = c.MailConversation(context.Background(), "conversation", 10)
				case "inbox":
					out, err = c.Inbox(context.Background(), InboxParams{})
				}
				if err != nil {
					t.Fatal(err)
				}
				want := Failed
				if surface != "inbox" && (mode == "matching" || mode == "stable_sender") {
					want = Verified
				}
				if out.Messages[0].VerificationStatus != want {
					t.Fatalf("status=%s want=%s", out.Messages[0].VerificationStatus, want)
				}
				if out.Messages[0].ToDID != raw["to_did"] {
					t.Fatal("unsigned recipient projection changed")
				}
			})
		}
	}
}
