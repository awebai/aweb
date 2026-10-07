package awid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Extends the probe-57 encrypted projection fixture to both read paths. The
// envelope authenticates decrypted content, but must also bind the outer IDs.
func TestEncryptedDisplayBinding(t *testing.T) {
	for _, kind := range []string{"mail", "chat"} {
		for _, mode := range []string{"matching", "message_id", "conversation_id", "empty_message_id", "empty_conversation_id", "missing_key", "bad_signature"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				sender := newE2EETestLocalIdentity(t)
				recipient := newE2EETestLocalIdentity(t)
				params := E2EEEncryptMessageParams{Sender: E2EESenderKey{DID: sender.did, EncryptionKey: sender.assertion, SigningKey: sender.priv}, Recipients: []E2EERecipientKey{{DID: recipient.did, EncryptionKey: recipient.assertion}}, Body: "authenticated body", Subject: "authenticated subject", MessageID: "message", ConversationID: "conversation", CreatedAt: time.Now()}
				var envelope *E2EEMessageEnvelope
				var err error
				if kind == "mail" {
					envelope, err = EncryptE2EEMail(params)
				} else {
					envelope, err = EncryptE2EEChat(params)
				}
				if err != nil {
					t.Fatal(err)
				}
				raw := InboxMessage{MessageID: "message", ConversationID: "conversation", ContentMode: ContentModeEncryptedV2, MessageVersion: 2, Encrypted: envelope, Body: "untrusted body", Subject: "untrusted subject", FromDID: "untrusted sender", ToDID: "untrusted recipient"}
				switch mode {
				case "message_id":
					raw.MessageID = "unsigned message"
				case "conversation_id":
					raw.ConversationID = "unsigned conversation"
				case "empty_message_id":
					raw.MessageID = ""
				case "empty_conversation_id":
					raw.ConversationID = ""
				case "bad_signature":
					envelope.ConversationID = "invalid signature"
				}
				c, _ := New("http://unused.invalid")
				c.did = recipient.did
				c.e2eePrivateKey = recipient.xPriv
				c.e2eeEncryptionKey = recipient.assertion
				if mode == "missing_key" {
					c.e2eePrivateKey = nil
				}
				var got InboxMessage
				if kind == "mail" {
					var out *InboxResponse
					out, err = c.normalizeInboxResponse(context.Background(), &InboxResponse{Messages: []InboxMessage{raw}})
					if err == nil {
						got = out.Messages[0]
					}
				} else {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{raw}})
					}))
					defer server.Close()
					chatClient, _ := New(server.URL)
					chatClient.did = c.did
					chatClient.e2eePrivateKey = c.e2eePrivateKey
					chatClient.e2eeEncryptionKey = c.e2eeEncryptionKey
					var out *ChatHistoryResponse
					out, err = chatClient.ChatHistory(context.Background(), ChatHistoryParams{SessionID: "conversation"})
					if err == nil {
						data, _ := json.Marshal(out.Messages[0])
						_ = json.Unmarshal(data, &got)
					}
				}
				if mode == "missing_key" || mode == "bad_signature" {
					if err == nil {
						t.Fatal("cryptographic failure accepted")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if got.MessageID != raw.MessageID || got.ConversationID != raw.ConversationID {
					t.Fatalf("outer IDs overwritten: %+v", got)
				}
				if mode == "matching" {
					wantTo := raw.ToDID
					if kind == "mail" {
						wantTo = recipient.did
					}
					if got.VerificationStatus != Verified || got.Body != params.Body || got.FromDID != sender.did || got.ToDID != wantTo {
						t.Fatalf("authenticated projection lost: %+v", got)
					}
				} else {
					if got.VerificationStatus != Failed || got.Body != raw.Body || got.FromDID != raw.FromDID || got.ToDID != raw.ToDID {
						t.Fatalf("mismatch must fail and preserve raw display: %+v", got)
					}
				}
			})
		}
	}
}
