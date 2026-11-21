package awid

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// ContinuationEncryption is the one continuation rule for chat and mail:
// --e2ee encrypts, --plaintext sends plaintext (with a notice into an
// encrypted conversation), and otherwise the conversation's encryption
// carries over, an unknown one refusing.
func TestContinuationEncryptionIsTheOneContinuationRule(t *testing.T) {
	unknown := ConversationEncryptionReading{State: ConversationEncryptionUnknown, Reason: "the server does not let this identity read the conversation (HTTP 403)"}
	encrypted := ConversationEncryptionReading{State: ConversationEncrypted}
	plaintext := ConversationEncryptionReading{State: ConversationPlaintext}
	for _, tc := range []struct {
		name          string
		conversation  ConversationEncryptionReading
		choice        E2EEChoice
		wantEncrypt   bool
		wantInherited bool
		wantNotice    string
		wantUnknown   bool
	}{
		{name: "required into plaintext", conversation: plaintext, choice: E2EERequired, wantEncrypt: true},
		{name: "required into unknown", conversation: unknown, choice: E2EERequired, wantEncrypt: true},
		{name: "plaintext into encrypted", conversation: encrypted, choice: E2EEPlaintext, wantNotice: PlaintextIntoEncryptedNotice},
		{name: "plaintext into unknown", conversation: unknown, choice: E2EEPlaintext},
		{name: "plaintext into plaintext", conversation: plaintext, choice: E2EEPlaintext},
		{name: "inherit encrypted", conversation: encrypted, choice: E2EEInherit, wantEncrypt: true, wantInherited: true},
		{name: "inherit plaintext", conversation: plaintext, choice: E2EEInherit},
		{name: "inherit unknown", conversation: unknown, choice: E2EEInherit, wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ContinuationEncryption(tc.conversation, tc.choice)
			var refusal *UnknownConversationEncryptionError
			if tc.wantUnknown {
				if !errors.As(err, &refusal) || refusal.Reason != tc.conversation.Reason {
					t.Fatalf("err=%v, want the unknown-encryption refusal with its reason", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if got.Encrypt != tc.wantEncrypt || got.Inherited != tc.wantInherited || got.Notice != tc.wantNotice {
				t.Fatalf("got %+v, want encrypt=%v inherited=%v notice=%q", got, tc.wantEncrypt, tc.wantInherited, tc.wantNotice)
			}
		})
	}
}

// A successful answer establishes a plaintext conversation only when it
// carries the message list both routes return: an answer without one is
// unknown, an empty list is plaintext. Mail asks for the latest page, so a
// recent encrypted row is seen in a conversation longer than the page.
func TestConversationEncryptionNeedsTheMessageListAndTheLatestPage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mail      bool
		body      string
		wantState ConversationEncryption
	}{
		{name: "chat answer without a message list", body: `{}`, wantState: ConversationEncryptionUnknown},
		{name: "chat answer with a null list", body: `{"messages":null}`, wantState: ConversationEncryptionUnknown},
		{name: "chat empty list", body: `{"messages":[]}`, wantState: ConversationPlaintext},
		{name: "mail answer without a message list", mail: true, body: `{"has_more":false}`, wantState: ConversationEncryptionUnknown},
		{name: "mail empty list", mail: true, body: `{"messages":[],"has_more":false}`, wantState: ConversationPlaintext},
		{name: "mail latest page shows a recent encrypted row", mail: true, body: `{"messages":[{"content_mode":"encrypted_v2","message_version":2}],"has_more":true}`, wantState: ConversationEncrypted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query url.Values
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query = r.URL.Query()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var reading ConversationEncryptionReading
			if tc.mail {
				reading, err = client.MailConversationEncryption(context.Background(), "conversation-1")
			} else {
				reading, err = client.ChatSessionEncryption(context.Background(), "session-1")
			}
			if err != nil {
				t.Fatal(err)
			}
			if reading.State != tc.wantState {
				t.Fatalf("state=%s reason=%q, want %s", reading.State, reading.Reason, tc.wantState)
			}
			if tc.wantState == ConversationEncryptionUnknown && reading.Reason == "" {
				t.Fatal("an unknown reading carries no reason")
			}
			if tc.mail && (query.Get("order") != "desc" || query.Get("limit") != "500") {
				t.Fatalf("mail read query=%v, want the latest 500 (order=desc)", query)
			}
		})
	}
}
