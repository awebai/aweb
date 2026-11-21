package awid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ContinuationEncryption is the one continuation rule for chat and mail:
// --e2ee encrypts, --plaintext sends plaintext (with a notice into an
// encrypted conversation), and otherwise an encrypted conversation is
// continued encrypted by a sender that can encrypt. An unknown conversation,
// or an encrypted one whose sender cannot encrypt, is sent in plaintext with
// a notice that says why.
func TestContinuationEncryptionIsTheOneContinuationRule(t *testing.T) {
	unknown := ConversationEncryptionReading{State: ConversationEncryptionUnknown, Reason: "the server does not let this identity read the conversation (HTTP 403)"}
	encrypted := ConversationEncryptionReading{State: ConversationEncrypted}
	plaintext := ConversationEncryptionReading{State: ConversationPlaintext}
	const noKey = "this identity has no local encryption key"
	for _, tc := range []struct {
		name          string
		conversation  ConversationEncryptionReading
		choice        E2EEChoice
		cannotEncrypt string
		wantEncrypt   bool
		wantInherited bool
		wantNotice    []string
	}{
		{name: "required into plaintext", conversation: plaintext, choice: E2EERequired, wantEncrypt: true},
		{name: "required into unknown", conversation: unknown, choice: E2EERequired, wantEncrypt: true},
		{name: "required without a key", conversation: encrypted, choice: E2EERequired, cannotEncrypt: noKey, wantEncrypt: true},
		{name: "plaintext into encrypted", conversation: encrypted, choice: E2EEPlaintext, wantNotice: []string{PlaintextIntoEncryptedNotice}},
		{name: "plaintext into unknown", conversation: unknown, choice: E2EEPlaintext},
		{name: "plaintext into plaintext", conversation: plaintext, choice: E2EEPlaintext},
		{name: "inherit encrypted", conversation: encrypted, choice: E2EEInherit, wantEncrypt: true, wantInherited: true},
		{name: "inherit encrypted without a key", conversation: encrypted, choice: E2EEInherit, cannotEncrypt: noKey, wantNotice: []string{"end-to-end encrypted", noKey, plaintextFallbackNotice, "--e2ee"}},
		{name: "inherit plaintext", conversation: plaintext, choice: E2EEInherit},
		{name: "inherit plaintext without a key", conversation: plaintext, choice: E2EEInherit, cannotEncrypt: noKey},
		{name: "inherit unknown", conversation: unknown, choice: E2EEInherit, wantNotice: []string{"cannot tell", unknown.Reason, plaintextFallbackNotice, "--e2ee"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ContinuationEncryption(tc.conversation, tc.choice, tc.cannotEncrypt)
			if got.Encrypt != tc.wantEncrypt || got.Inherited != tc.wantInherited {
				t.Fatalf("got %+v, want encrypt=%v inherited=%v", got, tc.wantEncrypt, tc.wantInherited)
			}
			if (got.Notice == "") != (len(tc.wantNotice) == 0) {
				t.Fatalf("notice %q, want one saying %q", got.Notice, tc.wantNotice)
			}
			for _, want := range tc.wantNotice {
				if !strings.Contains(got.Notice, want) {
					t.Fatalf("notice %q does not say %q", got.Notice, want)
				}
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

// A read that fails, by an HTTP error or a server that does not answer, is an
// unknown reading with its reason, not an error: the caller decides what an
// unknown conversation means. Only a cancelled context is an error.
func TestConversationEncryptionReadFailureIsUnknown(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	defer failing.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	for _, tc := range []struct {
		name, url string
	}{
		{name: "server error", url: failing.URL},
		{name: "server gone", url: goneURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := New(tc.url)
			if err != nil {
				t.Fatal(err)
			}
			reading, err := client.MailConversationEncryption(context.Background(), "conversation-1")
			if err != nil {
				t.Fatalf("err=%v, want an unknown reading", err)
			}
			if reading.State != ConversationEncryptionUnknown || !strings.Contains(reading.Reason, "reading the conversation failed") {
				t.Fatalf("reading=%+v, want unknown with the failure", reading)
			}
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	client, err := New(failing.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ChatSessionEncryption(cancelled, "session-1"); err == nil {
		t.Fatal("a cancelled read returned no error")
	}
}
