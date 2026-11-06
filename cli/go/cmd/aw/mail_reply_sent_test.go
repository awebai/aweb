package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// aw mail reply answers mail the caller received. A message the caller sent
// is refused with the command that continues its conversation, and nothing is
// sent or acknowledged.
func TestAwMailReplyToASentMessageNamesTheConversationCommand(t *testing.T) {
	t.Parallel()
	conversationID := "77777777-7777-4777-8777-777777777777"
	out, err := runMailReplyAgainstForTest(t, "msg-sent", func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/msg-sent" {
			_ = json.NewEncoder(w).Encode(awid.InboxMessage{
				MessageID:      "msg-sent",
				ConversationID: conversationID,
				FromAddress:    "acme.com/alice",
				ToAddress:      "otherco.example/bob",
				Subject:        "hello",
				Body:           "hi",
				CreatedAt:      "2026-05-02T00:00:00Z",
			})
			return true
		}
		return false
	})
	if err == nil {
		t.Fatalf("reply to a sent message succeeded:\n%s", out)
	}
	want := "message msg-sent is one you sent; aw mail reply answers mail you received. " +
		"To continue its conversation, run `aw mail send --conversation-id " + conversationID + " --body-file <file>`"
	if !strings.Contains(out, want) {
		t.Fatalf("output:\n%s\nwant %s", out, want)
	}
}

func TestAwMailReplyToAnUnknownMessageIsNotFound(t *testing.T) {
	t.Parallel()
	out, err := runMailReplyAgainstForTest(t, "msg-missing", func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/messages/msg-missing" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Message not found"}`))
			return true
		}
		return false
	})
	if err == nil || !strings.Contains(out, "mail message not found: msg-missing") {
		t.Fatalf("err=%v output:\n%s", err, out)
	}
	if strings.Contains(out, "one you sent") {
		t.Fatalf("an unknown message was reported as sent:\n%s", out)
	}
}

// runMailReplyAgainstForTest runs `aw mail reply <messageID>` against a server
// whose inbox has no such message; exact reads go to lookup. Any send or ack
// fails the test.
func runMailReplyAgainstForTest(t *testing.T, messageID string, lookup func(http.ResponseWriter, *http.Request) bool) (string, error) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if lookup(w, r) {
			return
		}
		switch {
		case r.URL.Path == "/v1/messages/inbox":
			if r.URL.Query().Get("message_id") != messageID {
				t.Errorf("message_id query=%q, want %s", r.URL.Query().Get("message_id"), messageID)
			}
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           awid.ComputeDIDKey(pub),
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	run := exec.CommandContext(ctx, bin, "mail", "reply", "--plaintext", messageID, "--body", "reply")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL, "AWID_REGISTRY_URL=http://127.0.0.1:1")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	return string(out), err
}
