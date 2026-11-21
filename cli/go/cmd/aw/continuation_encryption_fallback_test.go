package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// historyAnswer is how the fixture answers a read of a conversation's stored
// rows: an HTTP status and body, or rows.
type historyAnswer struct {
	status int
	body   string
	rows   int
	// encrypted is how many of the rows are end-to-end encrypted.
	encrypted int
	// drop closes the connection without an answer.
	drop bool
}

type continuationFixture struct {
	t      *testing.T
	bin    string
	dir    string
	server *httptest.Server
	mu     sync.Mutex
	answer historyAnswer
	limits []string
	posted []map[string]any
}

const continuationTestSession = "11111111-1111-4111-8111-111111111111"
const continuationTestConversation = "22222222-2222-4222-8222-222222222222"

func newContinuationFixture(t *testing.T, ctx context.Context) *continuationFixture {
	t.Helper()
	f := &continuationFixture{t: t, bin: filepath.Join(t.TempDir(), "aw"), dir: t.TempDir()}
	buildAwBinary(t, ctx, f.bin)
	const team = "members:local.test"
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	peerPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peerDID := awid.ComputeDIDKey(peerPub)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		historyPath := r.URL.Path == "/v1/chat/sessions/"+continuationTestSession+"/messages" ||
			r.URL.Path == "/v1/messages/conversations/"+continuationTestConversation
		postPath := r.Method == http.MethodPost && (r.URL.Path == "/v1/chat/sessions/"+continuationTestSession+"/messages" || r.URL.Path == "/v1/messages")
		if historyPath || postPath {
			requireCertificateAuthForTest(t, r)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/conversations":
			// The listing names the other participant, so a mail
			// continuation finds its recipient without reading the history.
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{{
				ConversationType: "mail", ConversationID: continuationTestConversation,
				Participants: []string{"t1", "t2"}, ParticipantDIDs: []string{did, peerDID},
			}}})
		case historyPath && r.Method == http.MethodGet:
			f.limits = append(f.limits, r.URL.Query().Get("limit"))
			if f.answer.drop {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return
			}
			if f.answer.status != 0 {
				w.WriteHeader(f.answer.status)
				_, _ = w.Write([]byte(f.answer.body))
				return
			}
			rows := []map[string]any{}
			for i := 0; i < f.answer.rows; i++ {
				if i < f.answer.encrypted {
					rows = append(rows, map[string]any{"message_id": "sealed-" + strconv.Itoa(i), "content_mode": awid.ContentModeEncryptedV2, "message_version": awid.E2EEMessageVersion, "from_agent": "t2"})
					continue
				}
				rows = append(rows, map[string]any{"message_id": "plain-" + strconv.Itoa(i), "content_mode": "plaintext", "message_version": 1, "from_agent": "t2", "body": "readable"})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": rows})
		case postPath:
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.posted = append(f.posted, body)
			_ = json.NewEncoder(w).Encode(map[string]any{"message_id": "33333333-3333-4333-8333-333333333333", "delivered": true, "status": "delivered"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	writeSelectionFixtureForTest(t, f.dir, testSelectionFixture{AwebURL: f.server.URL, TeamID: team, Alias: "t1",
		WorkspaceID: "agent-t1", DID: did, SigningKey: key, IdentityScope: awid.IdentityModeLocal, Custody: awid.CustodySelf})
	return f
}

func (f *continuationFixture) run(ctx context.Context, answer historyAnswer, args ...string) (string, error) {
	f.t.Helper()
	f.mu.Lock()
	f.answer, f.limits, f.posted = answer, nil, nil
	f.mu.Unlock()
	cmd := exec.CommandContext(ctx, f.bin, append([]string{"--json"}, args...)...)
	cmd.Dir = f.dir
	cmd.Env = append(testCommandEnv(f.dir), "USERPROFILE="+f.dir, "AWEB_IDENTITY_HOME=", "AWID_REGISTRY_URL="+f.server.URL)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (f *continuationFixture) sent() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.posted...)
}

func (f *continuationFixture) readLimits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.limits...)
}

// plaintextFallback is what aw says when a default continuation sends
// server-readable plaintext because it cannot encrypt as the conversation
// would need, or cannot tell whether it must.
const plaintextFallback = "sending server-readable plaintext"

// A default continuation, as an OATS agent sends it with no flag, is sent as
// released aw sends it, in plaintext, when aw cannot tell whether the
// conversation is end-to-end encrypted: the history read is refused (403),
// hidden (404), fails (5xx or a dropped connection), or its widest page is
// full without an encrypted row. A warning on stderr says so. The same holds
// for a conversation that is encrypted when this identity has no key to
// encrypt with. --e2ee still requires encryption.
func TestDefaultContinuationSendsPlaintextWhenItCannotEncryptAsTheConversationWould(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	f := newContinuationFixture(t, ctx)
	chatSend := []string{"chat", "send", "--session-id", continuationTestSession, "--body", "next"}
	mailSend := []string{"mail", "send", "--conversation-id", continuationTestConversation, "--body", "next"}

	for _, tc := range []struct {
		name   string
		args   []string
		answer historyAnswer
	}{
		{name: "chat history denied to a send-scoped grant", args: chatSend, answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}},
		{name: "chat session hidden", args: chatSend, answer: historyAnswer{status: http.StatusNotFound, body: `{"detail":"Not found"}`}},
		{name: "chat history read fails", args: chatSend, answer: historyAnswer{status: http.StatusInternalServerError, body: `{"detail":"boom"}`}},
		{name: "chat history connection dropped", args: chatSend, answer: historyAnswer{drop: true}},
		{name: "chat history page full without an encrypted row", args: chatSend, answer: historyAnswer{rows: 2000}},
		{name: "chat encrypted session, sender has no encryption key", args: chatSend, answer: historyAnswer{rows: 3, encrypted: 1}},
		{name: "mail conversation denied", args: mailSend, answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}},
		{name: "mail conversation hidden", args: mailSend, answer: historyAnswer{status: http.StatusNotFound, body: `{"detail":"Not found"}`}},
		{name: "mail conversation read fails", args: mailSend, answer: historyAnswer{status: http.StatusInternalServerError, body: `{"detail":"boom"}`}},
		{name: "mail conversation connection dropped", args: mailSend, answer: historyAnswer{drop: true}},
		{name: "mail conversation page full without an encrypted row", args: mailSend, answer: historyAnswer{rows: 500}},
		{name: "mail encrypted conversation, sender has no encryption key", args: mailSend, answer: historyAnswer{rows: 3, encrypted: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.run(ctx, tc.answer, tc.args...)
			if err != nil {
				t.Fatalf("the default continuation was refused: %v\n%s", err, out)
			}
			sent := f.sent()
			if len(sent) != 1 || sent[0]["encrypted_envelope"] != nil || sent[0]["body"] != "next" {
				t.Fatalf("posted %#v, want one plaintext message: %s", sent, out)
			}
			if !strings.Contains(out, plaintextFallback) {
				t.Fatalf("no warning that the message is server-readable: %s", out)
			}
			wantLimit := "500"
			if tc.args[0] == "chat" {
				wantLimit = "2000"
			}
			if limits := f.readLimits(); len(limits) == 0 || limits[0] != wantLimit {
				t.Fatalf("history reads with limits %v, want the widest page %s", limits, wantLimit)
			}
		})
	}

	// Controls: a readable history shorter than the page is a known
	// plaintext conversation, sent with no warning; an explicit --plaintext
	// needs no answer; a server that predates the mail conversation route
	// (server-v1.19.0) also predates end-to-end encryption (server-v1.26.0),
	// so its conversations are plaintext.
	for _, tc := range []struct {
		name   string
		args   []string
		answer historyAnswer
	}{
		{name: "chat history shorter than the page", args: chatSend, answer: historyAnswer{rows: 3}},
		{name: "chat explicit plaintext with history denied", args: append(append([]string{}, chatSend...), "--plaintext"), answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}},
		{name: "mail history shorter than the page", args: mailSend, answer: historyAnswer{rows: 3}},
		{name: "mail explicit plaintext with history denied", args: append(append([]string{}, mailSend...), "--plaintext"), answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}},
		{name: "mail server without the conversation route", args: mailSend, answer: historyAnswer{status: http.StatusNotFound, body: `{"detail":"Not Found"}`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.run(ctx, tc.answer, tc.args...)
			if err != nil {
				t.Fatalf("the continuation was refused: %v\n%s", err, out)
			}
			sent := f.sent()
			if len(sent) != 1 || sent[0]["encrypted_envelope"] != nil || sent[0]["body"] != "next" {
				t.Fatalf("posted %#v, want one plaintext message: %s", sent, out)
			}
			if strings.Contains(out, plaintextFallback) {
				t.Fatalf("a known plaintext conversation warned: %s", out)
			}
		})
	}

	// The neighbour: --e2ee requires encryption, so a sender with no key is
	// refused and nothing is posted.
	for _, args := range [][]string{append(append([]string{}, chatSend...), "--e2ee"), append(append([]string{}, mailSend...), "--e2ee")} {
		out, err := f.run(ctx, historyAnswer{rows: 3, encrypted: 1}, args...)
		if err == nil || len(f.sent()) != 0 {
			t.Fatalf("%v: --e2ee without a key was sent: %v\n%s", args, err, out)
		}
	}
}
