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
		case historyPath && r.Method == http.MethodGet:
			f.limits = append(f.limits, r.URL.Query().Get("limit"))
			if f.answer.status != 0 {
				w.WriteHeader(f.answer.status)
				_, _ = w.Write([]byte(f.answer.body))
				return
			}
			rows := []map[string]any{}
			for i := 0; i < f.answer.rows; i++ {
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

// A continuation inherits its conversation's encryption. When the stored rows
// that would show it cannot be read, or the widest readable page is full
// without an encrypted row, the encryption is unknown: a default continuation
// refuses and names the explicit choices instead of sending server-readable
// text into what may be an encrypted conversation.
func TestDefaultContinuationRefusesWhenTheConversationsEncryptionIsUnknown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	f := newContinuationFixture(t, ctx)
	chatSend := []string{"chat", "send", "--session-id", continuationTestSession, "--body", "next"}
	mailSend := []string{"mail", "send", "--conversation-id", continuationTestConversation, "--body", "next"}

	for _, tc := range []struct {
		name      string
		args      []string
		answer    historyAnswer
		wantLimit string
	}{
		{name: "chat history denied to a send-scoped grant", args: chatSend, answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}, wantLimit: "2000"},
		{name: "chat session hidden", args: chatSend, answer: historyAnswer{status: http.StatusNotFound, body: `{"detail":"Not found"}`}, wantLimit: "2000"},
		{name: "chat history page full without an encrypted row", args: chatSend, answer: historyAnswer{rows: 2000}, wantLimit: "2000"},
		{name: "mail conversation denied", args: mailSend, answer: historyAnswer{status: http.StatusForbidden, body: `{"detail":"Forbidden"}`}, wantLimit: "500"},
		{name: "mail conversation hidden", args: mailSend, answer: historyAnswer{status: http.StatusNotFound, body: `{"detail":"Not found"}`}, wantLimit: "500"},
		{name: "mail conversation page full without an encrypted row", args: mailSend, answer: historyAnswer{rows: 500}, wantLimit: "500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := f.run(ctx, tc.answer, tc.args...)
			if err == nil {
				t.Fatalf("the default continuation was sent although the encryption is unknown: %s", out)
			}
			if !strings.Contains(out, "--e2ee") || !strings.Contains(out, "--plaintext") {
				t.Fatalf("the refusal does not name the explicit choices: %s", out)
			}
			if sent := f.sent(); len(sent) != 0 {
				t.Fatalf("a message was posted: %#v", sent)
			}
			if limits := f.readLimits(); len(limits) != 1 || limits[0] != tc.wantLimit {
				t.Fatalf("history reads with limits %v, want one read with limit %s", limits, tc.wantLimit)
			}
		})
	}

	// Controls: a readable history that is shorter than the page is a known
	// plaintext conversation; an explicit --plaintext needs no answer; a server
	// that predates the mail conversation route (server-v1.19.0) also predates
	// end-to-end encryption (server-v1.26.0), so its conversations are plaintext.
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
			if len(sent) != 1 {
				t.Fatalf("posted %d messages, want 1: %s", len(sent), out)
			}
			if sent[0]["encrypted_envelope"] != nil || sent[0]["body"] != "next" {
				t.Fatalf("the continuation was not sent as plaintext: %#v", sent[0])
			}
		})
	}
}
