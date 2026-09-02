package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// The Gas City exec-provider contract test. It ports the SHAPE of gascity's
// own provider conformance suite (internal/mail/mailtest/conformance.go driven
// through internal/mail/exec, as internal/mail/exec/mcp_conformance_test.go
// does for the reference contrib script) rather than that suite's curl mock:
// the mock belongs to mcp_agent_mail, the shape belongs to the protocol.
//
// What is ported is the caller: gcExecProvider below reimplements gascity's
// exec.Provider.run() semantics exactly as verified at
// gastownhall/gascity @ c96e54a3ab890ca984755b7fc5b5290cba5122d5 —
//
//	cmd := exec.CommandContext(ctx, p.script, args...)   // args, JSON on stdin
//	cmd.Stdin = bytes.NewReader(stdinData)               // never the caller's
//	exit 2                       -> success with EMPTY output
//	any other non-zero exit      -> error wrapping stderr
//	stdout                       -> TrimRight("\n"), then JSON-decoded
//
// — and drives the REAL production `aw` binary through it against a local
// aweb server. Anything gc would do to this provider, this test does.

// gcExecMessage mirrors gascity's mail.Message (internal/mail/mail.go). The
// decode is the contract: gc will fail the whole operation if our stdout does
// not fit this shape.
type gcExecMessage struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Subject   string    `json:"subject"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	Read      bool      `json:"read"`
	ThreadID  string    `json:"thread_id,omitempty"`
	ReplyTo   string    `json:"reply_to,omitempty"`
	Priority  int       `json:"priority,omitempty"`
	CC        []string  `json:"cc,omitempty"`
	Rig       string    `json:"rig,omitempty"`
}

type gcExecCount struct {
	Total  int `json:"total"`
	Unread int `json:"unread"`
}

// gcExecProvider is gascity's exec.Provider, reduced to the parts that define
// the contract.
type gcExecProvider struct {
	t      *testing.T
	ctx    context.Context
	script string
	dir    string
	env    []string
}

// run is exec.Provider.run, semantics preserved including the exit-2 rule.
func (p *gcExecProvider) run(stdinData []byte, args ...string) (string, error) {
	p.t.Helper()
	cmd := exec.CommandContext(p.ctx, p.script, args...)
	cmd.Dir = p.dir
	cmd.Env = p.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = bytes.NewReader(stdinData)

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			// gc's forward-compatibility rule: unknown operation, success.
			return "", nil
		}
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return "", errors.New(message)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func (p *gcExecProvider) message(op string, stdin []byte, args ...string) gcExecMessage {
	p.t.Helper()
	out, err := p.run(stdin, append([]string{op}, args...)...)
	if err != nil {
		p.t.Fatalf("%s %v: %v", op, args, err)
	}
	var m gcExecMessage
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		p.t.Fatalf("%s %v: stdout is not a gc mail.Message: %v\nstdout=%q", op, args, err, out)
	}
	return m
}

func (p *gcExecProvider) messages(op string, args ...string) []gcExecMessage {
	p.t.Helper()
	out, err := p.run(nil, append([]string{op}, args...)...)
	if err != nil {
		p.t.Fatalf("%s %v: %v", op, args, err)
	}
	if out == "" {
		return nil
	}
	var msgs []gcExecMessage
	if err := json.Unmarshal([]byte(out), &msgs); err != nil {
		p.t.Fatalf("%s %v: stdout is not a gc []mail.Message: %v\nstdout=%q", op, args, err, out)
	}
	return msgs
}

func gcExecSendInput(from, subject, body string) []byte {
	// exec/json.go sendInput and replyInput are the same three fields.
	encoded, _ := json.Marshal(map[string]string{"from": from, "subject": subject, "body": body})
	return encoded
}

// TestGCMailExecProviderContract drives `aw gc-mail` exactly as Gas City's
// exec provider drives a mail script, against a local aweb server.
func TestGCMailExecProviderContract(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	recipientPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)

	const (
		conversationID = "44444444-4444-4444-8444-444444444444"
		inboundID      = "33333333-3333-4333-8333-333333333333"
		sentID         = "55555555-5555-4555-8555-555555555555"
	)
	inbound := awid.InboxMessage{
		MessageID:      inboundID,
		ConversationID: conversationID,
		Subject:        "Water levels",
		Body:           "the well is low",
		FromAddress:    "acme.example/mayor",
		FromAlias:      "mayor",
		FromDID:        recipientDID,
		ToDID:          did,
		CreatedAt:      "2026-09-02T11:43:10Z",
		Priority:       awid.PriorityNormal,
	}

	type sentRequest struct {
		ToAddress      string `json:"to_address"`
		ConversationID string `json:"conversation_id"`
		Subject        string `json:"subject"`
		Body           string `json:"body"`
		Priority       string `json:"priority"`
	}
	var sends []sentRequest
	var userAgents []string
	acked := map[string]int{}

	server := newLocalHTTPServerWithURL(t, func(serverURL string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ua := r.Header.Get("User-Agent"); ua != "" {
				userAgents = append(userAgents, ua)
			}
			switch {
			case r.URL.Path == "/v1/messages/"+inboundID && r.Method == http.MethodGet:
				_ = json.NewEncoder(w).Encode(inbound)
			case strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
				id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/messages/"), "/ack")
				if id != inboundID {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				acked[id]++
				now := "2026-09-02T12:00:00Z"
				inbound.ReadAt = &now
				_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: id, AcknowledgedAt: now})
			case strings.HasPrefix(r.URL.Path, "/v1/messages/") && r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/conversations/") && r.URL.Path != "/v1/messages/inbox":
				// Any other exact-message read is a miss.
				http.Error(w, "not found", http.StatusNotFound)
			case r.URL.Path == "/v1/messages/conversations/"+conversationID:
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{inbound}})
			case strings.HasPrefix(r.URL.Path, "/v1/messages/conversations/"):
				http.Error(w, "not found", http.StatusNotFound)
			case r.URL.Path == "/v1/messages/inbox":
				if r.URL.Query().Get("unread_only") == "true" && inbound.ReadAt != nil {
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
					return
				}
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{inbound}})
			case r.URL.Path == "/v1/conversations":
				_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
			case r.URL.Path == "/v1/namespaces/acme.example/addresses/mayor":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"address_id":      "addr-mayor",
					"domain":          "acme.example",
					"name":            "mayor",
					"did_aw":          "did:aw:mayor",
					"current_did_key": recipientDID,
					"reachability":    "public",
					"created_at":      "2026-09-02T00:00:00Z",
					"delivery":        map[string]any{"origin": serverURL, "source": "namespace"},
				})
			case r.URL.Path == "/v1/did/did:aw:mayor/key":
				_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": "did:aw:mayor", "current_did_key": recipientDID})
			case r.URL.Path == "/v1/messages" && r.Method == http.MethodPost:
				var got sentRequest
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
					t.Errorf("decode send: %v", err)
				}
				sends = append(sends, got)
				_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{
					MessageID:      sentID,
					ConversationID: conversationID,
					Status:         "delivered",
					DeliveredAt:    "2026-09-02T12:00:00Z",
				})
			case r.URL.Path == "/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected path %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected", http.StatusNotFound)
			}
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	city, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(city, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, city, awconfig.WorktreeIdentity{
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		CreatedAt:     "2026-09-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(city, ".aw", "signing.key"), priv); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(city, ".gc"), 0o700); err != nil {
		t.Fatal(err)
	}
	mapContent := "[addresses]\n\"myrig/mayor\" = \"acme.example/mayor\"\n\"human\" = \"acme.example/mayor\"\n"
	if err := os.WriteFile(filepath.Join(city, ".gc", "aweb-mail.toml"), []byte(mapContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// The provider is invoked the way GC_MAIL=exec:<script> invokes it: one
	// process per operation, positional args, JSON on stdin, cwd wherever gc
	// happens to be.
	launcher := filepath.Join(city, "aw-gc-mail")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nexec "+bin+" gc-mail \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p := &gcExecProvider{
		t:      t,
		ctx:    ctx,
		script: launcher,
		dir:    city,
		env:    append(testCommandEnv(city), "AWEB_URL="+server.URL, "GC_CITY="+city),
	}

	// --- ensure-running: called once before anything, result discarded ------
	if out, err := p.run(nil, "ensure-running"); err != nil || out != "" {
		t.Errorf("ensure-running: out=%q err=%v; it must succeed silently", out, err)
	}

	// --- send <to>, JSON in, gc mail.Message out ----------------------------
	sent := p.message("send", gcExecSendInput("mayor", "Patrol check", "check patrol status"), "myrig/mayor")
	if len(sends) != 1 {
		t.Fatalf("send count=%d", len(sends))
	}
	if sends[0].ToAddress != "acme.example/mayor" || sends[0].Subject != "Patrol check" || sends[0].Body != "check patrol status" {
		t.Errorf("send request %+v", sends[0])
	}
	if sent.ID != sentID || sent.ThreadID != conversationID {
		t.Errorf("send result %+v", sent)
	}
	// Disclosure: the returned "to" is the RESOLVED aweb address, which is
	// what `gc mail send --json` and `gc mail reply` show the operator.
	if sent.To != "acme.example/mayor" {
		t.Errorf("send result.to = %q, want the resolved address (the only disclosure channel the exec protocol leaves)", sent.To)
	}
	if sent.CreatedAt.IsZero() {
		t.Error("send result created_at did not decode into a time.Time")
	}

	// An empty subject is legal on the gc side (`gc mail send <to> "body"`),
	// and becomes the body's first line rather than an empty aweb subject.
	p.message("send", gcExecSendInput("mayor", "", "the well is low\nmore detail"), "myrig/mayor")
	if got := sends[len(sends)-1].Subject; got != "the well is low" {
		t.Errorf("derived subject = %q", got)
	}

	// --- inbox / check: read-only unread listings ---------------------------
	for _, op := range []string{"inbox", "check"} {
		msgs := p.messages(op, "mayor")
		if len(msgs) != 1 || msgs[0].ID != inboundID {
			t.Fatalf("%s = %+v", op, msgs)
		}
		if msgs[0].Read {
			t.Errorf("%s reported an unread message as read", op)
		}
		if msgs[0].From != "acme.example/mayor" {
			t.Errorf("%s from = %q, want the verified address", op, msgs[0].From)
		}
	}
	if acked[inboundID] != 0 {
		t.Errorf("inbox/check acknowledged %d message(s); both must be read-only", acked[inboundID])
	}

	// --- count --------------------------------------------------------------
	out, err := p.run(nil, "count", "mayor")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	var counted gcExecCount
	if err := json.Unmarshal([]byte(out), &counted); err != nil {
		t.Fatalf("count stdout is not gc's countOutput: %v\nstdout=%q", err, out)
	}
	if counted.Total != 1 || counted.Unread != 1 {
		t.Errorf("count = %+v, want {1 1}", counted)
	}

	// --- get: no read-state change ------------------------------------------
	got := p.message("get", nil, inboundID)
	if got.ID != inboundID || got.Read {
		t.Errorf("get = %+v", got)
	}
	if acked[inboundID] != 0 {
		t.Error("get acknowledged the message; gc's Get must not mark read")
	}

	// --- thread: by conversation id AND by any message id in it -------------
	for _, id := range []string{conversationID, inboundID} {
		thread := p.messages("thread", id)
		if len(thread) != 1 || thread[0].ID != inboundID {
			t.Errorf("thread %s = %+v", id, thread)
		}
	}

	// --- read: fetch and mark read ------------------------------------------
	read := p.message("read", nil, inboundID)
	if read.ID != inboundID || !read.Read {
		t.Errorf("read = %+v; reading is what marks read here", read)
	}
	if acked[inboundID] != 1 {
		t.Errorf("read acknowledged %d times, want 1", acked[inboundID])
	}
	if msgs := p.messages("inbox", "mayor"); len(msgs) != 0 {
		t.Errorf("inbox after read = %+v, want empty", msgs)
	}
	// `all` still shows it: read is not removal.
	if msgs := p.messages("all", "mayor"); len(msgs) != 1 || !msgs[0].Read {
		t.Errorf("all after read = %+v", msgs)
	}

	// --- reply: continues the conversation, no recipient named --------------
	replied := p.message("reply", gcExecSendInput("mayor", "", "on it"), inboundID)
	last := sends[len(sends)-1]
	if last.ConversationID != conversationID || last.ToAddress != "" {
		t.Errorf("reply request %+v; a continuation routes by conversation only", last)
	}
	if last.Subject != "Re: Water levels" {
		t.Errorf("reply subject = %q", last.Subject)
	}
	if replied.To != "acme.example/mayor" {
		t.Errorf("reply result.to = %q, want the conversation counterparty (gc prints reply.To)", replied.To)
	}

	// --- mark-read: no output, and a miss carries gc's not-found marker -----
	if out, err := p.run(nil, "mark-read", inboundID); err != nil || out != "" {
		t.Errorf("mark-read: out=%q err=%v", out, err)
	}
	if _, err := p.run(nil, "read", "99999999-9999-4999-8999-999999999999"); err == nil {
		t.Error("read of a missing message must fail")
	} else if !strings.Contains(err.Error(), "gc-mail-error:not-found") {
		t.Errorf("read miss = %v; gc maps ErrNotFound off this exact stderr marker", err)
	}

	// --- refusals: honest errors, never gc's silent exit-2 success ----------
	for _, refusal := range []struct{ op, want string }{
		{"mark-unread", "no way to clear read state"},
		{"archive", "cannot be removed on request"},
		{"delete", "cannot be removed on request"},
	} {
		out, err := p.run(nil, refusal.op, inboundID)
		if err == nil {
			t.Errorf("%s returned success (out=%q); exit 2 would make gc report a no-op as done", refusal.op, out)
			continue
		}
		if !strings.Contains(err.Error(), refusal.want) {
			t.Errorf("%s error = %v, want %q", refusal.op, err, refusal.want)
		}
		if strings.Contains(err.Error(), "already archived") {
			t.Errorf("%s error trips gc's already-archived success path: %v", refusal.op, err)
		}
	}

	// --- failures of a KNOWN operation must not be swallowed ----------------
	// gc converts exit 2 into "unknown operation -> success with no output".
	// A usage failure that exited 2 would be reported to the user as a
	// successful send that delivered nothing.
	if out, err := p.run(nil, "send"); err == nil {
		t.Errorf("send with no recipient returned success (out=%q); it must exit 1", out)
	}
	if out, err := p.run(gcExecSendInput("mayor", "s", "b"), "send", "otherrig/deacon"); err == nil {
		t.Errorf("unmapped recipient returned success (out=%q)", out)
	} else if !strings.Contains(err.Error(), "aweb-mail.toml") {
		t.Errorf("unmapped recipient error does not name the map: %v", err)
	}
	if out, err := p.run(nil, "send", "myrig/mayor"); err == nil {
		t.Errorf("send with no stdin returned success (out=%q)", out)
	}

	// --- a genuinely unknown operation is gc's forward-compatibility case ---
	if out, err := p.run(nil, "teleport", "x"); err != nil || out != "" {
		t.Errorf("unknown operation: out=%q err=%v; exit 2 (success, empty) is the contract here", out, err)
	}

	// --- transport identification (design record §7) ------------------------
	marked := 0
	for _, ua := range userAgents {
		if strings.HasPrefix(ua, "aw-gc-mail/") {
			marked++
		}
		if strings.HasPrefix(ua, "aw-beads-mail/") {
			t.Errorf("gc-mail request carried the bd delegate's User-Agent %q", ua)
		}
	}
	if marked == 0 {
		t.Errorf("no request carried the aw-gc-mail transport marker; saw %v", userAgents)
	}
}
