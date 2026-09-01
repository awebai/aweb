package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
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

func TestSplitBeadsMailEnvelope(t *testing.T) {
	p := 1
	withEnvelope := appendBeadsMailEnvelope("the body", beadsMailEnvelope{Type: "task", Priority: &p})
	body, env := splitBeadsMailEnvelope(withEnvelope)
	if body != "the body" || env == nil || env.Type != "task" || env.Priority == nil || *env.Priority != 1 {
		t.Errorf("round trip: body=%q env=%+v", body, env)
	}

	// Malformed JSON in the fence is body text, never an error.
	raw := "text\n\n```beads-mail\nnot json\n```\n"
	body, env = splitBeadsMailEnvelope(raw)
	if env != nil || body != raw {
		t.Errorf("malformed fence: body=%q env=%+v", body, env)
	}

	// The LAST fence wins; user content containing a fence earlier in the
	// body survives, and trailing content after the parsed fence is kept.
	tricky := "user wrote:\n```beads-mail\n{\"v\":1,\"type\":\"fake\"}\n```\nmore text\n\n```beads-mail\n{\"v\":1,\"type\":\"real\"}\n```\n"
	body, env = splitBeadsMailEnvelope(tricky)
	if env == nil || env.Type != "real" || !strings.Contains(body, "user wrote") || !strings.Contains(body, "more text") {
		t.Errorf("last-fence: body=%q env=%+v", body, env)
	}

	if body, env := splitBeadsMailEnvelope("plain"); env != nil || body != "plain" {
		t.Errorf("plain body: %q %+v", body, env)
	}
}

func TestBeadsMailStatePathUsesWorktreeRoot(t *testing.T) {
	// Selection.WorkspacePath is the workspace.yaml FILE — the state must
	// land beside it in the worktree's .aw, not under the yaml as if it
	// were a directory (that broke every team-bound workspace).
	sel := &awconfig.Selection{WorkspacePath: "/repo/.aw/workspace.yaml"}
	if got := beadsMailStatePath(sel); got != "/repo/.aw/beads-mail/state.json" {
		t.Errorf("state path %q", got)
	}
	cwd, _ := os.Getwd()
	if got := beadsMailStatePath(&awconfig.Selection{}); got != filepath.Join(cwd, ".aw", "beads-mail", "state.json") {
		t.Errorf("standalone fallback %q", got)
	}
}

func TestSanitizeBeadsMailBody(t *testing.T) {
	in := "line one\n\tindented\x1b[31mred\x07bell"
	got := sanitizeBeadsMailBody(in)
	if !strings.Contains(got, "line one\n\tindented") || strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("sanitized body %q", got)
	}
}

func TestBeadsMailReadVerbsAgainstLocalServer(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	senderPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderDID := awid.ComputeDIDKey(senderPub)

	pInt := 1
	unreadBody := appendBeadsMailEnvelope("the well is low", beadsMailEnvelope{Type: "task", Priority: &pInt})
	readAt := "2026-08-30T00:00:00Z"
	conversationID := "77777777-7777-4777-8777-777777777777"
	msgUnread := awid.InboxMessage{
		MessageID:      "88888888-8888-4888-8888-888888888888",
		ConversationID: conversationID,
		Subject:        "Water levels",
		Body:           unreadBody,
		FromAddress:    "acme.example/mayor",
		Priority:       awid.PriorityHigh,
		CreatedAt:      "2026-08-31T01:00:00Z",
	}
	msgRead := awid.InboxMessage{
		MessageID:      "99999999-9999-4999-8999-999999999999",
		ConversationID: conversationID,
		Subject:        "Earlier note",
		Body:           "old news",
		FromAddress:    "acme.example/mayor",
		Priority:       awid.PriorityNormal,
		CreatedAt:      "2026-08-30T01:00:00Z",
		ReadAt:         &readAt,
	}

	var ackCalls []string
	ackFailure := false
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/messages/inbox":
			q := r.URL.Query()
			if id := q.Get("message_id"); id != "" {
				for _, m := range []awid.InboxMessage{msgUnread, msgRead} {
					if m.MessageID == id {
						_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{m}})
						return
					}
				}
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
				return
			}
			if q.Get("unread_only") == "true" {
				unread := []awid.InboxMessage{}
				for _, a := range ackCalls {
					if a == msgUnread.MessageID {
						_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: unread})
						return
					}
				}
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{msgUnread}})
				return
			}
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{msgUnread, msgRead}})
		case r.URL.Path == "/v1/messages/"+msgUnread.MessageID && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(msgUnread)
		case r.URL.Path == "/v1/messages/"+msgRead.MessageID && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(msgRead)
		case r.URL.Path == "/v1/messages/conversations/"+conversationID:
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{msgRead, msgUnread}})
		case strings.HasSuffix(r.URL.Path, "/ack") && r.Method == http.MethodPost:
			if ackFailure {
				http.Error(w, "ack unavailable", http.StatusServiceUnavailable)
				return
			}
			parts := strings.Split(r.URL.Path, "/")
			ackCalls = append(ackCalls, parts[len(parts)-2])
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: parts[len(parts)-2], AcknowledgedAt: "2026-08-31T02:00:00Z"})
		case r.URL.Path == "/v1/namespaces/acme.example/addresses/mayor":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-mayor",
				"domain":          "acme.example",
				"name":            "mayor",
				"did_aw":          "did:aw:mayor",
				"current_did_key": senderDID,
				"reachability":    "public",
				"created_at":      "2026-08-31T00:00:00Z",
			})
		case r.URL.Path == "/v1/did/did:aw:mayor/key":
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": "did:aw:mayor", "current_did_key": senderDID})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tmp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		CreatedAt:     "2026-08-31T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, ".beads"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".beads", beadsMailMapFileName),
		[]byte("[addresses]\n\"mayor/\" = \"acme.example/mayor\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, append([]string{"beads-mail"}, args...)...)
		cmd.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
		cmd.Dir = tmp
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// inbox: read-only listing (no acks), reverse-mapped sender, unread
	// marker, and the index state file written.
	out, err := run("inbox")
	if err != nil {
		t.Fatalf("inbox failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "mayor/ (acme.example/mayor)") || !strings.Contains(out, "Water levels") || !strings.Contains(out, " 1 *") {
		t.Errorf("inbox output:\n%s", out)
	}
	if len(ackCalls) != 0 {
		t.Fatalf("inbox acked: %v", ackCalls)
	}
	stateContent, err := os.ReadFile(filepath.Join(tmp, ".aw", "beads-mail", "state.json"))
	if err != nil || !strings.Contains(string(stateContent), msgUnread.MessageID) {
		t.Errorf("state file: err=%v content=%s", err, stateContent)
	}

	// peek: shows the first unread without acking.
	if out, err := run("peek"); err != nil || !strings.Contains(out, "Water levels") {
		t.Fatalf("peek: %v\n%s", err, out)
	}
	if len(ackCalls) != 0 {
		t.Errorf("peek acked: %v", ackCalls)
	}

	// check with unread mail: exit 0 (a disclosed divergence from gt's
	// exit-1-on-empty convention), read-only, --json machine shape,
	// --inject the Claude Code hook envelope.
	out, err = run("check")
	if err != nil || !strings.Contains(out, "You have 1 unread bd mail message(s)") {
		t.Errorf("check: err=%v\n%s", err, out)
	}
	out, err = run("check", "--json")
	if err != nil || !strings.Contains(out, `"unread":1`) {
		t.Errorf("check --json: err=%v\n%s", err, out)
	}
	out, err = run("check", "--inject")
	if err != nil || !strings.Contains(out, "hookSpecificOutput") || !strings.Contains(out, "PostToolUse") {
		t.Errorf("check --inject: err=%v\n%s", err, out)
	}
	if len(ackCalls) != 0 {
		t.Errorf("check acked: %v", ackCalls)
	}

	// read by index: envelope stripped into headers, then acked.
	out, err = run("read", "1")
	if err != nil {
		t.Fatalf("read failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "the well is low") || strings.Contains(out, "beads-mail") ||
		!strings.Contains(out, "Type: task") || !strings.Contains(out, "high (beads 1)") {
		t.Errorf("read output:\n%s", out)
	}
	if len(ackCalls) != 1 || ackCalls[0] != msgUnread.MessageID {
		t.Errorf("read acks: %v", ackCalls)
	}

	// thread: oldest-first with both messages.
	out, err = run("thread", conversationID)
	if err != nil {
		t.Fatalf("thread failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Earlier note") || !strings.Contains(out, "Water levels") || !strings.Contains(out, "---") ||
		strings.Index(out, "Earlier note") > strings.Index(out, "Water levels") {
		t.Errorf("thread output (want oldest first):\n%s", out)
	}

	// Everything is read now (the fixture reflects the ack): check goes
	// silent with exit 0 — the divergence that makes hooks safe — peek
	// says so, and mark-read --all still succeeds with nothing to do.
	if out, err := run("check"); err != nil || strings.Contains(out, "unread bd mail") {
		t.Errorf("check after read: err=%v out=%q", err, out)
	}
	if out, err := run("peek"); err != nil || !strings.Contains(out, "No unread mail.") {
		t.Errorf("peek after read: err=%v\n%s", err, out)
	}
	if out, err := run("mark-read", "--all"); err != nil || !strings.Contains(out, "marked 0 message(s) read") {
		t.Errorf("mark-read --all after read: err=%v\n%s", err, out)
	}

	// Explicit mark-read by id still acks (server accepts acks for read
	// messages idempotently in this fixture).
	if out, err := run("mark-read", msgRead.MessageID); err != nil || !strings.Contains(out, "marked 1 message(s) read") {
		t.Errorf("mark-read by id: err=%v\n%s", err, out)
	}
	if len(ackCalls) != 2 {
		t.Errorf("acks after explicit mark-read: %v", ackCalls)
	}

	// Index out of range is a guided error.
	if out, err := run("read", "99"); err == nil || !strings.Contains(out, "out of range") {
		t.Errorf("read 99: err=%v\n%s", err, out)
	}

	// A failed acknowledgement must be visible. read has already displayed
	// the message, while mark-read reports that it did not change state.
	ackFailure = true
	if out, err := run("read", msgUnread.MessageID); err == nil ||
		!strings.Contains(out, "the well is low") || !strings.Contains(out, "could not be marked read") {
		t.Errorf("read with failed ack: err=%v\n%s", err, out)
	}
	if out, err := run("mark-read", msgRead.MessageID); err == nil ||
		!strings.Contains(out, "marked 0 message(s) read") || !strings.Contains(out, "failed to mark 1 message(s) read") {
		t.Errorf("mark-read with failed ack: err=%v\n%s", err, out)
	}
}
