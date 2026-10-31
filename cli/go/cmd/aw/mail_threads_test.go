package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// aw mail threads lists the mail conversations: each thread's title (its
// first message's subject), participants, last activity, unread count and
// conversation ID. Listing reads nothing else and acknowledges nothing.
func TestAwMailThreadsListsEachThreadWithItsTitle(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	self := awid.ComputeDIDKey(pub)

	var mu sync.Mutex
	var paths []string
	var query string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/conversations":
			query = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{
				Conversations: []awid.ConversationItem{
					{ConversationType: "mail", ConversationID: "11111111-1111-4111-8111-111111111111", Title: "Release plan", FirstMessageID: "msg-1", Subject: "Re: Release plan", Participants: []string{"gsk", "alice"}, LastMessageAt: "2026-10-31T12:00:00.123456+00:00", UnreadCount: 2},
					{ConversationType: "mail", ConversationID: "22222222-2222-4222-8222-222222222222", Title: "Release plan", FirstMessageID: "msg-2", Participants: []string{"bob", "gsk"}, LastMessageAt: "2026-10-30T09:00:00Z"},
				},
				NextCursor: "cursor-2",
			})
		case "/v1/agents/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	home := t.TempDir()
	writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
	run := func(args ...string) (string, string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, append([]string{"mail", "threads"}, args...)...)
		cmd.Dir = home
		cmd.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("aw mail threads %v: %v\n%s", args, err, &stderr)
		}
		return stdout.String(), stderr.String()
	}

	text, _ := run()
	for _, want := range []string{
		"Release plan",
		"With: alice\n",
		"Last activity: 2026-10-31T12:00:00Z · 2 unread",
		"Conversation ID: 11111111-1111-4111-8111-111111111111",
		"With: bob\n",
		"Last activity: 2026-10-30T09:00:00Z\n",
		"Conversation ID: 22222222-2222-4222-8222-222222222222",
		"aw mail threads --cursor cursor-2",
		"Answer in the conversation: aw mail reply <message_id>.",
		"Continue a thread: aw mail send --conversation-id <conversation_id> --body-file <file>",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("threads output missing %q:\n%s", want, text)
		}
	}
	// The list names the other participants, never you.
	if strings.Contains(text, "gsk") {
		t.Fatalf("threads lists you as a participant:\n%s", text)
	}
	// Two threads may share a title; the newest subject is not the title.
	if strings.Contains(text, "Re: Release plan") {
		t.Fatalf("threads shows the newest subject instead of the title:\n%s", text)
	}
	if !strings.Contains(query, "conversation_type=mail") {
		t.Fatalf("listing query %q does not select mail", query)
	}

	stdout, _ := run("--json", "--cursor", "cursor-2")
	assertOneJSONDocument(t, []byte(stdout))
	var listed awid.ConversationsResponse
	// JSON keeps the server's participants and timestamp as they are.
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil || len(listed.Conversations) != 2 || listed.Conversations[0].Title != "Release plan" || listed.NextCursor != "cursor-2" ||
		len(listed.Conversations[0].Participants) != 2 || listed.Conversations[0].LastMessageAt != "2026-10-31T12:00:00.123456+00:00" {
		t.Fatalf("threads --json: %v %s", err, stdout)
	}
	if !strings.Contains(query, "cursor=cursor-2") {
		t.Fatalf("listing query %q does not pass the cursor", query)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range paths {
		if path != "GET /v1/conversations" && path != "POST /v1/agents/heartbeat" {
			t.Fatalf("threads made another request: %v", paths)
		}
	}
}

// A conversation's title is fixed: aw mail reply refuses --subject and says
// how to start a new thread instead, before any request.
func TestAwMailReplyRefusesASubject(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	calls := 0
	var mu sync.Mutex
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		http.NotFound(w, r)
	}))
	home := t.TempDir()
	writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: awid.ComputeDIDKey(pub), Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
	cmd := exec.CommandContext(ctx, bin, "mail", "reply", "msg-in", "--subject", "Another topic", "--body", "hi")
	cmd.Dir = home
	cmd.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	mu.Lock()
	defer mu.Unlock()
	if exitCode(err) != 2 || calls != 0 || !strings.Contains(stderr.String(), "A conversation's title is fixed. To change the subject, start a new thread: aw mail send --to <recipient> --subject <subject>") {
		t.Fatalf("reply --subject: exit=%d calls=%d stderr=%s", exitCode(err), calls, &stderr)
	}
}

// Every surface that teaches mail says the same thing: answer in the
// conversation, start a new thread only for a new topic.
func TestMailHelpTeachesReplyInTheConversation(t *testing.T) {
	for _, cmd := range []string{mailCmd.Long, mailSendCmd.Long} {
		if !strings.Contains(cmd, mailThreadTeaching) {
			t.Fatalf("help does not teach the thread model:\n%s", cmd)
		}
	}
	if mailThreadTeaching != "Answer in the conversation: aw mail reply <message_id>. Start a new thread only for a new topic: aw mail send --to <recipient> --subject <subject>." {
		t.Fatalf("teaching wording changed: %q", mailThreadTeaching)
	}
}
