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

	"github.com/awebai/aw/awconfig"
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
	otherDID := func() string {
		otherPub, _, _ := ed25519.GenerateKey(nil)
		return awid.ComputeDIDKey(otherPub)
	}
	alice, bob, namesake := otherDID(), otherDID(), otherDID()

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
			// participant_details binds each participant's labels to its
			// identity; the legacy label arrays are deduplicated labels only.
			native := func(did string) map[string]string { return map[string]string{"kind": "native", "did": did} }
			_ = json.NewEncoder(w).Encode(map[string]any{
				"conversations": []map[string]any{
					{"conversation_type": "mail", "conversation_id": "11111111-1111-4111-8111-111111111111", "title": "Release plan", "first_message_id": "msg-1", "subject": "Re: Release plan",
						"participants": []string{"gsk", "alice"}, "last_message_at": "2026-10-31T12:00:00.123456+00:00", "unread_count": 2,
						"participant_details": []map[string]any{{"participant_ref": native(self), "alias": "gsk", "address": "test.local/gsk"}, {"participant_ref": native(alice), "alias": "alice", "address": "test.local/alice"}}},
					{"conversation_type": "mail", "conversation_id": "22222222-2222-4222-8222-222222222222", "title": "Release plan", "first_message_id": "msg-2",
						"participants": []string{"bob", "gsk"}, "last_message_at": "2026-10-30T09:00:00Z",
						"participant_details": []map[string]any{{"participant_ref": native(bob), "alias": "bob", "address": nil}, {"participant_ref": native(self), "alias": "gsk", "address": "test.local/gsk"}}},
					// Another identity with your alias, and a historical
					// participant whose reference cannot be parsed: both are
					// other participants, never you.
					{"conversation_type": "mail", "conversation_id": "33333333-3333-4333-8333-333333333333", "title": "Namesakes", "first_message_id": "msg-3",
						"participants": []string{"gsk", "legacy"}, "last_message_at": "2026-10-29T09:00:00Z",
						"participant_details": []map[string]any{{"participant_ref": native(self), "alias": "gsk", "address": "test.local/gsk"}, {"participant_ref": native(namesake), "alias": "gsk", "address": "other.example/gsk"}, {"participant_ref": nil, "alias": "legacy", "address": nil}}},
				},
				"next_cursor": "cursor-2",
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
	// The list names the other participants, never you: a namesake is shown
	// by its address, and an unparseable reference by its label.
	if !strings.Contains(text, "With: other.example/gsk, legacy\n") {
		t.Fatalf("threads hid another identity that shares your alias:\n%s", text)
	}
	if strings.Contains(text, "With: gsk") || strings.Contains(text, "test.local/gsk") || strings.Contains(text, ", gsk") {
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
	var raw struct {
		Conversations []struct {
			ParticipantDetails []map[string]any `json:"participant_details"`
		} `json:"conversations"`
	}
	if err := json.Unmarshal([]byte(stdout), &raw); err != nil || len(raw.Conversations) != 3 || len(raw.Conversations[2].ParticipantDetails) != 3 || raw.Conversations[2].ParticipantDetails[2]["participant_ref"] != nil {
		t.Fatalf("threads --json lost participant_details: %v %s", err, stdout)
	}
	var listed awid.ConversationsResponse
	// JSON keeps the server's participants and timestamp as they are.
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil || len(listed.Conversations) != 3 || listed.Conversations[0].Title != "Release plan" || listed.NextCursor != "cursor-2" ||
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

// An encrypted first message's subject is the thread's title only from that
// message's own authenticated proof: the exact first message of this
// conversation, decrypted and not failed. Anything else leaves the title
// empty, and reading it acknowledges nothing.
func TestAwMailThreadsTitlesAnEncryptedFirstMessageOnlyFromItsOwnProof(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalRoot := filepath.Join(root, "principal")
	selfPub, selfKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	selfDID := awid.ComputeDIDKey(selfPub)
	remotePub, remoteKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, remoteEncryptionPub, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	remoteDID := awid.ComputeDIDKey(remotePub)
	remoteAssertion, err := awid.BuildEncryptionKeyAssertion(remoteKey, remoteDID, "", remoteEncryptionPub, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	const (
		titled, wrongMessage, wrongConversation, failed = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	)
	messages := map[string]awid.InboxMessage{}
	var mu sync.Mutex
	var paths []string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/conversations":
			thread := func(conversationID, firstID string) map[string]any {
				return map[string]any{"conversation_type": "mail", "conversation_id": conversationID, "title": "", "first_message_id": firstID,
					"subject": "", "participants": []string{"remote", "principal"}, "last_message_at": "2026-10-31T12:00:00Z"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"conversations": []map[string]any{
				thread(titled, "msg-titled"),
				thread(wrongMessage, "msg-wrong-message"),
				thread(wrongConversation, "msg-wrong-conversation"),
				thread(failed, "msg-failed"),
			}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/messages/"):
			message, ok := messages[strings.TrimPrefix(r.URL.Path, "/v1/messages/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(message)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			// Sender verification reads the team roster; the remote sender
			// is not on it.
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", selfDID, selfKey)
	principalHome := filepath.Join(principalRoot, ".aw")
	selfAssertion := installMailReadEncryptionKeyForTest(t, principalRoot, principalHome, selfDID, selfKey)
	encrypted := func(outerID, outerConversation, innerID, innerConversation, subject string) awid.InboxMessage {
		envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
			Sender:         awid.E2EESenderKey{DID: remoteDID, EncryptionKey: remoteAssertion, SigningKey: remoteKey},
			Recipients:     []awid.E2EERecipientKey{{DID: selfDID, EncryptionKey: selfAssertion}},
			Subject:        subject,
			Body:           "first message body",
			MessageID:      innerID,
			ConversationID: innerConversation,
			CreatedAt:      time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return awid.InboxMessage{
			MessageID: outerID, ConversationID: outerConversation, Subject: "projected subject",
			FromAlias: "remote", ToAlias: "principal", FromDID: remoteDID, ToDID: selfDID,
			ContentMode: awid.ContentModeEncryptedV2, MessageVersion: awid.E2EEMessageVersion,
			Encrypted: envelope, Priority: awid.PriorityNormal, CreatedAt: envelope.CreatedAt,
		}
	}
	messages["msg-titled"] = encrypted("msg-titled", titled, "msg-titled", titled, "Salary review")
	// The server answers with another message than the thread's first.
	messages["msg-wrong-message"] = encrypted("msg-other", wrongMessage, "msg-other", wrongMessage, "Not the first message")
	// The exact message, but it belongs to another conversation.
	messages["msg-wrong-conversation"] = encrypted("msg-wrong-conversation", titled, "msg-wrong-conversation", titled, "Another thread's message")
	// The outer projection disagrees with the authenticated inner IDs, so the
	// read keeps the projection and marks it failed.
	messages["msg-failed"] = encrypted("msg-failed", failed, "msg-failed", titled, "Inner subject")

	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	command := exec.CommandContext(ctx, bin, "--identity-home", principalHome, "mail", "threads")
	command.Dir = principalRoot
	command.Env = append(testCommandEnv(filepath.Join(root, "home")), awconfig.IdentityHomeEnv+"=")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("aw mail threads: %v\n%s\n%s", err, &stdout, &stderr)
	}
	text := stdout.String()
	if !strings.Contains(text, "- Salary review\n") || strings.Count(text, "- (untitled)\n") != 3 {
		t.Fatalf("encrypted titles:\n%s\n%s", text, &stderr)
	}
	for _, leaked := range []string{"Not the first message", "Another thread's message", "projected subject", "Inner subject"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("threads adopted %q as a title:\n%s", leaked, text)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range paths {
		if strings.HasSuffix(path, "/ack") || strings.HasPrefix(path, "POST /v1/messages") {
			t.Fatalf("reading a title acknowledged or sent mail: %v", paths)
		}
	}
}
