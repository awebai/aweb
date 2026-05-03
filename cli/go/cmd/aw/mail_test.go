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

func TestResolveMailTargetKeepsTildeTargetAsAlias(t *testing.T) {
	oldTo, oldToDID, oldToAddress, oldConversationID := mailSendTo, mailSendToDID, mailSendToAddress, mailSendConversationID
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
		mailSendConversationID = oldConversationID
	})

	mailSendTo = "ops~alice"
	mailSendToDID = ""
	mailSendToAddress = ""
	mailSendConversationID = ""

	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "alias" {
		t.Fatalf("kind=%q, want alias", kind)
	}
	if value != "ops~alice" {
		t.Fatalf("value=%q, want ops~alice", value)
	}
}

func TestResolveMailTargetConversationIDRejectsRecipients(t *testing.T) {
	oldTo, oldToDID, oldToAddress, oldConversationID := mailSendTo, mailSendToDID, mailSendToAddress, mailSendConversationID
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
		mailSendConversationID = oldConversationID
	})

	mailSendTo = ""
	mailSendToDID = ""
	mailSendToAddress = ""
	mailSendConversationID = "55555555-5555-4555-8555-555555555555"
	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "conversation" || value != mailSendConversationID {
		t.Fatalf("target=(%q,%q), want conversation %q", kind, value, mailSendConversationID)
	}

	mailSendTo = "alice"
	_, _, err = resolveMailTarget()
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("err=%v, want cannot be combined", err)
	}
}

func TestResolveMailBodyUsesBodyArg(t *testing.T) {
	body, err := resolveMailBody("hello", "")
	if err != nil {
		t.Fatal(err)
	}
	if body != "hello" {
		t.Fatalf("body=%q, want hello", body)
	}
}

func TestResolveMailBodyMutualExclusion(t *testing.T) {
	_, err := resolveMailBody("hello", "/some/path")
	if err == nil {
		t.Fatal("expected error when both --body and --body-file set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err=%q, want mutually exclusive", err)
	}
}

func TestResolveMailBodyMissingFlags(t *testing.T) {
	_, err := resolveMailBody("", "")
	if err == nil {
		t.Fatal("expected error when neither flag set")
	}
	if !strings.Contains(err.Error(), "missing required flag") {
		t.Fatalf("err=%q, want missing required flag", err)
	}
	if !strings.Contains(err.Error(), "--body") || !strings.Contains(err.Error(), "--body-file") {
		t.Fatalf("err=%q, want both --body and --body-file mentioned", err)
	}
}

func TestResolveMailBodyReadsFileVerbatimWithBackticks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body.md")
	content := "look at `config.ts` line 42 and ${VAR} stays as ${VAR}"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	body, err := resolveMailBody("", path)
	if err != nil {
		t.Fatal(err)
	}
	if body != content {
		t.Fatalf("body=%q, want %q", body, content)
	}
}

func TestResolveMailBodyStripsExactlyOneTrailingNewline(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"no newline", "X", "X"},
		{"single newline", "X\n", "X"},
		{"double newline becomes single", "X\n\n", "X\n"},
		{"internal newline preserved", "line1\nline2\n", "line1\nline2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			body, err := resolveMailBody("", path)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if body != tc.want {
				t.Fatalf("body=%q, want %q", body, tc.want)
			}
		})
	}
}

func TestResolveMailBodyEmptyFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveMailBody("", path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%q, want empty mentioned", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("err=%q, want path %q mentioned", err, path)
	}
}

func TestResolveMailBodyNewlineOnlyFileErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newline_only")
	if err := os.WriteFile(path, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveMailBody("", path)
	if err == nil {
		t.Fatal("expected error: file with only a trailing newline strips to empty")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err=%q, want empty mentioned", err)
	}
}

func TestResolveMailBodyMissingFileErrors(t *testing.T) {
	_, err := resolveMailBody("", filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "body file") {
		t.Fatalf("err=%q, want body file mentioned", err)
	}
}

func TestAwMailSendBodyFilePreservesBackticksOnTheWire(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)

	bodyContent := "look at `config.ts` line 42 and ${VAR} stays literal\nsecond `paragraph` here"

	type captured struct {
		Body string `json:"body"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "msg-aalh-1",
				"status":       "delivered",
				"delivered_at": "2026-04-26T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-26T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	bodyFile := filepath.Join(tmp, "body.md")
	if err := os.WriteFile(bodyFile, []byte(bodyContent), 0o644); err != nil {
		t.Fatalf("write body file: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to-did", "did:aw:monitor",
		"--body-file", bodyFile,
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if got.Body != bodyContent {
		t.Fatalf("body on wire=%q, want %q", got.Body, bodyContent)
	}
}

func TestAwMailSendConversationIDSignsPayloadAndOmitsRecipient(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "55555555-5555-4555-8555-555555555555"

	type captured struct {
		ToAlias        string `json:"to_alias"`
		ToDID          string `json:"to_did"`
		ToAddress      string `json:"to_address"`
		ConversationID string `json:"conversation_id"`
		Subject        string `json:"subject"`
		Body           string `json:"body"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-aame-7",
				"conversation_id": conversationID,
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--conversation-id", conversationID,
		"--subject", "Re",
		"--body", "reply",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Sent mail in conversation "+conversationID) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if got.ConversationID != conversationID {
		t.Fatalf("conversation_id=%q, want %q", got.ConversationID, conversationID)
	}
	if got.ToAlias != "" || got.ToDID != "" || got.ToAddress != "" {
		t.Fatalf("continuation leaked recipient fields: %+v", got)
	}
	if got.Subject != "Re" || got.Body != "reply" {
		t.Fatalf("unexpected message body: %+v", got)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != conversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], conversationID)
	}
	if signed["to"] != "" || signed["to_did"] != "" {
		t.Fatalf("signed continuation should not bind rediscovered recipient: %+v", signed)
	}
}

func TestAwMailSendConversationIDSurfacesNonParticipantRejection(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "66666666-6666-4666-8666-666666666666"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			http.Error(w, `{"detail":"Authenticated identity is not a participant in this conversation"}`, http.StatusForbidden)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--conversation-id", conversationID,
		"--body", "not allowed",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "not a participant") {
		t.Fatalf("expected participant rejection, got:\n%s", string(out))
	}
}

func TestAwMailSendConversationIDSurfacesMissingConversation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "99999999-9999-4999-8999-999999999999"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages":
			http.Error(w, `{"detail":"Conversation not found"}`, http.StatusNotFound)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--conversation-id", conversationID,
		"--body", "missing",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Conversation not found") {
		t.Fatalf("expected missing conversation rejection, got:\n%s", string(out))
	}
	if strings.Contains(string(out), "agent not found") {
		t.Fatalf("missing conversation should not be rewritten as missing agent:\n%s", string(out))
	}
}

func TestAwMailShowFetchesConversation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "77777777-7777-4777-8777-777777777777"
	var sawPath string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/conversations/" + conversationID:
			sawPath = r.URL.String()
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID:      "msg-1",
						ConversationID: conversationID,
						FromAlias:      "athena",
						ToAlias:        "grace",
						Subject:        "review",
						Body:           "please check this",
						Priority:       awid.PriorityNormal,
						CreatedAt:      "2026-05-02T00:00:00Z",
					},
					{
						MessageID:      "msg-2",
						ConversationID: conversationID,
						FromAlias:      "grace",
						ToAlias:        "athena",
						Subject:        "Re",
						Body:           "done",
						Priority:       awid.PriorityNormal,
						CreatedAt:      "2026-05-02T00:01:00Z",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "show",
		"--conversation-id", conversationID,
		"--limit", "25",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(sawPath, "limit=25") {
		t.Fatalf("request path=%q, want limit=25", sawPath)
	}
	if !strings.Contains(string(out), "Mail conversation "+conversationID) ||
		!strings.Contains(string(out), "please check this") ||
		!strings.Contains(string(out), "done") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwMailShowLegacyConversationHintAndMessageIDFetch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	messageID := "88888888-8888-4888-8888-888888888888"
	var sawMessageIDQuery bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/conversations/" + messageID:
			http.Error(w, `{"detail":"This is a legacy mail without a conversation; use --message-id"}`, http.StatusNotFound)
		case "/v1/messages/inbox":
			if r.URL.Query().Get("message_id") != messageID {
				t.Fatalf("message_id query=%q, want %q", r.URL.Query().Get("message_id"), messageID)
			}
			sawMessageIDQuery = true
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{
					{
						MessageID: messageID,
						FromAlias: "athena",
						ToAlias:   "grace",
						Subject:   "legacy",
						Body:      "old mail",
						Priority:  awid.PriorityNormal,
						CreatedAt: "2026-05-02T00:00:00Z",
					},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	showConversation := exec.CommandContext(ctx, bin, "mail", "show", "--conversation-id", messageID)
	showConversation.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	showConversation.Dir = tmp
	out, err := showConversation.CombinedOutput()
	if err == nil {
		t.Fatalf("expected legacy hint failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "aw mail show --message-id "+messageID) {
		t.Fatalf("missing legacy message-id hint:\n%s", string(out))
	}

	showMessage := exec.CommandContext(ctx, bin, "mail", "show", "--message-id", messageID)
	showMessage.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	showMessage.Dir = tmp
	out, err = showMessage.CombinedOutput()
	if err != nil {
		t.Fatalf("message-id show failed: %v\n%s", err, string(out))
	}
	if !sawMessageIDQuery {
		t.Fatal("mail show --message-id did not query inbox by message_id")
	}
	if !strings.Contains(string(out), "old mail") {
		t.Fatalf("message-id output missing mail body:\n%s", string(out))
	}
}

func TestAwMailSendRejectsBothBodyAndBodyFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://127.0.0.1:1")

	bodyFile := filepath.Join(tmp, "body.md")
	if err := os.WriteFile(bodyFile, []byte("from file"), 0o644); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send",
		"--to", "alice",
		"--body", "from flag",
		"--body-file", bodyFile,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got:\n%s", string(out))
	}
}
