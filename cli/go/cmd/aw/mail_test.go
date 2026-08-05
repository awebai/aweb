package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
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

func TestResolveMailTargetNormalizesHostedHandleAddress(t *testing.T) {
	oldTo, oldToDID, oldToAddress, oldConversationID := mailSendTo, mailSendToDID, mailSendToAddress, mailSendConversationID
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
		mailSendConversationID = oldConversationID
	})

	mailSendTo = "@jane/c3po"
	mailSendToDID = ""
	mailSendToAddress = ""
	mailSendConversationID = ""

	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "address" {
		t.Fatalf("kind=%q, want address", kind)
	}
	if value != "jane.aweb.ai/c3po" {
		t.Fatalf("value=%q, want jane.aweb.ai/c3po", value)
	}
}

func TestResolveMailTargetNormalizesExplicitHostedHandleAddress(t *testing.T) {
	oldTo, oldToDID, oldToAddress, oldConversationID := mailSendTo, mailSendToDID, mailSendToAddress, mailSendConversationID
	t.Cleanup(func() {
		mailSendTo = oldTo
		mailSendToDID = oldToDID
		mailSendToAddress = oldToAddress
		mailSendConversationID = oldConversationID
	})

	mailSendTo = ""
	mailSendToDID = ""
	mailSendToAddress = "@jane/c3po"
	mailSendConversationID = ""

	kind, value, err := resolveMailTarget()
	if err != nil {
		t.Fatal(err)
	}
	if kind != "address" {
		t.Fatalf("kind=%q, want address", kind)
	}
	if value != "jane.aweb.ai/c3po" {
		t.Fatalf("value=%q, want jane.aweb.ai/c3po", value)
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

func TestE2EEAssertionIdentityUsesMatchingIdentityStableID(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           did,
		StableID:      stableID,
		Address:       "example.test/eve",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
	}); err != nil {
		t.Fatal(err)
	}

	identity := e2eeAssertionIdentityForSelection(&awconfig.Selection{
		WorkingDir: tmp,
		DID:        did,
		StableID:   "",
	})
	if identity.DID != did {
		t.Fatalf("did=%q, want %q", identity.DID, did)
	}
	if identity.StableID != stableID {
		t.Fatalf("stable_id=%q, want %q", identity.StableID, stableID)
	}
}

func TestE2EEAssertionIdentityUsesExternalIdentityHome(t *testing.T) {
	t.Parallel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	instance := filepath.Join(root, "instance")
	principal := filepath.Join(root, "principal")
	principalPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	principalStableID := awid.ComputeStableID(principalPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(principal, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           principalDID,
		StableID:      principalStableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(instance, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           awid.ComputeDIDKey(shadowPub),
		StableID:      awid.ComputeStableID(shadowPub),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
	}); err != nil {
		t.Fatal(err)
	}

	identity := e2eeAssertionIdentityForSelection(&awconfig.Selection{
		WorkingDir:   instance,
		IdentityHome: principal,
		DID:          principalDID,
	})
	if identity.DID != principalDID || identity.StableID != principalStableID {
		t.Fatalf("identity=(%q,%q), want external (%q,%q)", identity.DID, identity.StableID, principalDID, principalStableID)
	}
}

func TestAwMailInboxAcknowledgesUnreadPageBeforeCursorContinuation(t *testing.T) {
	t.Parallel()

	messageIDs := []string{
		"00000000-0000-4000-8000-000000000001",
		"00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003",
	}
	acked := map[string]bool{}
	pageFetches := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/messages/inbox":
			pageFetches++
			cursor := r.URL.Query().Get("cursor")
			if pageFetches == 1 {
				if cursor != "" {
					t.Fatalf("first page cursor=%q", cursor)
				}
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{
					Messages: []awid.InboxMessage{
						{MessageID: messageIDs[0], FromAlias: "alice", Body: "first-page-a", CreatedAt: "2026-07-31T12:00:02Z"},
						{MessageID: messageIDs[1], FromAlias: "alice", Body: "first-page-b", CreatedAt: "2026-07-31T12:00:01Z"},
					},
					HasMore:    true,
					NextCursor: "cursor-token",
				})
				return
			}
			if cursor != "cursor-token" {
				t.Fatalf("continuation cursor=%q", cursor)
			}
			if !acked[messageIDs[0]] || !acked[messageIDs[1]] {
				t.Fatalf("continuation fetched before visible page was acknowledged: %+v", acked)
			}
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{
				Messages: []awid.InboxMessage{{
					MessageID: messageIDs[2],
					FromAlias: "alice",
					Body:      "second-page",
					CreatedAt: "2026-07-31T12:00:00Z",
				}},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			messageID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/messages/"), "/ack")
			if !slices.Contains(messageIDs, messageID) {
				t.Fatalf("unexpected ack message id %q", messageID)
			}
			acked[messageID] = true
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: messageID, AcknowledgedAt: "2026-07-31T12:01:00Z"})
		case r.URL.Path == "/v1/agents/heartbeat":
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
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	runInbox := func(args ...string) string {
		run := exec.CommandContext(ctx, bin, append([]string{"mail", "inbox"}, args...)...)
		run.Env = testCommandEnv(tmp)
		run.Dir = tmp
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("mail inbox %v failed: %v\n%s", args, err, out)
		}
		return string(out)
	}

	firstOutput := runInbox("--limit", "2")
	if !strings.Contains(firstOutput, "first-page-a") || !strings.Contains(firstOutput, "first-page-b") ||
		strings.Contains(firstOutput, "second-page") || !strings.Contains(firstOutput, "--cursor cursor-token") {
		t.Fatalf("first page output is incomplete or overlaps continuation:\n%s", firstOutput)
	}
	if !acked[messageIDs[0]] || !acked[messageIDs[1]] || acked[messageIDs[2]] {
		t.Fatalf("first page read state=%+v", acked)
	}

	secondOutput := runInbox("--limit", "2", "--cursor", "cursor-token")
	if strings.Contains(secondOutput, "first-page") || !strings.Contains(secondOutput, "second-page") {
		t.Fatalf("second page overlapped or omitted content:\n%s", secondOutput)
	}
	if pageFetches != 2 || !acked[messageIDs[0]] || !acked[messageIDs[1]] || !acked[messageIDs[2]] {
		t.Fatalf("final fetch/read state: fetches=%d acked=%+v", pageFetches, acked)
	}
}

type mailPresentationErrorWriter struct{}

func (mailPresentationErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("closed presentation writer")
}

func TestPresentAndAcknowledgeMailInboxDoesNotAcknowledgeFailedOutput(t *testing.T) {
	previousJSON := jsonFlag
	t.Cleanup(func() { jsonFlag = previousJSON })

	messageID := "00000000-0000-4000-8000-000000000004"
	acked := false
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/"+messageID+"/ack" {
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
		acked = true
		_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: messageID})
	}))
	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp := &awid.InboxResponse{Messages: []awid.InboxMessage{{
		MessageID: messageID,
		FromAlias: "alice",
		Body:      "must remain unread",
	}}}

	for _, tc := range []struct {
		name string
		json bool
	}{
		{name: "text"},
		{name: "json", json: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jsonFlag = tc.json
			acked = false
			err := presentAndAcknowledgeMailInbox(
				context.Background(),
				mailPresentationErrorWriter{},
				client,
				resp,
			)
			if err == nil || !strings.Contains(err.Error(), "closed presentation writer") {
				t.Fatalf("presentation error=%v", err)
			}
			if acked {
				t.Fatal("mail was acknowledged after its presentation writer failed")
			}
		})
	}
}

func TestAwMailInboxDoesNotAcknowledgeWhenPresentationFails(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "text"},
		{name: "json", args: []string{"--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			messageID := "00000000-0000-4000-8000-000000000004"
			acked := false
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/messages/inbox":
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{
						MessageID: messageID,
						FromAlias: "alice",
						Body:      "must remain unread",
						CreatedAt: "2026-07-31T12:00:00Z",
					}}})
				case r.URL.Path == "/v1/messages/"+messageID+"/ack":
					acked = true
					_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: messageID, AcknowledgedAt: "2026-07-31T12:01:00Z"})
				case r.URL.Path == "/v1/agents/heartbeat":
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
			writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

			readEnd, writeEnd, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := readEnd.Close(); err != nil {
				t.Fatal(err)
			}
			runArgs := append([]string{"mail", "inbox"}, tc.args...)
			run := exec.CommandContext(ctx, bin, runArgs...)
			run.Env = testCommandEnv(tmp)
			run.Dir = tmp
			run.Stdout = writeEnd
			var stderr strings.Builder
			run.Stderr = &stderr
			runErr := run.Run()
			_ = writeEnd.Close()

			if runErr == nil {
				t.Fatalf("mail inbox reported success after its presentation write failed; stderr=%s", stderr.String())
			}
			if acked {
				t.Fatal("mail was acknowledged before the failed presentation write")
			}
		})
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
	recipientPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientDID := awid.ComputeDIDKey(recipientPub)

	bodyContent := "look at `config.ts` line 42 and ${VAR} stays literal\nsecond `paragraph` here"

	type captured struct {
		Body string `json:"body"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
		case "/v1/namespaces/otherco.com/addresses/monitor":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-monitor",
				"domain":          "otherco.com",
				"name":            "monitor",
				"did_aw":          "did:aw:monitor",
				"current_did_key": recipientDID,
				"reachability":    "public",
				"created_at":      "2026-04-26T00:00:00Z",
				"delivery": map[string]any{
					"origin": "https://remote.example",
					"source": "namespace",
				},
			})
		case "/v1/did/did:aw:monitor/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          "did:aw:monitor",
				"current_did_key": recipientDID,
			})
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
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		CreatedAt:     "2026-04-26T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	bodyFile := filepath.Join(tmp, "body.md")
	if err := os.WriteFile(bodyFile, []byte(bodyContent), 0o644); err != nil {
		t.Fatalf("write body file: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
		"--to-address", "otherco.com/monitor",
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

func TestAwMailSendConversationIDSignsPayloadWithRediscoveredRecipient(t *testing.T) {
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
		ToStableID     string `json:"to_stable_id"`
		ToAddress      string `json:"to_address"`
		ConversationID string `json:"conversation_id"`
		Subject        string `json:"subject"`
		Body           string `json:"body"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{
				{
					ConversationType:     "mail",
					ConversationID:       conversationID,
					Participants:         []string{"alice", "bob"},
					ParticipantDIDs:      []string{stableID, "did:aw:bob"},
					ParticipantAddresses: []string{"test.local/alice", "otherco.com/bob"},
				},
			}})
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
		DID:           did,
		Address:       "test.local/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
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
	// aweb-aauz: the id line alone reads as delivered-and-verified. The boundary
	// notice must reach real command output, not merely exist as a string.
	if !strings.Contains(string(out), "Acceptance is not delivery") {
		t.Fatalf("send output omits the boundary notice, so exit 0 still reads as delivery:\n%s", string(out))
	}
	if got.ConversationID != conversationID {
		t.Fatalf("conversation_id=%q, want %q", got.ConversationID, conversationID)
	}
	if got.ToAlias != "" || got.ToDID != "" {
		t.Fatalf("continuation used unexpected recipient fields: %+v", got)
	}
	if got.ToAddress != "" {
		t.Fatalf("to_address=%q, want empty for identity-bound continuation", got.ToAddress)
	}
	if got.ToStableID != "did:aw:bob" {
		t.Fatalf("to_stable_id=%q, want did:aw:bob", got.ToStableID)
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
	if signed["to"] != "did:aw:bob" || signed["to_stable_id"] != "did:aw:bob" {
		t.Fatalf("signed continuation did not bind rediscovered participant identity: %+v", signed)
	}
	if got, _ := signed["to_did"].(string); got != "" {
		t.Fatalf("signed continuation should leave unresolved to_did empty for stored did:aw route: %+v", signed)
	}

	// aweb-aauz: --json must stay machine-clean on THIS path. A status line in JSON
	// breaks every downstream parser, and the failure is silent. Asserted per path
	// because a single --json check would inherit the one-of-three reachability
	// coverage this file just fixed - the same defect one layer up.
	runJSON := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--conversation-id", conversationID, "--subject", "Re", "--body", "reply", "--json")
	runJSON.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	runJSON.Dir = tmp
	jsonOut, jsonErr := runJSON.CombinedOutput()
	if jsonErr != nil {
		t.Fatalf("conversation --json run failed: %v\n%s", jsonErr, string(jsonOut))
	}
	if strings.Contains(string(jsonOut), "Acceptance is not delivery") {
		t.Fatalf("conversation --json output carries the boundary notice, breaking parsers:\n%s", string(jsonOut))
	}
}

func TestAwMailSendToAddressAutoThreadsUniqueConversation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "55555555-5555-4555-8555-555555555555"

	type captured struct {
		ToAddress      string `json:"to_address"`
		ToStableID     string `json:"to_stable_id"`
		ConversationID string `json:"conversation_id"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/conversations":
			http.NotFound(w, r)
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{
				{
					MessageID:      "msg-in",
					ConversationID: conversationID,
					FromAddress:    "otherco.com/bob",
					FromDID:        "did:aw:bob",
					ToAddress:      "acme.com/alice",
					ToDID:          stableID,
					Subject:        "hello",
					Body:           "hi",
					CreatedAt:      "2026-05-02T00:00:00Z",
				},
			}})
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-reply",
				"conversation_id": conversationID,
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:01Z",
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
		DID:           did,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
		"--to-address", "otherco.com/bob",
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
	if got.ToAddress != "" {
		t.Fatalf("to_address=%q, want empty for identity-bound continuation", got.ToAddress)
	}
	if got.ToStableID != "did:aw:bob" {
		t.Fatalf("to_stable_id=%q, want did:aw:bob", got.ToStableID)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != conversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], conversationID)
	}
	if signed["to"] != "did:aw:bob" || signed["to_stable_id"] != "did:aw:bob" {
		t.Fatalf("signed threaded reply did not bind participant identity: %+v", signed)
	}
}

func TestAwMailSendToAddressAutoThreadsSentConversationFromIndex(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "66666666-6666-4666-8666-666666666666"

	type captured struct {
		ToAddress      string `json:"to_address"`
		ToStableID     string `json:"to_stable_id"`
		ConversationID string `json:"conversation_id"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured
	var conversationQuery string
	var registryAddressLookups int

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case "/v1/conversations":
			conversationQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{
				{
					ConversationType:     "mail",
					ConversationID:       conversationID,
					Participants:         []string{"gsk", "alice"},
					ParticipantDIDs:      []string{stableID, "did:aw:alice"},
					ParticipantAddresses: []string{"test.local/gsk", "test.local/alice"},
					Subject:              "Ephemeral sender address",
					LastMessageAt:        "2026-05-02T00:00:00Z",
				},
			}})
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-reply",
				"conversation_id": conversationID,
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:01Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/namespaces/test.local/addresses/alice":
			registryAddressLookups++
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Address not found"}`))
		case "/v1/did/did%3Aaw%3Aalice/key", "/v1/did/did:aw:alice/key":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"DID not found"}`))
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
		DID:           did,
		StableID:      stableID,
		Address:       "test.local/gsk",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
		"--to-address", "test.local/alice",
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
	if got := conversationQuery; !strings.Contains(got, "conversation_type=mail") || !strings.Contains(got, "participant_address=test.local%2Falice") {
		t.Fatalf("conversation query=%q, want mail participant_address filter", got)
	}
	if got.ConversationID != conversationID {
		t.Fatalf("conversation_id=%q, want %q", got.ConversationID, conversationID)
	}
	if got.ToAddress != "" {
		t.Fatalf("to_address=%q, want empty for threaded identity-bound continuation", got.ToAddress)
	}
	if got.ToStableID != "did:aw:alice" {
		t.Fatalf("to_stable_id=%q, want did:aw:alice", got.ToStableID)
	}
	if registryAddressLookups != 0 {
		t.Fatalf("threaded continuation performed %d address lookup(s), want 0", registryAddressLookups)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != conversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], conversationID)
	}
	if signed["to"] != "did:aw:alice" || signed["to_stable_id"] != "did:aw:alice" {
		t.Fatalf("signed threaded sent-side reply did not bind participant identity: %+v", signed)
	}
}

func TestAwMailSendAliasAutoThreadsConcreteAgentConversation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "77777777-7777-4777-8777-777777777777"

	type captured struct {
		ToAlias        string `json:"to_alias"`
		ToAddress      string `json:"to_address"`
		ToStableID     string `json:"to_stable_id"`
		ConversationID string `json:"conversation_id"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured
	var conversationQuery string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{
				TeamID: "devteam:test.local",
				Agents: []awid.AgentView{
					{
						AgentID: "alice-agent",
						Alias:   "alice",
						DIDKey:  "did:key:alice-current",
						DIDAW:   "did:aw:alice",
						Address: "test.local/alice",
					},
				},
			})
		case "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
		case "/v1/conversations":
			conversationQuery = r.URL.RawQuery
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{
				{
					ConversationType:     "mail",
					ConversationID:       conversationID,
					Participants:         []string{"gsk", "alice"},
					ParticipantDIDs:      []string{stableID, "did:aw:alice"},
					ParticipantAddresses: []string{"test.local/gsk", "test.local/alice"},
					Subject:              "Ephemeral sender address",
					LastMessageAt:        "2026-05-02T00:00:00Z",
				},
			}})
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-alias-reply",
				"conversation_id": conversationID,
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:01Z",
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

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:       server.URL,
		TeamID:        "devteam:test.local",
		Alias:         "gsk",
		WorkspaceID:   "workspace-1",
		DID:           did,
		Address:       "test.local/gsk",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		SigningKey:    priv,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
		"--to", "alice",
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
	if got := conversationQuery; !strings.Contains(got, "conversation_type=mail") || !strings.Contains(got, "participant_did=did%3Aaw%3Aalice") {
		t.Fatalf("conversation query=%q, want mail participant_did filter", got)
	}
	if got.ConversationID != conversationID {
		t.Fatalf("conversation_id=%q, want %q", got.ConversationID, conversationID)
	}
	if got.ToAlias != "" {
		t.Fatalf("auto-threaded alias reply leaked to_alias=%q", got.ToAlias)
	}
	if got.ToAddress != "" {
		t.Fatalf("to_address=%q, want empty for threaded identity-bound continuation", got.ToAddress)
	}
	if got.ToStableID != "did:aw:alice" {
		t.Fatalf("to_stable_id=%q, want did:aw:alice", got.ToStableID)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != conversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], conversationID)
	}
	if signed["to"] != "did:aw:alice" || signed["to_stable_id"] != "did:aw:alice" {
		t.Fatalf("signed threaded alias reply did not bind participant identity: %+v", signed)
	}
}

func TestAwMailSendAliasToSelfSkipsConversationDiscovery(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)

	type captured struct {
		ToAlias        string `json:"to_alias"`
		ConversationID string `json:"conversation_id"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{
				TeamID: "devteam:test.local",
				Agents: []awid.AgentView{
					{
						AgentID: "self-agent",
						Alias:   "gsk",
						DIDKey:  did,
						DIDAW:   stableID,
						Address: "test.local/gsk",
					},
				},
			})
		case "/v1/conversations", "/v1/messages/inbox":
			t.Fatalf("self-alias send should not discover conversations via %s", r.URL.Path)
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-self",
				"conversation_id": "88888888-8888-4888-8888-888888888888",
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:01Z",
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

	writeSelectionFixtureForTest(t, tmp, testSelectionFixture{
		AwebURL:       server.URL,
		TeamID:        "devteam:test.local",
		Alias:         "gsk",
		WorkspaceID:   "workspace-1",
		DID:           did,
		StableID:      stableID,
		Address:       "test.local/gsk",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		SigningKey:    priv,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
		"--to", "gsk",
		"--subject", "self",
		"--body", "hello from integration test",
	)
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	// aweb-aauz site 2: the --to path prints a different success line, so it needs
	// its own reachability proof. Removing this wiring left the suite green.
	if !strings.Contains(string(out), "Acceptance is not delivery") {
		t.Fatalf("--to path omits the boundary notice:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Sent mail to gsk") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if got.ToAlias != "gsk" {
		t.Fatalf("to_alias=%q, want gsk", got.ToAlias)
	}
	if got.ConversationID == "" {
		t.Fatal("self-alias signed send should include an initial conversation_id")
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != got.ConversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], got.ConversationID)
	}

	// aweb-aauz: --json must stay machine-clean on THIS path. A status line in JSON
	// breaks every downstream parser, and the failure is silent. Asserted per path
	// because a single --json check would inherit the one-of-three reachability
	// coverage this file just fixed - the same defect one layer up.
	runJSON := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext", "--to", "gsk", "--subject", "self", "--body", "hello from integration test", "--json")
	runJSON.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	runJSON.Dir = tmp
	jsonOut, jsonErr := runJSON.CombinedOutput()
	if jsonErr != nil {
		t.Fatalf("to-address --json run failed: %v\n%s", jsonErr, string(jsonOut))
	}
	if strings.Contains(string(jsonOut), "Acceptance is not delivery") {
		t.Fatalf("to-address --json output carries the boundary notice, breaking parsers:\n%s", string(jsonOut))
	}
}

func TestAwMailReplyUsesMessageConversation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := stableIDFromDidForTest(t, did)
	conversationID := "66666666-6666-4666-8666-666666666666"

	type captured struct {
		ToAddress      string `json:"to_address"`
		ToStableID     string `json:"to_stable_id"`
		ConversationID string `json:"conversation_id"`
		Body           string `json:"body"`
		SignedPayload  string `json:"signed_payload"`
	}
	var got captured
	acked := false

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/inbox":
			if r.URL.Query().Get("message_id") != "msg-in" {
				t.Fatalf("message_id query=%q, want msg-in", r.URL.Query().Get("message_id"))
			}
			_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{
				{
					MessageID:      "msg-in",
					ConversationID: conversationID,
					FromAddress:    "otherco.com/bob",
					Subject:        "hello",
					Body:           "hi",
					CreatedAt:      "2026-05-02T00:00:00Z",
				},
			}})
		case "/v1/conversations":
			_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{
				{
					ConversationType:     "mail",
					ConversationID:       conversationID,
					Participants:         []string{"alice", "bob"},
					ParticipantDIDs:      []string{stableID, "did:aw:bob"},
					ParticipantAddresses: []string{"acme.com/alice", "otherco.com/bob"},
				},
			}})
		case "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":      "msg-reply",
				"conversation_id": conversationID,
				"status":          "delivered",
				"delivered_at":    "2026-05-02T00:00:01Z",
			})
		case "/v1/messages/msg-in/ack":
			if r.Method != http.MethodPost {
				t.Fatalf("ack method=%s, want POST", r.Method)
			}
			acked = true
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-in"})
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
		DID:           did,
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "reply", "--plaintext", "msg-in", "--body", "reply")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Sent mail in conversation "+conversationID) {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	// aweb-aauz site 3: mail reply is a separate command with its own output path.
	if !strings.Contains(string(out), "Acceptance is not delivery") {
		t.Fatalf("reply path omits the boundary notice:\n%s", string(out))
	}
	if got.ConversationID != conversationID || got.Body != "reply" {
		t.Fatalf("unexpected body: %+v", got)
	}
	if !acked {
		t.Fatal("reply should ack the source message after sending")
	}
	if got.ToAddress != "" {
		t.Fatalf("to_address=%q, want empty for identity-bound continuation", got.ToAddress)
	}
	if got.ToStableID != "did:aw:bob" {
		t.Fatalf("to_stable_id=%q, want did:aw:bob", got.ToStableID)
	}
	var signed map[string]any
	if err := json.Unmarshal([]byte(got.SignedPayload), &signed); err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if signed["conversation_id"] != conversationID {
		t.Fatalf("signed conversation_id=%v, want %s", signed["conversation_id"], conversationID)
	}
	if signed["to"] != "did:aw:bob" || signed["to_stable_id"] != "did:aw:bob" {
		t.Fatalf("signed reply did not bind rediscovered participant identity: %+v", signed)
	}

	// aweb-aauz: --json must stay machine-clean on THIS path. A status line in JSON
	// breaks every downstream parser, and the failure is silent. Asserted per path
	// because a single --json check would inherit the one-of-three reachability
	// coverage this file just fixed - the same defect one layer up.
	runJSON := exec.CommandContext(ctx, bin, "mail", "reply", "--plaintext", "msg-in", "--body", "reply", "--json")
	runJSON.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	runJSON.Dir = tmp
	jsonOut, jsonErr := runJSON.CombinedOutput()
	if jsonErr != nil {
		t.Fatalf("reply --json run failed: %v\n%s", jsonErr, string(jsonOut))
	}
	if strings.Contains(string(jsonOut), "Acceptance is not delivery") {
		t.Fatalf("reply --json output carries the boundary notice, breaking parsers:\n%s", string(jsonOut))
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
		case "/v1/conversations", "/v1/messages/conversations/" + conversationID:
			http.NotFound(w, r)
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
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
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
		case "/v1/conversations", "/v1/messages/conversations/" + conversationID:
			http.NotFound(w, r)
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
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
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
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
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

func TestAwMailAckByMessageIDJSON(t *testing.T) {
	t.Parallel()

	messageID := "88888888-8888-4888-8888-888888888888"
	var sawAck bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/" + messageID + "/ack":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s, want POST", r.Method)
			}
			sawAck = true
			_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: messageID, AcknowledgedAt: "2026-05-02T00:00:01Z"})
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
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "mail", "ack", messageID, "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawAck {
		t.Fatal("mail ack did not call ack endpoint")
	}
	if !strings.Contains(string(out), messageID) || !strings.Contains(string(out), "acknowledged_at") {
		t.Fatalf("output missing ack fields:\n%s", string(out))
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
	var sawExactMessageRead bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/conversations/" + messageID:
			http.Error(w, `{"detail":"This is a legacy mail without a conversation; use --message-id"}`, http.StatusNotFound)
		case "/v1/messages/" + messageID:
			sawExactMessageRead = true
			_ = json.NewEncoder(w).Encode(awid.InboxMessage{
				MessageID: messageID,
				FromAlias: "athena",
				ToAlias:   "grace",
				Subject:   "legacy",
				Body:      "old mail",
				Priority:  awid.PriorityNormal,
				CreatedAt: "2026-05-02T00:00:00Z",
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
		DID:           did,
		StableID:      stableID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
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
	if !sawExactMessageRead {
		t.Fatal("mail show --message-id did not use the participant-visible exact route")
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

	run := exec.CommandContext(ctx, bin, "mail", "send", "--plaintext",
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

func TestMailAndChatDefaultPlaintextAndE2EEOptInFailsClosed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	var mailBody map[string]any
	var chatBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			if err := json.NewDecoder(r.Body).Decode(&chatBody); err != nil {
				t.Fatalf("decode chat body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{
				SessionID: "session-1",
				MessageID: "chat-1",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
			if err := json.NewDecoder(r.Body).Decode(&mailBody); err != nil {
				t.Fatalf("decode mail body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"message_id":   "mail-1",
				"status":       "delivered",
				"delivered_at": "2026-03-17T12:00:00Z",
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "published"})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			_ = json.NewEncoder(w).Encode(awid.PublishAgentEncryptionKeyResponse{
				AgentID: "workspace-1",
				TeamID:  "backend:demo",
				Alias:   "alice",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{
				TeamID: "backend:demo",
				Agents: []awid.AgentView{{
					AgentID: "agent-alice",
					Alias:   "alice",
					DIDKey:  "did:key:z6Mkalice",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "mail", args: []string{"mail", "send", "--to", "alice", "--body", "hello"}},
		{name: "chat", args: []string{"chat", "send-and-leave", "alice", "hello"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := exec.CommandContext(ctx, bin, tc.args...)
			run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("expected default plaintext success, got failure: %v\n%s", err, string(out))
			}
		})
	}
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{name: "mail", body: mailBody},
		{name: "chat", body: chatBody},
	} {
		if tc.body == nil {
			t.Fatalf("%s default send did not reach server", tc.name)
		}
		if got := tc.body["content_mode"]; got == "encrypted_v2" {
			t.Fatalf("%s default send unexpectedly used encrypted_v2: %#v", tc.name, tc.body)
		}
		if _, ok := tc.body["encrypted_envelope"]; ok {
			t.Fatalf("%s default send unexpectedly included encrypted_envelope: %#v", tc.name, tc.body)
		}
	}

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "mail", args: []string{"mail", "send", "--e2ee", "--to", "alice", "--body", "hello"}},
		{name: "chat", args: []string{"chat", "send-and-leave", "--e2ee", "alice", "hello"}},
	} {
		t.Run(tc.name+"_e2ee_opt_in", func(t *testing.T) {
			run := exec.CommandContext(ctx, bin, tc.args...)
			run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
			run.Dir = tmp
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected explicit E2E failure for old recipient without encryption key, got success:\n%s", string(out))
			}
			if !strings.Contains(string(out), "has no E2E encryption key") &&
				!strings.Contains(string(out), "has no published E2E encryption key") {
				t.Fatalf("expected explicit E2E recipient-key error, got:\n%s", string(out))
			}
		})
	}
}

// The send path reports that the server accepted a message. It cannot report
// delivery, presentation, or any recipient's trust verdict: the first two are
// not returned to a sender, and the third is computed per-recipient-machine
// against a local pin store the sender cannot see (aweb-aauz).
//
// So the notice is a statement of LIMITS, not a warning. At send time nothing
// is known to be wrong, and an alert would imply knowledge we do not have.
func TestMailSendBoundaryNoticeStatesWhatAcceptanceDoesNotEstablish(t *testing.T) {
	notice := mailSendBoundaryNotice()

	if strings.TrimSpace(notice) == "" {
		t.Fatal("boundary notice is empty; acceptance by the server would read as delivery")
	}

	// Each clause the sender must not infer from exit 0.
	for _, want := range []string{"deliver", "present", "trust"} {
		if !strings.Contains(strings.ToLower(notice), want) {
			t.Errorf("notice does not mention %q, so a reader cannot tell that acceptance excludes it:\n%s", want, notice)
		}
	}

	// It must attribute what IS established to the server, or "accepted" is unanchored.
	if !strings.Contains(strings.ToLower(notice), "server") {
		t.Errorf("notice does not say WHO accepted the message:\n%s", notice)
	}

	// A statement of limits, not an alert. Alarm words imply a detected problem.
	for _, banned := range []string{"warning", "error", "failed", "problem"} {
		if strings.Contains(strings.ToLower(notice), banned) {
			t.Errorf("notice uses alarm word %q; at send time nothing is known to be wrong:\n%s", banned, notice)
		}
	}
}
