package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// aweb-aava's sibling defect, aweb-aayg. `aw mail show --conversation-id` returns at
// most --limit messages, defaulting to 200, and takes them from the OLDEST end. On a
// 282-message conversation it returned the oldest 200 and printed "(200 messages)",
// which is indistinguishable from a complete 200-message conversation. The command
// was the team's designated safe read for "did I miss something recent", so the
// truncation was aimed exactly at the messages the question was about.
//
// The response carries no total and no has_more, so the CLI cannot say "200 of 282".
// What it CAN establish is that it asked for N and got N, which means there may be
// more. That is stated rather than a completeness it cannot verify.

func conversationOfSize(n int) *awid.InboxResponse {
	resp := &awid.InboxResponse{}
	for i := 0; i < n; i++ {
		resp.Messages = append(resp.Messages, awid.InboxMessage{
			ConversationID: "conv-1",
			FromAlias:      "alice",
			Subject:        "s",
			Body:           "b",
		})
	}
	return resp
}

func TestMailConversationSaysWhenItMayBeAWindow(t *testing.T) {
	restore := mailShowLimit
	t.Cleanup(func() { mailShowLimit = restore })
	mailShowLimit = 200

	got := formatMailConversation(conversationOfSize(200))

	// A bare "(200 messages)" does not satisfy this: it reads as the size of the
	// conversation rather than the size of the window.
	if !strings.Contains(got, "200 messages") {
		t.Fatalf("header lost the count:\n%s", got)
	}
	lower := strings.ToLower(got)
	if !strings.Contains(lower, "limit") {
		t.Fatalf("a full window does not mention the limit that produced it, so a truncated read looks complete:\n%s", got)
	}
	// Which end it took. A reader who does not know this will re-run with a higher
	// limit and still not understand why recent messages were missing.
	if !strings.Contains(lower, "oldest") {
		t.Fatalf("output does not say which end the window took:\n%s", got)
	}
}

func TestMailConversationDoesNotCryWolfWhenItIsComplete(t *testing.T) {
	restore := mailShowLimit
	t.Cleanup(func() { mailShowLimit = restore })
	mailShowLimit = 200

	got := formatMailConversation(conversationOfSize(3))

	lower := strings.ToLower(got)
	// A warning on every listing is a warning nobody reads. Fewer results than the
	// limit proves the window was not the binding constraint.
	if strings.Contains(lower, "may be more") || strings.Contains(lower, "truncat") {
		t.Fatalf("a complete conversation was reported as possibly windowed:\n%s", got)
	}
}

// The remedy has to be in the message. Knowing a read was partial without knowing
// how to complete it leaves the reader exactly as stuck.
func TestMailConversationWindowNoticeNamesTheRemedy(t *testing.T) {
	restore := mailShowLimit
	t.Cleanup(func() { mailShowLimit = restore })
	mailShowLimit = 200

	got := formatMailConversation(conversationOfSize(200))

	if !strings.Contains(got, "--limit") {
		t.Fatalf("the notice does not name --limit as the way to see more:\n%s", got)
	}
}

// The remedy has a ceiling, and a notice that omits it sends the reader into an
// HTTP 422 they will read as the command being broken. Measured directly against a
// live server: --limit 500 is accepted, --limit 501 returns
// "Input should be less than or equal to 500". So a conversation longer than 500
// cannot be returned whole by this command, and there is no paging flag.
func TestMailConversationWindowNoticeNamesTheCeiling(t *testing.T) {
	restore := mailShowLimit
	t.Cleanup(func() { mailShowLimit = restore })
	mailShowLimit = 200

	got := formatMailConversation(conversationOfSize(200))

	if !strings.Contains(got, "500") {
		t.Fatalf("the notice tells the reader to raise --limit without naming the 500 ceiling, so following it on a long thread produces an HTTP 422:\n%s", got)
	}
}

func TestMailConversationExactLimitLanguageStaysConditional(t *testing.T) {
	for surface, got := range map[string]string{
		"window notice": mailWindowNotice(200, 200),
		"command help":  mailShowCmd.Long,
	} {
		t.Run(surface, func(t *testing.T) {
			lower := strings.ToLower(got)
			if !strings.Contains(lower, "may") {
				t.Fatalf("%s does not state the one-sided inference conditionally:\n%s", surface, got)
			}
			if strings.Contains(lower, "you were truncated") {
				t.Fatalf("%s claims truncation is proven when returned == limit can also be an exact-size conversation:\n%s", surface, got)
			}
		})
	}
}

func TestMailConversationAtCeilingDoesNotRecommendAnImpossibleRerun(t *testing.T) {
	got := strings.ToLower(mailWindowNotice(500, 500))

	if strings.Contains(got, "higher --limit") || strings.Contains(got, "re-run") {
		t.Fatalf("the notice recommends a request above the server's 500 ceiling:\n%s", got)
	}
	if !strings.Contains(got, "cannot be established") || !strings.Contains(got, "no pagination") {
		t.Fatalf("the ceiling notice does not explain why completeness cannot be established:\n%s", got)
	}
}

// An exact-message read is one complete message, never an oldest-end window.
func TestMailShowExactMessageDoesNotReportAConversationWindow(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	messageID := "99999999-9999-4999-8999-999999999999"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/" + messageID:
			_ = json.NewEncoder(w).Encode(awid.InboxMessage{
				MessageID: messageID,
				FromAlias: "alice",
				Subject:   "exact",
				Body:      "one message",
				Priority:  awid.PriorityNormal,
				CreatedAt: "2026-05-02T00:00:00Z",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           did,
		StableID:      stableIDFromDidForTest(t, did),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "show", "--message-id", messageID, "--limit", "1")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("run failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	combined := strings.ToLower(stdout.String() + stderr.String())
	if !strings.Contains(combined, "one message") {
		t.Fatalf("exact message was not rendered:\n%s", combined)
	}
	for _, forbidden := range []string{"oldest", "may be more", "higher --limit", "500-message"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("exact-message read was mislabeled with conversation-window guidance %q:\n%s", forbidden, combined)
		}
	}
}

// The JSON path is where getting this wrong is worst: a notice written to stdout
// would corrupt the document every machine consumer parses. It goes to stderr, so
// stdout stays a clean JSON body and a human still sees the warning.
func TestMailShowJSONKeepsStdoutCleanAndWarnsOnStderr(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	conversationID := "88888888-8888-4888-8888-888888888888"

	const limit = 3
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/messages/conversations/" + conversationID:
			// Exactly the limit: the shape that means "there may be more".
			resp := awid.InboxResponse{}
			for i := 0; i < limit; i++ {
				resp.Messages = append(resp.Messages, awid.InboxMessage{
					MessageID:      fmt.Sprintf("msg-%d", i),
					ConversationID: conversationID,
					FromAlias:      "alice",
					Subject:        "s",
					Body:           "b",
					Priority:       awid.PriorityNormal,
					CreatedAt:      "2026-05-02T00:00:00Z",
				})
			}
			_ = json.NewEncoder(w).Encode(resp)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeIdentityForTest(t, tmp, awconfig.WorktreeIdentity{
		DID:           did,
		StableID:      stableIDFromDidForTest(t, did),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-05-02T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), priv); err != nil {
		t.Fatalf("write signing key: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "mail", "show",
		"--conversation-id", conversationID, "--limit", fmt.Sprint(limit), "--json")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	run.Dir = tmp
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("run failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON, so the notice corrupted the machine-readable output: %v\n%s", err, stdout.String())
	}
	if _, ok := parsed["messages"]; !ok {
		t.Fatalf("stdout JSON has no messages key:\n%s", stdout.String())
	}
	if !strings.Contains(strings.ToLower(stderr.String()), "oldest") {
		t.Fatalf("stderr carries no window notice, so a JSON consumer gets a partial read with no warning at all:\nstderr:\n%s", stderr.String())
	}
}
