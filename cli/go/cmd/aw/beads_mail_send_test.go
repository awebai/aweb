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

func TestBeadsMailEnvelope(t *testing.T) {
	if got := appendBeadsMailEnvelope("plain body", beadsMailEnvelope{}); got != "plain body" {
		t.Errorf("default envelope changed the body: %q", got)
	}
	p := 1
	got := appendBeadsMailEnvelope("body", beadsMailEnvelope{Type: "task", Priority: &p})
	if !strings.Contains(got, "```beads-mail\n") || !strings.Contains(got, `"type":"task"`) || !strings.Contains(got, `"priority":1`) {
		t.Errorf("envelope missing fields:\n%s", got)
	}
	if !strings.HasPrefix(got, "body\n\n```beads-mail") {
		t.Errorf("envelope not appended after the body:\n%s", got)
	}
}

func TestBeadsMailDispatchSplit(t *testing.T) {
	// §5: alias sends cert-authenticated ONLY for a fresh conversation;
	// every continuation goes by identity so the signed sender is the
	// workspace identity, never a team-local alias.
	cases := []struct {
		kind, conversation string
		cert               bool
	}{
		{"alias", "", true},
		{"alias", "conv-1", false},
		{"address", "", false},
		{"address", "conv-1", false},
		{"did", "", false},
	}
	for _, tc := range cases {
		if got := beadsMailUsesCertSend(tc.kind, tc.conversation); got != tc.cert {
			t.Errorf("kind=%s conversation=%q: cert=%v want %v", tc.kind, tc.conversation, got, tc.cert)
		}
	}
}

func TestBeadsMailPriorityMapping(t *testing.T) {
	want := map[int]awid.MessagePriority{
		0: awid.PriorityUrgent,
		1: awid.PriorityHigh,
		2: awid.PriorityNormal,
		3: awid.PriorityLow,
		4: awid.PriorityLow,
	}
	for beads, aweb := range want {
		if got := beadsMailPriorityToAweb(beads); got != aweb {
			t.Errorf("priority %d -> %s, want %s", beads, got, aweb)
		}
	}
}

// beadsMailSendReplyHarness builds the production binary once and stands up a
// local server capturing what the delegate sends. The identity-home evidence
// bar (identity_home_policy.go): these verbs consume the workspace identity in
// cwd; the harness proves the requests go to that identity's server signed
// with its key, and that no conversation auto-discovery happens.
func TestBeadsMailSendAndReplyAgainstLocalServer(t *testing.T) {
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

	type sentRequest struct {
		ToAddress      string `json:"to_address"`
		ConversationID string `json:"conversation_id"`
		Subject        string `json:"subject"`
		Body           string `json:"body"`
		Priority       string `json:"priority"`
		FromDID        string `json:"from_did"`
	}
	var sends []sentRequest
	var sendFromDIDs []string
	var conversationListCalls, ackCalls int
	sourceMessage := awid.InboxMessage{
		MessageID:      "33333333-3333-4333-8333-333333333333",
		ConversationID: "44444444-4444-4444-8444-444444444444",
		Subject:        "Hello there",
		Body:           "original",
		FromAddress:    "acme.example/mayor",
		FromDID:        recipientDID,
		ToDID:          did,
	}

	server := newLocalHTTPServerWithURL(t, func(serverURL string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/v1/conversations":
				conversationListCalls++
				_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{})
			case r.URL.Path == "/v1/messages/inbox":
				if r.URL.Query().Get("message_id") == sourceMessage.MessageID {
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{sourceMessage}})
					return
				}
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{})
			case r.URL.Path == "/v1/messages/conversations/"+sourceMessage.ConversationID:
				// The client rediscovers the recipient from the conversation
				// when sending a continuation without an explicit target.
				_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{sourceMessage}})
			case r.URL.Path == "/v1/namespaces/acme.example/addresses/mayor":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"address_id":      "addr-mayor",
					"domain":          "acme.example",
					"name":            "mayor",
					"did_aw":          "did:aw:mayor",
					"current_did_key": recipientDID,
					"reachability":    "public",
					"created_at":      "2026-08-31T00:00:00Z",
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
				sendFromDIDs = append(sendFromDIDs, got.FromDID)
				_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{
					MessageID:      "55555555-5555-4555-8555-555555555555",
					ConversationID: "66666666-6666-4666-8666-666666666666",
					Status:         "delivered",
					DeliveredAt:    "2026-08-31T00:00:00Z",
				})
			case strings.HasSuffix(r.URL.Path, "/ack"):
				ackCalls++
				_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: sourceMessage.MessageID, AcknowledgedAt: "2026-08-31T00:00:00Z"})
			case r.URL.Path == "/v1/agents/heartbeat":
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected path %s %s", r.Method, r.URL.Path)
				http.Error(w, "unexpected", http.StatusNotFound)
			}
		})
	})

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
	mapContent := "[addresses]\n\"mayor/\" = \"acme.example/mayor\"\n"
	if err := os.WriteFile(filepath.Join(tmp, ".beads", beadsMailMapFileName), []byte(mapContent), 0o600); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, append([]string{"beads-mail"}, args...)...)
		cmd.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
		cmd.Dir = tmp
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// Send to a mapped rig name: priority 1 maps to high, --type rides the
	// envelope, the disclosure line names the resolved address, and no
	// conversation auto-discovery happens.
	out, err := run("send", "mayor/", "-s", "Water levels", "-m", "the well is low", "--priority", "1", "--type", "task")
	if err != nil {
		t.Fatalf("send failed: %v\n%s", err, out)
	}
	if len(sends) != 1 {
		t.Fatalf("send count=%d", len(sends))
	}
	sent := sends[0]
	// A fresh signed send mints a NEW conversation id client-side
	// (awid/mail.go GenerateUUID4 path); what the design record forbids is
	// silently continuing an EXISTING conversation.
	if sent.ToAddress != "acme.example/mayor" || sent.Priority != "high" || sent.Subject != "Water levels" ||
		sent.ConversationID == "" || sent.ConversationID == sourceMessage.ConversationID {
		t.Errorf("send request %+v", sent)
	}
	if !strings.Contains(sent.Body, "the well is low") || !strings.Contains(sent.Body, "```beads-mail") ||
		!strings.Contains(sent.Body, `"type":"task"`) || !strings.Contains(sent.Body, `"priority":1`) {
		t.Errorf("send body:\n%s", sent.Body)
	}
	if !strings.Contains(out, "to mayor/ -> acme.example/mayor") || !strings.Contains(out, "message_id=") {
		t.Errorf("disclosure output:\n%s", out)
	}
	if conversationListCalls != 0 {
		t.Errorf("send performed conversation auto-discovery (%d calls); the design record forbids it", conversationListCalls)
	}

	// Default send stays plain: no envelope block.
	if out, err := run("send", "mayor/", "-s", "plain", "-m", "nothing special"); err != nil {
		t.Fatalf("plain send failed: %v\n%s", err, out)
	}
	if body := sends[len(sends)-1].Body; strings.Contains(body, "beads-mail") {
		t.Errorf("default send grew an envelope:\n%s", body)
	}

	// Envelope flags: --permanent marks ephemeral:false, --pinned rides
	// along; an explicit --wisp=true (the default restated) emits nothing.
	if out, err := run("send", "mayor/", "-s", "keep", "-m", "handoff", "--permanent", "--pinned"); err != nil {
		t.Fatalf("permanent send failed: %v\n%s", err, out)
	}
	if body := sends[len(sends)-1].Body; !strings.Contains(body, `"ephemeral":false`) || !strings.Contains(body, `"pinned":true`) {
		t.Errorf("permanent/pinned envelope:\n%s", body)
	}
	if out, err := run("send", "mayor/", "-s", "w", "-m", "x", "--wisp=true"); err != nil {
		t.Fatalf("wisp send failed: %v\n%s", err, out)
	}
	if body := sends[len(sends)-1].Body; strings.Contains(body, "beads-mail") {
		t.Errorf("explicit default --wisp=true grew an envelope:\n%s", body)
	}

	// send --reply-to continues the source's conversation exactly.
	if out, err := run("send", "mayor/", "-s", "follow-up", "-m", "more", "--reply-to", sourceMessage.MessageID); err != nil {
		t.Fatalf("reply-to send failed: %v\n%s", err, out)
	}
	if got := sends[len(sends)-1]; got.ConversationID != sourceMessage.ConversationID {
		t.Errorf("--reply-to conversation=%q want %q", got.ConversationID, sourceMessage.ConversationID)
	}

	// Reply: continues the source conversation, subject defaults to
	// Re: <original>, and the source message is acked.
	out, err = run("reply", sourceMessage.MessageID, "-m", "on it")
	if err != nil {
		t.Fatalf("reply failed: %v\n%s", err, out)
	}
	replySent := sends[len(sends)-1]
	if replySent.ConversationID != sourceMessage.ConversationID || replySent.Subject != "Re: Hello there" || replySent.Body != "on it" {
		t.Errorf("reply request %+v", replySent)
	}
	if ackCalls != 1 {
		t.Errorf("ack calls=%d", ackCalls)
	}

	// Identity-home consumption evidence (the bar stated in
	// beads_mail_test.go): with an external principal selected, the send is
	// signed as the PRINCIPAL identity, not the shadow identity sitting in
	// the instance directory.
	principalPub, principalPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	principalRoot := filepath.Join(tmp, "principal-root")
	writeIdentityForTest(t, principalRoot, awconfig.WorktreeIdentity{
		DID:           principalDID,
		StableID:      stableIDFromDidForTest(t, principalDID),
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		RegistryURL:   server.URL,
		CreatedAt:     "2026-08-31T00:00:00Z",
	})
	if err := awid.SaveSigningKey(filepath.Join(principalRoot, ".aw", "signing.key"), principalPriv); err != nil {
		t.Fatal(err)
	}
	principalSendCount := len(sendFromDIDs)
	cmdExternal := exec.CommandContext(ctx, bin, "--identity-home", filepath.Join(principalRoot, ".aw"),
		"beads-mail", "send", "mayor/", "-s", "principal speaks", "-m", "hello")
	cmdExternal.Env = append(testCommandEnv(tmp), "AWEB_URL="+server.URL)
	cmdExternal.Dir = tmp
	if out, err := cmdExternal.CombinedOutput(); err != nil {
		t.Fatalf("external-principal send failed: %v\n%s", err, out)
	}
	if len(sendFromDIDs) != principalSendCount+1 {
		t.Fatalf("external-principal send not captured")
	}
	if got := sendFromDIDs[len(sendFromDIDs)-1]; got != principalDID {
		t.Errorf("external-principal send signed as %q, want principal %q (shadow was %q)", got, principalDID, did)
	}

	// --self sends work, and a malformed address map must not break them:
	// --self never consults the map (dual-write just stays off).
	if out, err := run("send", "--self", "-s", "note to self", "-m", "remember"); err != nil {
		t.Fatalf("--self send failed: %v\n%s", err, out)
	}
	mapPath := filepath.Join(tmp, ".beads", beadsMailMapFileName)
	goodMap, err := os.ReadFile(mapPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mapPath, []byte("this is not the format"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("send", "--self", "-s", "still works", "-m", "x"); err != nil {
		t.Fatalf("--self with broken map failed: %v\n%s", err, out)
	}
	if out, err := run("send", "mayor/", "-s", "x", "-m", "x"); err == nil {
		t.Fatalf("mapped send with broken map succeeded:\n%s", out)
	}
	if err := os.WriteFile(mapPath, goodMap, 0o600); err != nil {
		t.Fatal(err)
	}

	// The comm log records delegate sends, which is what makes the search
	// verb's aw log fallback true. Logs live under user state, rooted at the
	// test HOME.
	foundLogged := false
	_ = filepath.WalkDir(tmp, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
			return nil
		}
		if content, readErr := os.ReadFile(path); readErr == nil && strings.Contains(string(content), "the well is low") {
			foundLogged = true
		}
		return nil
	})
	if !foundLogged {
		t.Errorf("delegate send not found in any comm log under %s", tmp)
	}
}
