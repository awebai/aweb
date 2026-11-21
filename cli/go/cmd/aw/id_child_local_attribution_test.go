package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHumanApprovalExplainsLocalAttributionBeforeSigning(t *testing.T) {
	run := newResignRun(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer server.Close()
	run.alice.RegistryURL = server.URL
	if err := awconfig.SaveHumanRecord(run.alice); err != nil {
		t.Fatal(err)
	}
	opts := run.issuerOpts()
	var shown bytes.Buffer
	opts.Show = &shown
	invitation, err := executeIDChildInvite(t.Context(), opts, "agent", "local child", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	key, err := awid.LoadSigningKey(filepath.Join(run.childDir, ".aw", "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(run.childDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := newInvitationID()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := awid.SignIDCertificateRequest(map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": requestID, "operation": "issue",
		"id": identity.DID, "subject_key": identity.DID, "domain": invitation.Domain,
		"kind": "agent", "parent": invitation.Parent, "invitation_id": invitation.InvitationID, "old_certificate": nil,
	}, awid.KeySigner(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeIDChildReceive(t.Context(), opts, raw); err != nil {
		t.Fatal(err)
	}
	response, err := executeIDChildApprove(t.Context(), opts, requestID)
	if err == nil || response != nil {
		t.Fatal("unavailable status signed a certificate")
	}
	const want = "This agent is unregistered; your signature attributes it to you, and nothing prevents it from also holding another person's signature.\n"
	if shown.String() != want {
		t.Fatalf("attribution notice=%q", shown.String())
	}
	if run.prompts != 0 {
		t.Fatal("signing started before evidence was available")
	}
	if bytes.Contains(shown.Bytes(), []byte("PRIVATE")) {
		t.Fatal("private material in notice")
	}
	// The refusal leaves the received request available for a real retry.
	state, err := showIDChildRequest(t.Context(), opts, requestID)
	if err != nil || state.State != awid.IDRequestPending {
		t.Fatalf("pending=%+v err=%v", state, err)
	}
	if _, err := os.Stat(filepath.Join(run.childDir, ".aw", "signing.key")); err != nil {
		t.Fatal(err)
	}
}
