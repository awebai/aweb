package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func testCustodyService(t *testing.T, residentKey, sessionKey ed25519.PrivateKey) *custodyService {
	t.Helper()
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	sessionDID := awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey))
	return &custodyService{
		serviceID: "test-service",
		identity: &awconfig.ResolvedIdentity{
			DID: residentDID, StableID: "did:aw:alice", Address: "acme.com/alice", Handle: "alice",
		},
		signingKey: residentKey,
		now:        time.Now,
		replay:     map[string]string{},
		replayAt:   map[string]time.Time{},
		results:    map[string]any{},
		grantStatus: func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
			return custodyGrantStatus{Active: true, Scopes: []string{"mail.read", "mail.send", "chat.read", "chat.send"}, GrantDIDKey: sessionDID, TeamID: "backend:acme.com", Status: "active", EffectiveStatus: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
		},
	}
}

func signedCustodyRequest(t *testing.T, sessionKey ed25519.PrivateKey, residentDID string) *awid.PlainMessageSignRequest {
	t.Helper()
	req := &awid.PlainMessageSignRequest{
		Version:       1,
		Operation:     "sign_plain_message",
		GrantID:       "11111111-1111-4111-8111-111111111111",
		SessionDIDKey: awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)),
		TeamID:        "backend:acme.com",
		SubjectDIDAW:  "did:aw:alice",
		SubjectDIDKey: residentDID,
		Audience:      "local-resident-custody:test-service",
		Envelope: awid.MessageEnvelope{
			From: "acme.com/alice", To: "acme.com/bob", Type: "mail", Subject: "hello", Body: "body",
		},
	}
	if err := awid.SignCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCustodySignPlainMessageBuildsStructuredEnvelopeAndReplaysSafely(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	svc := testCustodyService(t, residentKey, sessionKey)
	req := signedCustodyRequest(t, sessionKey, residentDID)

	out, err := svc.signPlainMessage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if out.FromDID != residentDID || out.SigningKeyID != residentDID {
		t.Fatalf("signed as %q/%q, want resident %q", out.FromDID, out.SigningKeyID, residentDID)
	}
	status, err := awid.VerifySignedPayload(out.SignedPayload, out.Signature, out.FromDID, out.SigningKeyID)
	if err != nil || status != awid.Verified {
		t.Fatalf("verify status=%s err=%v", status, err)
	}
	if strings.Contains(out.SignedPayload, "body_sha256") {
		t.Fatalf("signed request-auth-shaped payload: %s", out.SignedPayload)
	}

	identityAuthShape := `{"body_sha256":"abc","did_aw":"did:aw:alice","timestamp":"2026-01-01T00:00:00Z"}`
	oracleReq := signedCustodyRequest(t, sessionKey, residentDID)
	oracleReq.Envelope.Body = identityAuthShape
	if err := awid.SignCustodyProof(sessionKey, oracleReq); err != nil {
		t.Fatal(err)
	}
	oracleOut, err := svc.signPlainMessage(context.Background(), oracleReq)
	if err != nil {
		t.Fatal(err)
	}
	if oracleOut.SignedPayload == identityAuthShape || !strings.Contains(oracleOut.SignedPayload, `"type":"mail"`) || !strings.Contains(oracleOut.SignedPayload, `"from_did"`) || !strings.Contains(oracleOut.SignedPayload, `"to"`) {
		t.Fatalf("custody signed oracle-shaped bytes instead of message envelope: %s", oracleOut.SignedPayload)
	}

	retry, err := svc.signPlainMessage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Signature != out.Signature || retry.SignedPayload != out.SignedPayload {
		t.Fatal("exact retry did not return cached result")
	}

	changed := *req
	changed.Envelope.Body = "changed"
	if err := awid.SignCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Nonce = req.Nonce
	if _, err := svc.signPlainMessage(context.Background(), &changed); err == nil || err.Error() != "replay_detected" {
		t.Fatalf("err=%v, want replay_detected", err)
	}
}

func TestCustodySignPlainMessageRejectsWrongAudienceRestartReplayAndFromMismatch(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	svc := testCustodyService(t, residentKey, sessionKey)

	wrongAudience := signedCustodyRequest(t, sessionKey, residentDID)
	wrongAudience.Audience = "local-resident-custody:other-service"
	if err := awid.SignCustodyProof(sessionKey, wrongAudience); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signPlainMessage(context.Background(), wrongAudience); err == nil || err.Error() != "bad_audience" {
		t.Fatalf("err=%v, want bad_audience", err)
	}

	fromMismatch := signedCustodyRequest(t, sessionKey, residentDID)
	fromMismatch.Envelope.From = "acme.com/mallory"
	if err := awid.SignCustodyProof(sessionKey, fromMismatch); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signPlainMessage(context.Background(), fromMismatch); err == nil || err.Error() != "message_not_allowed" {
		t.Fatalf("err=%v, want message_not_allowed", err)
	}

	oldRun := signedCustodyRequest(t, sessionKey, residentDID)
	svc.serviceID = "new-service"
	if _, err := svc.signPlainMessage(context.Background(), oldRun); err == nil || err.Error() != "bad_audience" {
		t.Fatalf("err=%v, want bad_audience", err)
	}
}

func TestCustodySignPlainMessageRejectsOracleShapesAndUnknownFields(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	svc := testCustodyService(t, residentKey, sessionKey)
	for _, body := range []string{
		`{"body_sha256":"abc","did_aw":"did:aw:alice","timestamp":"2026-01-01T00:00:00Z"}`,
		`{"body_sha256":"abc","team_id":"backend:acme.com","timestamp":"2026-01-01T00:00:00Z"}`,
		`{"op":"rotate_key","new_did":"did:key:zBad"}`,
		`{"grant_id":"g","delegate":"did:key:zBad"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/sign_plain_message", bytes.NewBufferString(body))
		rr := httptest.NewRecorder()
		svc.handleSignPlainMessage(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("body %s status=%d", body, rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "message_not_allowed") {
			t.Fatalf("body %s response=%s", body, rr.Body.String())
		}
	}

	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	req := signedCustodyRequest(t, sessionKey, residentDID)
	data, _ := json.Marshal(req)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	env := raw["envelope"].(map[string]any)
	env["unexpected"] = "x"
	data, _ = json.Marshal(raw)
	rr := httptest.NewRecorder()
	svc.handleSignPlainMessage(rr, httptest.NewRequest(http.MethodPost, "/sign_plain_message", bytes.NewReader(data)))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "message_not_allowed") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCustodyGrantStatusClientRequiresAuthoritativeStatusAndProbe(t *testing.T) {
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/status") {
			_, _ = w.Write([]byte(`{"grant_id":"g","team_id":"backend:acme.com","grant_did_key":"did:key:zSession","scopes":["mail.send"],"status":"active"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer legacy.Close()
	legacyClient, err := aweb.New(legacy.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := grantStatusViaClient(legacyClient)(context.Background(), "11111111-1111-4111-8111-111111111111"); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("legacy status err=%v, want incompatible", err)
	}

	typedProbe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"grant_not_found","contract":"identity-grant-status.v1"}`))
	}))
	defer typedProbe.Close()
	typedClient, err := aweb.New(typedProbe.URL)
	if err != nil {
		t.Fatal(err)
	}
	if checkedAt, err := typedClient.ProbeIdentityGrantStatus(context.Background()); err != nil || checkedAt == "" {
		t.Fatalf("typed probe checkedAt=%q err=%v", checkedAt, err)
	}

	genericProbe := httptest.NewServer(http.NotFoundHandler())
	defer genericProbe.Close()
	genericClient, err := aweb.New(genericProbe.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genericClient.ProbeIdentityGrantStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "incompatible") {
		t.Fatalf("generic probe err=%v, want incompatible", err)
	}
}

func TestCustodyGrantValidationFailsClosedOnEffectiveStatusExpiryBindingAndFreshness(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	svc := testCustodyService(t, residentKey, sessionKey)
	req := signedCustodyRequest(t, sessionKey, residentDID)

	cases := []struct {
		name string
		st   custodyGrantStatus
		want string
	}{
		{"issuer revoked", custodyGrantStatus{Active: false, EffectiveStatus: "issuer_revoked"}, "grant_issuer_revoked"},
		{"subject inactive", custodyGrantStatus{Active: false, EffectiveStatus: "subject_inactive"}, "grant_subject_inactive"},
		{"expired locally", custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: req.TeamID, GrantDIDKey: req.SessionDIDKey, Scopes: []string{"mail.send"}, ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}, "grant_expired"},
		{"bad expiry", custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: req.TeamID, GrantDIDKey: req.SessionDIDKey, Scopes: []string{"mail.send"}, ExpiresAt: "not-a-time"}, "grant_freshness_unavailable"},
		{"session mismatch", custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: req.TeamID, GrantDIDKey: "did:key:zOther", Scopes: []string{"mail.send"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, "grant_session_mismatch"},
		{"team mismatch", custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: "ops:acme.com", GrantDIDKey: req.SessionDIDKey, Scopes: []string{"mail.send"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, "grant_team_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc.replay = map[string]string{}
			svc.replayAt = map[string]time.Time{}
			svc.results = map[string]any{}
			svc.grantStatus = func(context.Context, string) (custodyGrantStatus, error) { return tc.st, nil }
			if _, err := svc.signPlainMessage(context.Background(), req); err == nil || err.Error() != tc.want {
				t.Fatalf("err=%v, want %s", err, tc.want)
			}
		})
	}

	svc.grantStatus = func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
		<-ctx.Done()
		return custodyGrantStatus{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := svc.signPlainMessage(ctx, req); err == nil || err.Error() != "grant_freshness_unavailable" {
		t.Fatalf("err=%v, want grant_freshness_unavailable", err)
	}
}

func TestCustodyReplayEntriesEvictAfterAcceptedWindow(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	now := time.Now().UTC()
	svc := testCustodyService(t, residentKey, sessionKey)
	svc.now = func() time.Time { return now }
	req := signedCustodyRequest(t, sessionKey, residentDID)
	req.Timestamp = now.Format(time.RFC3339)
	if err := awid.SignCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signPlainMessage(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(svc.replay) != 1 || len(svc.results) != 1 {
		t.Fatalf("replay/result not recorded")
	}
	now = now.Add(3 * time.Minute)
	changed := signedCustodyRequest(t, sessionKey, residentDID)
	changed.Nonce = req.Nonce
	changed.Timestamp = now.Format(time.RFC3339)
	changed.Envelope.Body = "after eviction"
	if err := awid.SignCustodyProof(sessionKey, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.signPlainMessage(context.Background(), changed); err != nil {
		t.Fatalf("old replay slot was not evicted: %v", err)
	}
	if len(svc.replay) != 1 || len(svc.results) != 1 {
		t.Fatalf("old replay entries not evicted: replay=%d results=%d", len(svc.replay), len(svc.results))
	}
}

func TestCustodyStatusContainsOnlySafeReadiness(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	svc := testCustodyService(t, residentKey, sessionKey)
	svc.socketPath = "/tmp/custody.sock"
	status := svc.status(context.Background(), "running", nil)
	b, _ := json.Marshal(status)
	text := string(b)
	if !strings.Contains(text, "signing_ready") || strings.Contains(text, string(residentKey)) {
		t.Fatalf("unsafe status: %s", text)
	}
	if !strings.Contains(text, `"did_aw"`) || !strings.Contains(text, `"did_key"`) || strings.Contains(text, "DIDAW") || strings.Contains(text, "DIDKey") {
		t.Fatalf("status json field names are not OATS-ready: %s", text)
	}
	if status.Keys["encryption_ready"] != false {
		t.Fatalf("encryption readiness must remain false: %#v", status.Keys)
	}

	if len(status.Teams) != 0 {
		t.Fatalf("status invented team readiness without certificates: %#v", status.Teams)
	}
	identityHome := t.TempDir()
	_, teamKey, _ := ed25519.GenerateKey(nil)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: svc.identity.DID, MemberDIDAW: svc.identity.StableID, MemberAddress: svc.identity.Address, Alias: "alice", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(identityHome, "backend:acme.com", cert); err != nil {
		t.Fatal(err)
	}
	svc.residentHome = identityHome
	svc.readinessCheck = func(context.Context) (string, error) { return "2026-09-24T00:00:00Z", nil }
	ready := svc.status(context.Background(), "running", nil)
	if ready.Keys["signing_ready"] != true || ready.Freshness["last_checked_at"] == nil || len(ready.Teams) != 1 || ready.Teams[0]["certificate_present"] != true {
		t.Fatalf("status did not use real readiness and cert checks: keys=%#v freshness=%#v teams=%#v", ready.Keys, ready.Freshness, ready.Teams)
	}
	svc.readinessCheck = func(context.Context) (string, error) { return "", context.DeadlineExceeded }
	failed := svc.status(context.Background(), "running", nil)
	if failed.Keys["signing_ready"] != false || len(failed.Errors) == 0 || failed.Errors[0] != "grant_status_unavailable" {
		t.Fatalf("status did not fail closed on readiness error: %#v errors=%v", failed.Keys, failed.Errors)
	}
}

func TestCustodyStatusUnavailableUsesStableErrorCode(t *testing.T) {
	status := custodyUnavailableStatus("/tmp/missing.sock")
	if status.Status != "not_running" || len(status.Errors) != 1 || status.Errors[0] != "custody_unavailable" {
		t.Fatalf("unexpected unavailable status: %#v", status)
	}
}

func TestCustodySocketPathLengthDiagnostic(t *testing.T) {
	limit := custodySocketPathLimit()
	if limit <= 0 {
		t.Skip("platform has no custody socket path preflight limit")
	}
	tooLong := "/tmp/" + strings.Repeat("x", limit)
	if err := validateCustodySocketPathLength(tooLong); err == nil || !strings.Contains(err.Error(), "custody_socket_path_too_long") || !strings.Contains(err.Error(), "/private/tmp/idtest-custody") {
		t.Fatalf("err=%v, want stable too-long diagnostic with short path guidance", err)
	}
	short := "/tmp/" + strings.Repeat("x", limit-10)
	if err := validateCustodySocketPathLength(short); err != nil {
		t.Fatalf("short path rejected: %v", err)
	}
}

func TestCustodyServeRefusesLiveSocketAndRemovesStaleSocket(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	runID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join("/tmp", "aw-custody-test-"+runID[:8])
	_ = os.RemoveAll(runDir)
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	if err := os.MkdirAll(runDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runDir, 0o777); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(runDir, "custody.sock")
	t.Cleanup(func() { _ = os.Remove(socket) })

	first := testCustodyService(t, residentKey, sessionKey)
	first.socketPath = socket
	first.readinessCheck = func(ctx context.Context) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- first.serve(ctx) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("custody service exited before creating socket: %v", err)
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}
	info, err := os.Stat(runDir)
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("run dir mode=%v, want 0700", info.Mode().Perm())
	}
	socketInfo, err := os.Stat(socket)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if socketInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("socket mode=%v, want no group/other permissions", socketInfo.Mode().Perm())
	}
	second := testCustodyService(t, residentKey, sessionKey)
	second.socketPath = socket
	if err := second.serve(context.Background()); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("err=%v, want already running", err)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first custody service did not stop")
	}

	_ = os.Remove(socket)
	if err := os.WriteFile(socket, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := testCustodyService(t, residentKey, sessionKey)
	stale.socketPath = socket
	staleCtx, staleCancel := context.WithCancel(context.Background())
	errc = make(chan error, 1)
	go func() { errc <- stale.serve(staleCtx) }()
	for i := 0; i < 100; i++ {
		if err := custodyHTTP(context.Background(), socket, http.MethodGet, "/status", nil, &custodyStatusReport{}); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	staleCancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale replacement service did not stop")
	}
}

type custodyE2EETestIdentity struct {
	did       string
	stableID  string
	address   string
	signKey   ed25519.PrivateKey
	xPriv     *ecdh.PrivateKey
	assertion *awid.EncryptionKeyAssertion
}

func newCustodyE2EETestIdentity(t *testing.T, address string) custodyE2EETestIdentity {
	t.Helper()
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(signKey.Public().(ed25519.PublicKey))
	stableID := "did:aw:" + strings.ReplaceAll(address, "/", "-")
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := awid.BuildEncryptionKeyAssertion(signKey, did, stableID, xPriv.PublicKey().Bytes(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return custodyE2EETestIdentity{did: did, stableID: stableID, address: address, signKey: signKey, xPriv: xPriv, assertion: assertion}
}

func TestCustodyCreateAndUnwrapE2EEEnvelope(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyService(t, alice.signKey, sessionKey)
	svc.identity.DID = alice.did
	svc.identity.StableID = alice.stableID
	svc.identity.Address = alice.address
	svc.e2eeAssertion = alice.assertion
	svc.e2eePrivateKey = alice.xPriv
	svc.resolveRecipient = func(ctx context.Context, identifier string) (*awid.ResolvedIdentity, error) {
		return &awid.ResolvedIdentity{DID: bob.did, StableID: bob.stableID, Address: bob.address, EncryptionKey: bob.assertion}, nil
	}

	createReq := &awid.E2EEEnvelopeCreateRequest{Version: 1, Operation: "create_e2ee_envelope", GrantID: "11111111-1111-4111-8111-111111111111", SessionDIDKey: awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)), TeamID: "backend:acme.com", SubjectDIDAW: alice.stableID, SubjectDIDKey: alice.did, Audience: "local-resident-custody:test-service", Kind: "mail", Subject: "secret", Body: "body", MessageID: "22222222-2222-4222-8222-222222222222", ConversationID: "33333333-3333-4333-8333-333333333333", Recipients: []awid.E2EERecipientKey{{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion}}}
	if err := awid.SignE2EECreateCustodyProof(sessionKey, createReq); err != nil {
		t.Fatal(err)
	}
	created, err := svc.createE2EEEnvelope(context.Background(), createReq)
	if err != nil {
		t.Fatal(err)
	}
	if created.EncryptedEnvelope == nil || created.EncryptedEnvelope.From.DID != alice.did || created.EncryptedEnvelope.SigningKeyID != alice.did {
		t.Fatalf("bad custody e2ee envelope: %#v", created.EncryptedEnvelope)
	}
	bobPlain, err := awid.DecryptE2EEMessage(created.EncryptedEnvelope, awid.E2EEDecryptIdentity{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKeyID: bob.assertion.EncryptionKeyID, PrivateKey: bob.xPriv})
	if err != nil || bobPlain.Body != "body" || bobPlain.Subject != "secret" {
		t.Fatalf("bob decrypt=%#v err=%v", bobPlain, err)
	}

	incoming, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: alice.assertion}}, Subject: "for alice", Body: "resident secret", MessageID: "44444444-4444-4444-8444-444444444444", ConversationID: "55555555-5555-4555-8555-555555555555", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	svc.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		if kind != "mail" || messageID != incoming.MessageID || conversationID != incoming.ConversationID {
			t.Fatalf("unexpected stored lookup kind=%q message=%q conversation=%q", kind, messageID, conversationID)
		}
		return incoming, nil
	}
	unwrapReq := &awid.E2EEUnwrapRequest{Version: 1, Operation: "unwrap_e2ee_message", GrantID: "11111111-1111-4111-8111-111111111111", SessionDIDKey: awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)), TeamID: "backend:acme.com", SubjectDIDAW: alice.stableID, SubjectDIDKey: alice.did, Audience: "local-resident-custody:test-service", Kind: "mail", MessageID: incoming.MessageID, ConversationID: incoming.ConversationID, OutputMode: "plaintext", Envelope: incoming}
	if err := awid.SignE2EEUnwrapCustodyProof(sessionKey, unwrapReq); err != nil {
		t.Fatal(err)
	}
	unwrapped, err := svc.unwrapE2EEMessage(context.Background(), unwrapReq)
	if err != nil {
		t.Fatal(err)
	}
	if unwrapped.Subject != "for alice" || unwrapped.Body != "resident secret" {
		t.Fatalf("unexpected unwrap: %#v", unwrapped)
	}
}

func signedE2EEUnwrapRequest(t *testing.T, sessionKey ed25519.PrivateKey, alice custodyE2EETestIdentity, envelope *awid.E2EEMessageEnvelope) *awid.E2EEUnwrapRequest {
	t.Helper()
	req := &awid.E2EEUnwrapRequest{Version: 1, Operation: "unwrap_e2ee_message", GrantID: "11111111-1111-4111-8111-111111111111", SessionDIDKey: awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)), TeamID: "backend:acme.com", SubjectDIDAW: alice.stableID, SubjectDIDKey: alice.did, Audience: "local-resident-custody:test-service", Kind: strings.TrimSpace(envelope.Kind), MessageID: envelope.MessageID, ConversationID: envelope.ConversationID, OutputMode: "plaintext", Envelope: envelope}
	if err := awid.SignE2EEUnwrapCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestCustodyUnwrapRequiresReadableStoredE2EEMessage(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "beta.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyService(t, alice.signKey, sessionKey)
	svc.identity.DID = alice.did
	svc.identity.StableID = alice.stableID
	svc.identity.Address = alice.address
	svc.e2eeAssertion = alice.assertion
	svc.e2eePrivateKey = alice.xPriv
	incoming, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: alice.assertion}}, Subject: "cross team", Body: "readable", MessageID: "66666666-6666-4666-8666-666666666666", ConversationID: "77777777-7777-4777-8777-777777777777", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	unreadable := signedE2EEUnwrapRequest(t, sessionKey, alice, incoming)
	svc.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		return nil, errors.New("stored_message_unavailable")
	}
	if _, err := svc.unwrapE2EEMessage(context.Background(), unreadable); err == nil || err.Error() != "stored_message_unavailable" {
		t.Fatalf("err=%v, want stored_message_unavailable", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/"+incoming.MessageID {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(awid.InboxMessage{MessageID: incoming.MessageID, ConversationID: incoming.ConversationID, FromAddress: bob.address, ToAddress: alice.address, ContentMode: awid.ContentModeEncryptedV2, MessageVersion: awid.E2EEMessageVersion, Encrypted: incoming})
	}))
	defer server.Close()
	client, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	svc.client = client
	svc.readStoredEnvelope = svc.storedE2EEEnvelopeViaClient
	readable := signedE2EEUnwrapRequest(t, sessionKey, alice, incoming)
	out, err := svc.unwrapE2EEMessage(context.Background(), readable)
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "cross team" || out.Body != "readable" {
		t.Fatalf("unexpected unwrap: %#v", out)
	}
}

func saveCustodyArchivedKey(t *testing.T, home string, keyID string, priv *ecdh.PrivateKey) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, "encryption-keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	privateRel := filepath.ToSlash(filepath.Join("encryption-keys", "old.x25519.key"))
	privatePath := filepath.Join(home, filepath.FromSlash(privateRel))
	if err := awid.SaveX25519PrivateKey(privatePath, priv); err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawStdEncoding.EncodeToString(priv.PublicKey().Bytes())
	state := &awconfig.EncryptionKeyState{Keys: []awconfig.EncryptionKeyRecord{{KeyID: keyID, PublicKey: publicKey, PrivateKeyPath: privateRel, CreatedAt: time.Now().UTC().Format(time.RFC3339), NotBefore: time.Now().UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}}
	if err := awconfig.SaveEncryptionKeyStateTo(filepath.Join(home, "encryption.yaml"), state); err != nil {
		t.Fatal(err)
	}
	return privatePath
}

func TestCustodyUnwrapUsesArchivedE2EEKeyForHistory(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	oldPriv, _, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	oldAssertion, err := awid.BuildEncryptionKeyAssertion(alice.signKey, alice.did, alice.stableID, oldPriv.PublicKey().Bytes(), "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	bob := newCustodyE2EETestIdentity(t, "beta.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyService(t, alice.signKey, sessionKey)
	svc.residentHome = t.TempDir()
	svc.identity.DID = alice.did
	svc.identity.StableID = alice.stableID
	svc.identity.Address = alice.address
	svc.e2eeAssertion = alice.assertion
	svc.e2eePrivateKey = alice.xPriv
	oldMessage, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: oldAssertion}}, Subject: "old", Body: "historical secret", MessageID: "88888888-8888-4888-8888-888888888888", ConversationID: "99999999-9999-4999-8999-999999999999", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	svc.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		return oldMessage, nil
	}
	missing := signedE2EEUnwrapRequest(t, sessionKey, alice, oldMessage)
	if _, err := svc.unwrapE2EEMessage(context.Background(), missing); err == nil || err.Error() != "archived_key_unavailable" {
		t.Fatalf("err=%v, want archived_key_unavailable", err)
	}
	saveCustodyArchivedKey(t, svc.residentHome, oldAssertion.EncryptionKeyID, oldPriv)
	ok := signedE2EEUnwrapRequest(t, sessionKey, alice, oldMessage)
	out, err := svc.unwrapE2EEMessage(context.Background(), ok)
	if err != nil {
		t.Fatal(err)
	}
	if out.Body != "historical secret" || out.Subject != "old" {
		t.Fatalf("unexpected archived unwrap: %#v", out)
	}
}

func signedE2EECreateRequest(t *testing.T, sessionKey ed25519.PrivateKey, alice, bob custodyE2EETestIdentity) *awid.E2EEEnvelopeCreateRequest {
	t.Helper()
	req := &awid.E2EEEnvelopeCreateRequest{Version: 1, Operation: "create_e2ee_envelope", GrantID: "11111111-1111-4111-8111-111111111111", SessionDIDKey: awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)), TeamID: "backend:acme.com", SubjectDIDAW: alice.stableID, SubjectDIDKey: alice.did, Audience: "local-resident-custody:test-service", Kind: "mail", Subject: "secret", Body: "body", MessageID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ConversationID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Recipients: []awid.E2EERecipientKey{{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion}}}
	if err := awid.SignE2EECreateCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	return req
}

func testCustodyE2EEService(t *testing.T, alice, bob custodyE2EETestIdentity, sessionKey ed25519.PrivateKey) *custodyService {
	t.Helper()
	svc := testCustodyService(t, alice.signKey, sessionKey)
	svc.identity.DID = alice.did
	svc.identity.StableID = alice.stableID
	svc.identity.Address = alice.address
	svc.e2eeAssertion = alice.assertion
	svc.e2eePrivateKey = alice.xPriv
	svc.resolveRecipient = func(ctx context.Context, identifier string) (*awid.ResolvedIdentity, error) {
		return &awid.ResolvedIdentity{DID: bob.did, StableID: bob.stableID, Address: bob.address, EncryptionKey: bob.assertion}, nil
	}
	return svc
}

func TestCustodyCreateE2EEReplayAndOperationBinding(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyE2EEService(t, alice, bob, sessionKey)
	req := signedE2EECreateRequest(t, sessionKey, alice, bob)
	first, err := svc.createE2EEEnvelope(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.createE2EEEnvelope(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.EncryptedEnvelope == nil || replay.EncryptedEnvelope == nil || first.EncryptedEnvelope.Signature != replay.EncryptedEnvelope.Signature || first.EncryptedEnvelope.CreatedAt != replay.EncryptedEnvelope.CreatedAt {
		t.Fatalf("create replay was not cached: first=%#v replay=%#v", first.EncryptedEnvelope, replay.EncryptedEnvelope)
	}
	changed := *req
	changed.Body = "changed"
	if err := awid.SignE2EECreateCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Nonce = req.Nonce
	if _, err := svc.createE2EEEnvelope(context.Background(), &changed); err == nil || err.Error() != "replay_detected" {
		t.Fatalf("err=%v, want replay_detected", err)
	}
	wrongOp := signedE2EECreateRequest(t, sessionKey, alice, bob)
	wrongOp.Operation = "unwrap_e2ee_message"
	if err := awid.SignE2EECreateCustodyProof(sessionKey, wrongOp); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.createE2EEEnvelope(context.Background(), wrongOp); err == nil || err.Error() != "unsupported_operation" {
		t.Fatalf("err=%v, want unsupported_operation", err)
	}
}

func TestCustodyUnwrapE2EEReplayAndOperationBinding(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyE2EEService(t, alice, bob, sessionKey)
	incoming, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: alice.assertion}}, Subject: "replay", Body: "secret", MessageID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", ConversationID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	svc.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		return incoming, nil
	}
	req := signedE2EEUnwrapRequest(t, sessionKey, alice, incoming)
	first, err := svc.unwrapE2EEMessage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.unwrapE2EEMessage(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.Body != replay.Body || first.Subject != replay.Subject {
		t.Fatalf("unwrap replay was not cached: first=%#v replay=%#v", first, replay)
	}
	changed := *req
	changed.OutputMode = "plaintext "
	if err := awid.SignE2EEUnwrapCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Nonce = req.Nonce
	if _, err := svc.unwrapE2EEMessage(context.Background(), &changed); err == nil || err.Error() != "replay_detected" {
		t.Fatalf("err=%v, want replay_detected", err)
	}
	wrongOp := signedE2EEUnwrapRequest(t, sessionKey, alice, incoming)
	wrongOp.Operation = "create_e2ee_envelope"
	if err := awid.SignE2EEUnwrapCustodyProof(sessionKey, wrongOp); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.unwrapE2EEMessage(context.Background(), wrongOp); err == nil || err.Error() != "unsupported_operation" {
		t.Fatalf("err=%v, want unsupported_operation", err)
	}
}

func TestCustodyCreateE2EEVerifiesRecipientCurrentBinding(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	attacker := newCustodyE2EETestIdentity(t, "acme.com/attacker")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyE2EEService(t, alice, bob, sessionKey)
	svc.resolveRecipient = func(ctx context.Context, identifier string) (*awid.ResolvedIdentity, error) {
		return &awid.ResolvedIdentity{DID: bob.did, StableID: bob.stableID, Address: bob.address, EncryptionKey: bob.assertion}, nil
	}
	req := signedE2EECreateRequest(t, sessionKey, alice, bob)
	req.Recipients[0].DID = attacker.did
	req.Recipients[0].EncryptionKey = attacker.assertion
	if err := awid.SignE2EECreateCustodyProof(sessionKey, req); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.createE2EEEnvelope(context.Background(), req); err == nil || err.Error() != "recipient_binding_mismatch" {
		t.Fatalf("err=%v, want recipient_binding_mismatch", err)
	}
}

func TestCustodyE2EEHandlersRejectUnknownFields(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyE2EEService(t, alice, bob, sessionKey)
	createReq := signedE2EECreateRequest(t, sessionKey, alice, bob)
	data, _ := json.Marshal(createReq)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unexpected"] = "x"
	data, _ = json.Marshal(raw)
	rr := httptest.NewRecorder()
	svc.handleCreateE2EEEnvelope(rr, httptest.NewRequest(http.MethodPost, "/create_e2ee_envelope", bytes.NewReader(data)))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bad_request") {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}

	incoming, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: alice.assertion}}, Subject: "unknown", Body: "field", MessageID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", ConversationID: "ffffffff-ffff-4fff-8fff-ffffffffffff", CreatedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	unwrapReq := signedE2EEUnwrapRequest(t, sessionKey, alice, incoming)
	data, _ = json.Marshal(unwrapReq)
	raw = map[string]any{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["unexpected"] = "x"
	data, _ = json.Marshal(raw)
	rr = httptest.NewRecorder()
	svc.handleUnwrapE2EEMessage(rr, httptest.NewRequest(http.MethodPost, "/unwrap_e2ee_message", bytes.NewReader(data)))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "bad_request") {
		t.Fatalf("unwrap status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCustodyStatusReportsEncryptionKeyUnavailable(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(rand.Reader)
	_, sessionKey, _ := ed25519.GenerateKey(rand.Reader)
	svc := testCustodyService(t, residentKey, sessionKey)
	svc.e2eeKeyError = "encryption_key_unavailable"
	status := svc.status(context.Background(), "running", nil)
	found := false
	for _, code := range status.Errors {
		if code == "encryption_key_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("status errors=%v, want encryption_key_unavailable", status.Errors)
	}
	if ready, _ := status.Keys["encryption_ready"].(bool); ready {
		t.Fatalf("encryption_ready=true with key error: %#v", status.Keys)
	}
}
