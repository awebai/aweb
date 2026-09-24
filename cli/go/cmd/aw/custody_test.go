package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
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
		results:    map[string]*awid.PlainMessageSignResponse{},
		grantStatus: func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
			return custodyGrantStatus{Active: true, Scopes: []string{"mail.send", "chat.send"}, GrantDIDKey: sessionDID, TeamID: "backend:acme.com", Status: "active", EffectiveStatus: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
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
			svc.results = map[string]*awid.PlainMessageSignResponse{}
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
