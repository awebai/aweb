package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func seedReplaceKeyWorkspace(t *testing.T, serverURL string) (root, agentHome, oldDID, newDID string, teamKey ed25519.PrivateKey, oldCert *awid.TeamCertificate) {
	t.Helper()
	resetTeamHumanCreateGlobals(t)
	root = t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)

	_, teamKey, _ = awid.GenerateKeypair()
	if err := awconfig.SaveTeamKey("acme.com", "backend", teamKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta("acme.com", &awconfig.ControllerMeta{
		Domain:      "acme.com",
		RegistryURL: serverURL,
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "captain",
			CertPath:    ".aw/team-certs/backend__acme.com.pem",
			AwebURL:     serverURL,
			RegistryURL: serverURL,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	oldPub, _, _ := awid.GenerateKeypair()
	newPub, newKey, _ := awid.GenerateKeypair()
	oldDID = awid.ComputeDIDKey(oldPub)
	newDID = awid.ComputeDIDKey(newPub)
	agentHome = filepath.Join(root, "agents", "instances", "alice")
	if err := os.MkdirAll(filepath.Join(agentHome, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(agentHome), newKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(agentHome, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           newDID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	oldCert, _ = awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  oldDID,
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
	})
	if _, err := awconfig.SaveTeamCertificateForTeam(agentHome, "backend:acme.com", oldCert); err != nil {
		t.Fatal(err)
	}
	return root, agentHome, oldDID, newDID, teamKey, oldCert
}

func TestLocalIdentityKeyReplacementAuthPayloadMatchesServerCanonicalOrder(t *testing.T) {
	payload := localIdentityKeyReplacementRequest{
		TeamID: "backend:acme.com", OldDIDKey: "did:key:old", NewDIDKey: "did:key:new",
		OldCertificateID: "cert-old", NewCertificateID: "cert-new",
	}
	got, err := localIdentityKeyReplacementAuthPayload("alice", payload, "2026-07-23T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_alias":"alice","new_certificate_id":"cert-new","new_did_key":"did:key:new","old_certificate_id":"cert-old","old_did_key":"did:key:old","operation":"replace_local_identity_key","team_id":"backend:acme.com","timestamp":"2026-07-23T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("canonical payload=%s\nwant=%s", got, want)
	}
}

func TestReplacementHomeRejectsGlobalIdentityScope(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	_, agentHome, oldDID, newDID, _, _ := seedReplaceKeyWorkspace(t, server.URL)
	identity, _, err := awconfig.LoadWorktreeIdentityFromDir(agentHome)
	if err != nil {
		t.Fatal(err)
	}
	identity.IdentityScope = awid.IdentityModeGlobal
	identity.Lifetime = ""
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(agentHome, awconfig.DefaultWorktreeIdentityRelativePath()), identity); err != nil {
		t.Fatal(err)
	}

	_, err = preflightReplacementAgentHome(agentHome, "backend:acme.com", "alice", oldDID, newDID, "")
	if err == nil || !strings.Contains(err.Error(), "must contain a local team-scoped identity") {
		t.Fatalf("error=%v", err)
	}
}

func TestReplacementHomeWithoutOldCertificateAcceptsExplicitCertificateID(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	_, agentHome, oldDID, newDID, _, _ := seedReplaceKeyWorkspace(t, server.URL)
	if err := os.Remove(awconfig.TeamCertificatePath(agentHome, "backend:acme.com")); err != nil {
		t.Fatal(err)
	}
	got, err := preflightReplacementAgentHome(agentHome, "backend:acme.com", "alice", oldDID, newDID, "cert-from-operator-records")
	if err != nil {
		t.Fatal(err)
	}
	if got != "cert-from-operator-records" {
		t.Fatalf("certificate_id=%q", got)
	}
}

func TestTeamReplaceKeyReplacesRosterRevokesOldRegistersAndInstallsNewCertificate(t *testing.T) {
	var server *httptest.Server
	var order []string
	var registered map[string]any
	var servicePayload localIdentityKeyReplacementRequest
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/alice/replace-key":
			order = append(order, "roster")
			if err := json.NewDecoder(r.Body).Decode(&servicePayload); err != nil {
				t.Fatal(err)
			}
			controllerDID, signature, err := parseDIDKeyAuthorizationForTest(r.Header.Get("Authorization"))
			if err != nil {
				t.Fatal(err)
			}
			publicKey, err := awid.ExtractPublicKey(controllerDID)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := localIdentityKeyReplacementAuthPayload("alice", servicePayload, r.Header.Get("X-AWEB-Timestamp"))
			if err != nil {
				t.Fatal(err)
			}
			rawSignature, err := base64.RawStdEncoding.DecodeString(signature)
			if err != nil || !ed25519.Verify(publicKey, canonical, rawSignature) {
				t.Fatalf("invalid controller signature: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "replaced", "audit_id": "audit-1", "agent_id": "agent-1",
				"team_id": servicePayload.TeamID, "alias": "alice",
				"old_did_key": servicePayload.OldDIDKey, "new_did_key": servicePayload.NewDIDKey,
				"old_certificate_id": servicePayload.OldCertificateID, "new_certificate_id": servicePayload.NewCertificateID,
				"authorized_by": controllerDID, "authorized_at": "2026-07-23T00:00:00+00:00",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			order = append(order, "revoke-old")
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["certificate_id"] != servicePayload.OldCertificateID {
				t.Fatalf("revoked certificate=%v", body["certificate_id"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificates"):
			order = append(order, "register-new")
			if err := json.NewDecoder(r.Body).Decode(&registered); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	_, agentHome, oldDID, newDID, _, oldCert := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyHome = agentHome

	if err := runTeamHumanReplaceKey(nil, []string{"alice"}); err != nil {
		t.Fatalf("runTeamHumanReplaceKey: %v", err)
	}
	if strings.Join(order, ",") != "roster,revoke-old,register-new" {
		t.Fatalf("operation order=%v", order)
	}
	if servicePayload.OldCertificateID != oldCert.CertificateID {
		t.Fatalf("old certificate=%q", servicePayload.OldCertificateID)
	}
	if registered["member_did_key"] != newDID || registered["alias"] != "alice" {
		t.Fatalf("registered=%v", registered)
	}
	installed, err := awconfig.LoadTeamCertificateForTeam(agentHome, "backend:acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if installed.MemberDIDKey != newDID || installed.CertificateID != servicePayload.NewCertificateID {
		t.Fatalf("installed=%+v", installed)
	}
}

func TestTeamReplaceKeyWithoutHomePrintsCertificatePlacementMaterial(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/alice/replace-key":
			var body localIdentityKeyReplacementRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "replaced", "audit_id": "audit-1", "agent_id": "agent-1", "team_id": body.TeamID,
				"alias": "alice", "old_did_key": body.OldDIDKey, "new_did_key": body.NewDIDKey,
				"old_certificate_id": body.OldCertificateID, "new_certificate_id": body.NewCertificateID,
				"authorized_by": strings.Fields(r.Header.Get("Authorization"))[1], "authorized_at": "2026-07-23T00:00:00+00:00",
			})
		case strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case strings.HasSuffix(r.URL.Path, "/certificates"):
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	_, _, oldDID, newDID, _, oldCert := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyOldCertID = oldCert.CertificateID
	teamHumanReplaceKeyHome = ""
	jsonFlag = true
	var runErr error
	printed := captureIDCommandStdout(t, func() {
		runErr = runTeamHumanReplaceKey(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(printed), &output); err != nil {
		t.Fatalf("output=%q: %v", printed, err)
	}
	if output["team_certificate"] == "" || !strings.Contains(output["placement"].(string), ".aw/team-certs") {
		t.Fatalf("output=%v", output)
	}
}

func TestTeamReplaceKeyRefusesWithoutLocalControllerKey(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(root)
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "default:hosted.aweb.ai", Memberships: []awconfig.TeamMembership{{TeamID: "default:hosted.aweb.ai", Alias: "owner", CertPath: ".aw/team-certs/default__hosted.aweb.ai.pem", AwebURL: "https://api.aweb.ai"}}}); err != nil {
		t.Fatal(err)
	}
	oldPublicKey, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPublicKey, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublicKey)
	newDID := awid.ComputeDIDKey(newPublicKey)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyOldCertID = "cert-old"

	err = runTeamHumanReplaceKey(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected hosted boundary error")
	}
	for _, want := range []string{"local team controller key", "hosted", "AC", "operator support"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}

func TestTeamReplaceKeyReconcilesCommittedRosterAfterResponseLoss(t *testing.T) {
	var serviceCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/alice/replace-key":
			serviceCalls++
			var body localIdentityKeyReplacementRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if serviceCalls == 1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "replaced", "audit_id": "audit-original", "agent_id": "agent-1", "team_id": body.TeamID,
				"alias": "alice", "old_did_key": body.OldDIDKey, "new_did_key": body.NewDIDKey,
				"old_certificate_id": body.OldCertificateID, "new_certificate_id": body.NewCertificateID,
				"authorized_by": strings.Fields(r.Header.Get("Authorization"))[1], "authorized_at": "2026-07-23T00:00:00+00:00",
			})
		case strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case strings.HasSuffix(r.URL.Path, "/certificates"):
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	_, agentHome, oldDID, newDID, _, oldCert := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyHome = agentHome
	if err := runTeamHumanReplaceKey(nil, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if serviceCalls != 2 {
		t.Fatalf("service calls=%d, want exact replay", serviceCalls)
	}
	installed, err := awconfig.LoadTeamCertificateForTeam(agentHome, "backend:acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if installed.CertificateID == oldCert.CertificateID || installed.MemberDIDKey != newDID {
		t.Fatalf("installed certificate=%+v", installed)
	}
}

func TestTeamReplaceKeyRosterCASFailureMakesNoCertificateChanges(t *testing.T) {
	var registryCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents/alice/replace-key" {
			http.Error(w, "old key changed", http.StatusConflict)
			return
		}
		registryCalls++
		t.Fatalf("certificate mutation followed failed roster CAS: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	_, agentHome, oldDID, newDID, _, oldCert := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyHome = agentHome

	err := runTeamHumanReplaceKey(nil, []string{"alice"})
	if err == nil || !strings.Contains(err.Error(), "no certificate changes were attempted") {
		t.Fatalf("error=%v", err)
	}
	if registryCalls != 0 {
		t.Fatalf("registry calls=%d", registryCalls)
	}
	installed, loadErr := awconfig.LoadTeamCertificateForTeam(agentHome, "backend:acme.com")
	if loadErr != nil || installed.CertificateID != oldCert.CertificateID {
		t.Fatalf("old certificate changed: cert=%+v err=%v", installed, loadErr)
	}
}

func TestTeamReplaceKeyReportsOldCertificateRevocationFailureState(t *testing.T) {
	var registerCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/alice/replace-key":
			var body localIdentityKeyReplacementRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "replaced", "audit_id": "audit-1", "agent_id": "agent-1", "team_id": body.TeamID,
				"alias": "alice", "old_did_key": body.OldDIDKey, "new_did_key": body.NewDIDKey,
				"old_certificate_id": body.OldCertificateID, "new_certificate_id": body.NewCertificateID,
				"authorized_by": strings.Fields(r.Header.Get("Authorization"))[1], "authorized_at": "2026-07-23T00:00:00+00:00",
			})
		case strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			http.Error(w, "revocation failed", http.StatusBadRequest)
		case strings.HasSuffix(r.URL.Path, "/certificates"):
			registerCalled = true
			t.Fatal("new certificate registered after old revocation failed")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	_, agentHome, oldDID, newDID, _, _ := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyHome = agentHome

	err := runTeamHumanReplaceKey(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected partial-state error")
	}
	for _, want := range []string{"roster row was replaced", "audit audit-1 was written", "old certificate", "was not revoked", "new certificate", "was not registered or installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	const materialMarker = "exact audited replacement certificate material for recovery: "
	_, encodedMaterial, found := strings.Cut(err.Error(), materialMarker)
	if !found {
		t.Fatalf("error lacks recovery material: %v", err)
	}
	recoveryCert, decodeErr := awid.DecodeTeamCertificateHeader(strings.TrimSpace(encodedMaterial))
	if decodeErr != nil || recoveryCert.MemberDIDKey != newDID {
		t.Fatalf("recovery certificate=%+v err=%v", recoveryCert, decodeErr)
	}
	if registerCalled {
		t.Fatal("register called")
	}
}

func TestTeamReplaceKeyReportsRegisteredCertificateFailureState(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/agents/alice/replace-key":
			var body localIdentityKeyReplacementRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": "replaced", "audit_id": "audit-1", "agent_id": "agent-1", "team_id": body.TeamID,
				"alias": "alice", "old_did_key": body.OldDIDKey, "new_did_key": body.NewDIDKey,
				"old_certificate_id": body.OldCertificateID, "new_certificate_id": body.NewCertificateID,
				"authorized_by": strings.Fields(r.Header.Get("Authorization"))[1], "authorized_at": "2026-07-23T00:00:00+00:00",
			})
		case strings.HasSuffix(r.URL.Path, "/certificates/revoke"):
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case strings.HasSuffix(r.URL.Path, "/certificates"):
			http.Error(w, "registry write failed", http.StatusBadRequest)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	_, agentHome, oldDID, newDID, _, _ := seedReplaceKeyWorkspace(t, server.URL)
	teamHumanReplaceKeyOldDID = oldDID
	teamHumanReplaceKeyNewDID = newDID
	teamHumanReplaceKeyHome = agentHome

	err := runTeamHumanReplaceKey(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected partial-state error")
	}
	for _, want := range []string{"roster row was replaced", "old certificate was revoked", "new certificate was not registered or installed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}

func parseDIDKeyAuthorizationForTest(value string) (string, string, error) {
	parts := strings.Split(value, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		return "", "", io.ErrUnexpectedEOF
	}
	return parts[1], parts[2], nil
}
