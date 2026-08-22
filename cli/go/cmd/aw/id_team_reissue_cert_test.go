package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func resetTeamReissueCertGlobals(t *testing.T) {
	t.Helper()
	oldTeam := teamReissueCertTeam
	oldNamespace := teamReissueCertNamespace
	oldDID := teamReissueCertDID
	oldHome := teamReissueCertHome
	oldLocal := teamReissueCertLocal
	oldGlobal := teamReissueCertGlobal
	oldDIDAW := teamReissueCertDIDAW
	oldAddress := teamReissueCertAddress
	oldRegistry := teamReissueCertRegistryURL
	oldJSON := jsonFlag
	t.Cleanup(func() {
		teamReissueCertTeam = oldTeam
		teamReissueCertNamespace = oldNamespace
		teamReissueCertDID = oldDID
		teamReissueCertHome = oldHome
		teamReissueCertLocal = oldLocal
		teamReissueCertGlobal = oldGlobal
		teamReissueCertDIDAW = oldDIDAW
		teamReissueCertAddress = oldAddress
		teamReissueCertRegistryURL = oldRegistry
		jsonFlag = oldJSON
	})
	teamReissueCertTeam = ""
	teamReissueCertNamespace = ""
	teamReissueCertDID = ""
	teamReissueCertHome = ""
	teamReissueCertLocal = false
	teamReissueCertGlobal = false
	teamReissueCertDIDAW = ""
	teamReissueCertAddress = ""
	teamReissueCertRegistryURL = ""
	jsonFlag = false
}

type fakeReissueRegistryCert struct {
	CertificateID string
	MemberDIDKey  string
	MemberDIDAW   string
	MemberAddress string
	Alias         string
	IdentityScope string
	IssuedAt      string
	Revoked       bool
}

// fakeReissueRegistry is a stateful fake of the AWID registry's team
// certificate routes. Like the real registry, it enforces one UNREVOKED
// certificate per (team, alias) - a register that would violate it answers
// 409 "Alias already active in team", the real partial-index conflict.
type fakeReissueRegistry struct {
	t                *testing.T
	mu               sync.Mutex
	calls            []string
	certs            []*fakeReissueRegistryCert
	failNextRegister bool
}

func (f *fakeReissueRegistry) activeByAliasLocked(alias string) *fakeReissueRegistryCert {
	for _, cert := range f.certs {
		if !cert.Revoked && cert.Alias == alias {
			return cert
		}
	}
	return nil
}

func (f *fakeReissueRegistry) findLocked(certificateID string) *fakeReissueRegistryCert {
	for _, cert := range f.certs {
		if cert.CertificateID == certificateID {
			return cert
		}
	}
	return nil
}

func (f *fakeReissueRegistry) snapshotCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeReissueRegistry) snapshotCerts() []fakeReissueRegistryCert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]fakeReissueRegistryCert, 0, len(f.certs))
	for _, cert := range f.certs {
		out = append(out, *cert)
	}
	return out
}

func (f *fakeReissueRegistry) activeCertForAlias(alias string) *fakeReissueRegistryCert {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cert := f.activeByAliasLocked(alias); cert != nil {
		copied := *cert
		return &copied
	}
	return nil
}

func (f *fakeReissueRegistry) handler() http.Handler {
	const base = "/v1/namespaces/acme.com/teams/backend"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == base:
			f.calls = append(f.calls, "get-team")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "domain": "acme.com", "name": "backend",
				"team_did_key": "did:key:team", "visibility": "private", "created_at": "2026-08-01T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == base+"/certificates":
			f.calls = append(f.calls, "list-certificates")
			activeOnly := r.URL.Query().Get("active_only") == "true"
			certificates := make([]map[string]any, 0, len(f.certs))
			for _, cert := range f.certs {
				if activeOnly && cert.Revoked {
					continue
				}
				revokedAt := ""
				if cert.Revoked {
					revokedAt = "2026-08-02T00:00:00Z"
				}
				certificates = append(certificates, map[string]any{
					"team_id": "backend:acme.com", "certificate_id": cert.CertificateID,
					"member_did_key": cert.MemberDIDKey, "member_did_aw": cert.MemberDIDAW,
					"member_address": cert.MemberAddress, "alias": cert.Alias,
					"identity_scope": cert.IdentityScope, "issued_at": cert.IssuedAt,
					"revoked_at": revokedAt,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"certificates": certificates, "has_more": false,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, base+"/members/"):
			alias := strings.TrimPrefix(r.URL.Path, base+"/members/")
			f.calls = append(f.calls, "resolve:"+alias)
			active := f.activeByAliasLocked(alias)
			if active == nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Member not found"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "certificate_id": active.CertificateID,
				"member_did_key": active.MemberDIDKey, "member_did_aw": active.MemberDIDAW,
				"member_address": active.MemberAddress, "alias": active.Alias,
				"identity_scope": active.IdentityScope, "issued_at": active.IssuedAt,
			})
		case r.Method == http.MethodPost && r.URL.Path == base+"/certificates/revoke":
			f.calls = append(f.calls, "revoke")
			var body struct {
				CertificateID string `json:"certificate_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			cert := f.findLocked(body.CertificateID)
			if cert == nil {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Certificate not found"})
				return
			}
			if cert.Revoked {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Certificate already revoked"})
				return
			}
			cert.Revoked = true
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})
		case r.Method == http.MethodPost && r.URL.Path == base+"/certificates":
			f.calls = append(f.calls, "register")
			if f.failNextRegister {
				f.failNextRegister = false
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "simulated crash before registration"})
				return
			}
			var body struct {
				CertificateID string `json:"certificate_id"`
				MemberDIDKey  string `json:"member_did_key"`
				MemberDIDAW   string `json:"member_did_aw"`
				MemberAddress string `json:"member_address"`
				Alias         string `json:"alias"`
				IdentityScope string `json:"identity_scope"`
				Certificate   string `json:"certificate"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				f.t.Errorf("register body decode: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if f.findLocked(body.CertificateID) != nil {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{
					"code": "certificate_already_registered", "message": "Certificate already registered",
				}})
				return
			}
			if f.activeByAliasLocked(body.Alias) != nil {
				// The unique active-alias partial index: one unrevoked
				// certificate per (team, alias).
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Alias already active in team"})
				return
			}
			f.certs = append(f.certs, &fakeReissueRegistryCert{
				CertificateID: body.CertificateID, MemberDIDKey: body.MemberDIDKey,
				MemberDIDAW: body.MemberDIDAW, MemberAddress: body.MemberAddress,
				Alias: body.Alias, IdentityScope: body.IdentityScope,
				IssuedAt: time.Now().UTC().Format(time.RFC3339),
			})
			w.WriteHeader(http.StatusCreated)
		default:
			f.t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "unexpected route"})
		}
	})
}

// seedReissueCertController seeds a controller machine that holds the
// backend:acme.com team key, points the command at the fake registry, and
// returns the team key.
func seedReissueCertController(t *testing.T, registryURL string) ed25519.PrivateKey {
	t.Helper()
	resetTeamReissueCertGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(root)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("acme.com", "backend", teamKey); err != nil {
		t.Fatal(err)
	}
	teamReissueCertTeam = "backend"
	teamReissueCertNamespace = "acme.com"
	teamReissueCertRegistryURL = registryURL
	return teamKey
}

func newReissueCertFakeRegistry(t *testing.T) (*fakeReissueRegistry, *httptest.Server) {
	t.Helper()
	fake := &fakeReissueRegistry{t: t}
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	return fake, server
}

func TestTeamReissueCertRevokesRegisteredOldThenRegistersFresh(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-1", MemberDIDKey: memberDID, Alias: "alice",
		IdentityScope: awid.IdentityModeLocal, IssuedAt: "2026-08-01T00:00:00Z",
	})
	teamReissueCertDID = memberDID

	var runErr error
	printed := captureIDCommandStdout(t, func() {
		runErr = runTeamReissueCert(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatalf("runTeamReissueCert: %v", runErr)
	}
	if got := strings.Join(fake.snapshotCalls(), ","); got != "resolve:alice,revoke,register" {
		t.Fatalf("registry call order=%q; the old registration must be revoked before the fresh one is registered", got)
	}
	certs := fake.snapshotCerts()
	if len(certs) != 2 || !certs[0].Revoked || certs[0].CertificateID != "cert-old-1" {
		t.Fatalf("certificates=%+v", certs)
	}
	fresh := certs[1]
	if fresh.Revoked || fresh.CertificateID == "cert-old-1" || fresh.MemberDIDKey != memberDID ||
		fresh.Alias != "alice" || fresh.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("fresh certificate=%+v", fresh)
	}
	for _, want := range []string{
		"old certificate cert-old-1 revoked",
		"Grants issued under the old certificate are no longer valid",
		"expect the member to reconnect",
		"member did:key: " + memberDID + " (unchanged)",
		"new certificate registered: " + fresh.CertificateID,
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("output missing %q:\n%s", want, printed)
		}
	}
}

func TestTeamReissueCertNeverRegisteredRegistersWithoutRevoke(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	teamReissueCertDID = memberDID

	var runErr error
	printed := captureIDCommandStdout(t, func() {
		runErr = runTeamReissueCert(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatalf("runTeamReissueCert: %v", runErr)
	}
	if got := strings.Join(fake.snapshotCalls(), ","); got != "resolve:alice,get-team,list-certificates,register" {
		t.Fatalf("registry calls=%q; a never-registered alias must register without any revoke", got)
	}
	certs := fake.snapshotCerts()
	if len(certs) != 1 || certs[0].Revoked || certs[0].MemberDIDKey != memberDID || certs[0].Alias != "alice" {
		t.Fatalf("certificates=%+v", certs)
	}
	for _, want := range []string{
		"no active certificate was registered for this alias; nothing was revoked",
		"expect the member to reconnect",
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("output missing %q:\n%s", want, printed)
		}
	}
}

func TestTeamReissueCertRerunAfterCrashBetweenRevokeAndRegister(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-1", MemberDIDKey: memberDID, Alias: "alice",
		IdentityScope: awid.IdentityModeLocal, IssuedAt: "2026-08-01T00:00:00Z",
	})
	fake.failNextRegister = true
	teamReissueCertDID = memberDID

	err = runTeamReissueCert(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected the simulated crash between revoke and register to surface")
	}
	for _, want := range []string{"was revoked but fresh certificate", "re-running this command is safe", "fresh certificate material"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	if fake.activeCertForAlias("alice") != nil {
		t.Fatal("crash window must leave no active certificate for the alias")
	}

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("re-run after crash: %v", err)
	}
	fresh := fake.activeCertForAlias("alice")
	if fresh == nil || fresh.MemberDIDKey != memberDID || fresh.CertificateID == "cert-old-1" {
		t.Fatalf("fresh certificate after re-run=%+v", fresh)
	}
	revokes := 0
	for _, call := range fake.snapshotCalls() {
		if call == "revoke" {
			revokes++
		}
	}
	if revokes != 1 {
		t.Fatalf("revoke calls=%d; the re-run must find no active certificate and register only", revokes)
	}
}

func TestTeamReissueCertGlobalRerunRecoversFactsAfterRevokeAndRegisterFailure(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-global", MemberDIDKey: memberDID,
		MemberDIDAW: "did:aw:alice", MemberAddress: "acme.com/alice",
		Alias: "alice", IdentityScope: awid.IdentityModeGlobal,
		IssuedAt: "2026-08-01T00:00:00Z",
	})
	fake.failNextRegister = true
	teamReissueCertDID = memberDID

	if err := runTeamReissueCert(nil, []string{"alice"}); err == nil {
		t.Fatal("expected the simulated failure after revocation")
	}
	if fake.activeCertForAlias("alice") != nil {
		t.Fatal("failed first run must leave no active certificate")
	}

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("re-run after partial global reissue: %v", err)
	}
	fresh := fake.activeCertForAlias("alice")
	if fresh == nil || fresh.IdentityScope != awid.IdentityModeGlobal ||
		fresh.MemberDIDAW != "did:aw:alice" || fresh.MemberAddress != "acme.com/alice" {
		t.Fatalf("re-run must preserve the revoked global certificate facts: %+v", fresh)
	}
}

func TestTeamReissueCertRefusesAmbiguousNewestRevokedMemberFacts(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	for _, cert := range []*fakeReissueRegistryCert{
		{
			CertificateID: "cert-global", MemberDIDKey: memberDID,
			MemberDIDAW: "did:aw:alice", MemberAddress: "acme.com/alice",
			Alias: "alice", IdentityScope: awid.IdentityModeGlobal,
			IssuedAt: "2026-08-01T00:00:00Z", Revoked: true,
		},
		{
			CertificateID: "cert-local", MemberDIDKey: memberDID,
			Alias: "alice", IdentityScope: awid.IdentityModeLocal,
			IssuedAt: "2026-08-01T00:00:00Z", Revoked: true,
		},
	} {
		fake.certs = append(fake.certs, cert)
	}
	teamReissueCertDID = memberDID

	err = runTeamReissueCert(nil, []string{"alice"})
	if err == nil || !strings.Contains(err.Error(), "certificate history") ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous history refusal, got %v", err)
	}
	if fake.activeCertForAlias("alice") != nil {
		t.Fatal("ambiguous history must not register a replacement")
	}
}

// A run against an already-reissued member is the chosen idempotency behavior:
// mint-and-swap again. The registry ends with exactly one active certificate
// for the alias either way, and no run can 409 against the active-alias index.
func TestTeamReissueCertSecondRunSwapsAgain(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	teamReissueCertDID = memberDID

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	first := fake.activeCertForAlias("alice")
	if first == nil {
		t.Fatal("first run registered nothing")
	}
	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second := fake.activeCertForAlias("alice")
	if second == nil || second.CertificateID == first.CertificateID {
		t.Fatalf("second run must swap in a fresh certificate: first=%+v second=%+v", first, second)
	}
	active := 0
	for _, cert := range fake.snapshotCerts() {
		if !cert.Revoked {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("active certificates=%d, want exactly one per alias", active)
	}
}

func TestTeamReissueCertInstallsFreshBlobIntoReachableHome(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	teamKey := seedReissueCertController(t, server.URL)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-1", MemberDIDKey: memberDID, Alias: "alice",
		IdentityScope: awid.IdentityModeLocal, IssuedAt: "2026-08-01T00:00:00Z",
	})

	// A provisioned member home whose certificate blob is lost: membership
	// state and signing key are intact, the blob is absent.
	agentHome := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(filepath.Join(agentHome, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(agentHome), memberKey); err != nil {
		t.Fatal(err)
	}
	certPath := awconfig.TeamCertificateRelativePath("backend:acme.com")
	joinedAt := time.Now().UTC().Format(time.RFC3339)
	if err := awconfig.SaveTeamState(agentHome, &awconfig.TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID: "backend:acme.com", Alias: "alice", CertPath: certPath,
			JoinedAt: joinedAt, RegistryURL: server.URL,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(agentHome, awconfig.DefaultWorktreeWorkspaceRelativePath()), &awconfig.WorktreeWorkspace{
		AwebURL: server.URL, WorkspacePath: agentHome,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID: "backend:acme.com", Alias: "alice", CertPath: certPath,
			JoinedAt: joinedAt, WorkspaceID: "workspace-alice",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.LoadTeamCertificateForTeam(agentHome, "backend:acme.com"); !os.IsNotExist(err) {
		t.Fatalf("precondition: certificate blob must be absent, got %v", err)
	}
	teamReissueCertHome = agentHome

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("runTeamReissueCert: %v", err)
	}
	installed, err := awconfig.LoadTeamCertificateForTeam(agentHome, "backend:acme.com")
	if err != nil {
		t.Fatalf("fresh blob not installed: %v", err)
	}
	fresh := fake.activeCertForAlias("alice")
	if fresh == nil || installed.CertificateID != fresh.CertificateID || installed.MemberDIDKey != memberDID {
		t.Fatalf("installed=%+v registered=%+v", installed, fresh)
	}
	teamPub := teamKey.Public().(ed25519.PublicKey)
	if err := awid.VerifyTeamCertificate(installed, teamPub); err != nil {
		t.Fatalf("installed certificate does not verify against the team key: %v", err)
	}
}

func TestTeamReissueCertWithoutHomePrintsPlacementMaterial(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	teamReissueCertDID = memberDID
	jsonFlag = true

	var runErr error
	printed := captureIDCommandStdout(t, func() {
		runErr = runTeamReissueCert(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	var output map[string]any
	if err := json.Unmarshal([]byte(printed), &output); err != nil {
		t.Fatalf("output=%q: %v", printed, err)
	}
	material, _ := output["team_certificate"].(string)
	placement, _ := output["placement"].(string)
	if material == "" || !strings.Contains(placement, ".aw/team-certs") {
		t.Fatalf("output=%v", output)
	}
	cert, err := awid.DecodeTeamCertificateHeader(material)
	if err != nil {
		t.Fatalf("decode printed material: %v", err)
	}
	fresh := fake.activeCertForAlias("alice")
	if fresh == nil || cert.CertificateID != fresh.CertificateID || cert.MemberDIDKey != memberDID {
		t.Fatalf("printed certificate=%+v registered=%+v", cert, fresh)
	}
	if output["old_certificate_action"] != certificateNoneRegistered {
		t.Fatalf("old_certificate_action=%v", output["old_certificate_action"])
	}
}

func TestTeamReissueCertKeepsGlobalMemberFactsFromRegisteredCertificate(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-1", MemberDIDKey: memberDID, MemberDIDAW: "did:aw:alice",
		MemberAddress: "acme.com/alice", Alias: "alice",
		IdentityScope: awid.IdentityModeGlobal, IssuedAt: "2026-08-01T00:00:00Z",
	})
	teamReissueCertDID = memberDID

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("runTeamReissueCert: %v", err)
	}
	fresh := fake.activeCertForAlias("alice")
	if fresh == nil || fresh.IdentityScope != awid.IdentityModeGlobal ||
		fresh.MemberDIDAW != "did:aw:alice" || fresh.MemberAddress != "acme.com/alice" {
		t.Fatalf("fresh certificate must keep the registered global member facts: %+v", fresh)
	}
}

func TestTeamReissueCertRefusesRegisteredKeyMismatchPointsToReplaceKey(t *testing.T) {
	fake, server := newReissueCertFakeRegistry(t)
	seedReissueCertController(t, server.URL)
	registeredPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	attestedPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	fake.certs = append(fake.certs, &fakeReissueRegistryCert{
		CertificateID: "cert-old-1", MemberDIDKey: awid.ComputeDIDKey(registeredPub), Alias: "alice",
		IdentityScope: awid.IdentityModeLocal, IssuedAt: "2026-08-01T00:00:00Z",
	})
	teamReissueCertDID = awid.ComputeDIDKey(attestedPub)

	err = runTeamReissueCert(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected key-mismatch refusal")
	}
	for _, want := range []string{"never changes the member key", "aw team admin replace-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	for _, call := range fake.snapshotCalls() {
		if call == "revoke" || call == "register" {
			t.Fatalf("registry was mutated after refusal: calls=%v", fake.snapshotCalls())
		}
	}
	if got := fake.activeCertForAlias("alice"); got == nil || got.Revoked {
		t.Fatalf("registered certificate must be untouched: %+v", got)
	}
}

func TestTeamReissueCertHostedNamespaceRefusesLocalControllerPath(t *testing.T) {
	resetTeamReissueCertGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	teamReissueCertTeam = "default"
	teamReissueCertNamespace = "hosted.aweb.ai"
	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamReissueCertDID = awid.ComputeDIDKey(pub)

	err = runTeamReissueCert(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected hosted custody refusal")
	}
	for _, want := range []string{"hosted", "operator support"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
}
