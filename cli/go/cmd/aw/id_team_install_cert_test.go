package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const installTeamID = "backend:example.com"

// certificateRegistry is a private team at AWID: its metadata and
// certificate list refuse team_private to a caller without member authority,
// as they do to a member whose certificate is revoked; each certificate's
// anonymous status answers its current team key and whether it is revoked.
// It answers 503 when down.
type certificateRegistry struct {
	server  *httptest.Server
	mu      sync.Mutex
	teamKey string
	rows    []awid.RegistryCertificate
	down    bool
	// answer replaces the status the registry reports, when set.
	answer string
}

func newCertificateRegistry(t *testing.T, teamKey ed25519.PrivateKey) *certificateRegistry {
	t.Helper()
	r := &certificateRegistry{teamKey: awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"detail":"unavailable"}`))
			return
		}
		const prefix = "/v1/namespaces/example.com/teams/backend/certificates/"
		if id, isStatus := strings.CutSuffix(strings.TrimPrefix(req.URL.Path, prefix), "/status"); isStatus && strings.HasPrefix(req.URL.Path, prefix) {
			for _, row := range r.rows {
				if row.CertificateID == id {
					status, revokedAt := "active", any(nil)
					if row.RevokedAt != "" {
						status, revokedAt = "revoked", row.RevokedAt
					}
					if r.answer != "" {
						status = r.answer
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"team_id": installTeamID, "team_did_key": r.teamKey, "status": status, "revoked_at": revokedAt})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"Certificate not found"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":{"code":"team_private","message":"Team is private"}}`))
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *certificateRegistry) register(cert *awid.TeamCertificate, revoked bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := awid.RegistryCertificate{CertificateID: cert.CertificateID, TeamID: cert.Team, MemberDIDKey: cert.MemberDIDKey,
		MemberDIDAW: cert.MemberDIDAW, Alias: cert.Alias, IdentityScope: cert.IdentityScope, IssuedAt: cert.IssuedAt}
	if revoked {
		row.RevokedAt = "2026-11-13T00:00:00Z"
	}
	r.rows = append(r.rows, row)
}

// keyOnlyHome is a home holding a local identity, and its did:key.
func keyOnlyHome(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	result, err := createUnaddressedIdentity(context.Background(), localRequest(root))
	if err != nil {
		t.Fatal(err)
	}
	return root, result["did_key"].(string)
}

func signedMemberCertificate(t *testing.T, teamKey ed25519.PrivateKey, memberDIDKey, memberDIDAW, scope string) *awid.TeamCertificate {
	t.Helper()
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: installTeamID, MemberDIDKey: memberDIDKey,
		MemberDIDAW: memberDIDAW, Alias: "agent-1", IdentityScope: scope})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func certificateFile(t *testing.T, cert *awid.TeamCertificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admitted.cert")
	if err := awid.SaveTeamCertificate(path, cert); err != nil {
		t.Fatal(err)
	}
	return path
}

func installRequest(t *testing.T, registry *certificateRegistry, home, certificatePath string) teamCertificateInstall {
	t.Helper()
	client, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.TrustRegistryOrigin(registry.server.URL); err != nil {
		t.Fatal(err)
	}
	return teamCertificateInstall{WorkingDir: t.TempDir(), Home: home, CertificatePath: certificatePath,
		RegistryURL: registry.server.URL, Registry: client}
}

func TestAnAdmittedLocalCertificateIsInstalledIntoAKeyOnlyHome(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	result, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert)))
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "installed" || result["team_id"] != installTeamID || result["alias"] != "agent-1" ||
		result["certificate_id"] != cert.CertificateID || result["did_key"] != didKey || result["did_aw"] != nil {
		t.Fatalf("result %v", result)
	}
	installed, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, installTeamID)
	if err != nil || installed.CertificateID != cert.CertificateID || installed.Signature != cert.Signature {
		t.Fatalf("installed %+v, %v", installed, err)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil || state.Membership(installTeamID) == nil {
		t.Fatalf("membership %+v, %v", state, err)
	}
	assertCredentialGeneration(t, home, 1)
}

// assertCredentialGeneration requires home's committed credential generation
// to be want, with no update incomplete.
func assertCredentialGeneration(t *testing.T, home string, want int64) {
	t.Helper()
	if state, err := awconfig.ReadCredentialState(home); err != nil || state.Generation != want || state.Marker != nil {
		t.Fatalf("credential state %+v err %v, want generation %d", state, err, want)
	}
}

func TestReinstallingTheSameCertificateReportsItAndChangesNothing(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	path := certificateFile(t, cert)
	if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, path)); err != nil {
		t.Fatal(err)
	}
	contents := homeContents(t, home)
	result, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, path))
	if err != nil || result["status"] != "already_installed" || result["certificate_id"] != cert.CertificateID {
		t.Fatalf("rerun %v, %v", result, err)
	}
	if !maps.Equal(contents, homeContents(t, home)) {
		t.Fatal("the rerun changed the home")
	}
}

// A run killed after the certificate was saved and before the membership was
// recorded is completed by the rerun.
func TestAnInstallKilledBeforeItsMembershipIsCompletedByTheRerun(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, installTeamID, cert); err != nil {
		t.Fatal(err)
	}
	result, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert)))
	if err != nil || result["status"] != "already_installed" {
		t.Fatalf("rerun %v, %v", result, err)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil || state.Membership(installTeamID) == nil {
		t.Fatalf("membership %+v, %v", state, err)
	}
	assertCredentialGeneration(t, home, 1)
}

func TestACertificateThatIsNotThisHomesCurrentMembershipIsRefusedAndNothingInstalled(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	_, otherKey, _ := awid.GenerateKeypair()
	for name, tc := range map[string]struct {
		code    string
		prepare func(t *testing.T, registry *certificateRegistry, home, didKey string) string
	}{
		"another member's key": {"member_mismatch", func(t *testing.T, registry *certificateRegistry, home, _ string) string {
			pub, _, _ := awid.GenerateKeypair()
			cert := signedMemberCertificate(t, teamKey, awid.ComputeDIDKey(pub), "", awid.IdentityModeLocal)
			registry.register(cert, false)
			return certificateFile(t, cert)
		}},
		"a registered member where the home is local": {"member_mismatch", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, teamKey, didKey, "did:aw:someone", awid.IdentityModeGlobal)
			registry.register(cert, false)
			return certificateFile(t, cert)
		}},
		"signed by a key that is not the team's current key": {"team_key_not_current", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, otherKey, didKey, "", awid.IdentityModeLocal)
			registry.register(cert, false)
			return certificateFile(t, cert)
		}},
		"a signature that does not verify": {"certificate_bad_signature", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, otherKey, didKey, "", awid.IdentityModeLocal)
			cert.TeamDIDKey = registry.teamKey
			registry.register(cert, false)
			return certificateFile(t, cert)
		}},
		"revoked": {"certificate_revoked", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
			registry.register(cert, true)
			return certificateFile(t, cert)
		}},
		"not registered": {"certificate_unregistered", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			return certificateFile(t, signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal))
		}},
		"not a certificate": {"certificate_invalid", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			path := filepath.Join(t.TempDir(), "admitted.cert")
			_ = os.WriteFile(path, []byte("not a certificate\n"), 0o600)
			return path
		}},
		"another certificate already installed for the team": {"certificate_conflict", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			first := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
			registry.register(first, false)
			if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, first))); err != nil {
				t.Fatal(err)
			}
			second := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
			registry.register(second, false)
			return certificateFile(t, second)
		}},
		"a status aw does not know": {"certificate_invalid", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
			registry.register(cert, false)
			registry.answer = "suspended"
			return certificateFile(t, cert)
		}},
		"the registry is unavailable": {"registry_unavailable", func(t *testing.T, registry *certificateRegistry, home, didKey string) string {
			cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
			registry.register(cert, false)
			registry.down = true
			return certificateFile(t, cert)
		}},
	} {
		registry := newCertificateRegistry(t, teamKey)
		home, didKey := keyOnlyHome(t)
		path := tc.prepare(t, registry, home, didKey)
		contents := homeContents(t, home)
		_, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, path))
		if code := errorCodeOf(err); code != tc.code {
			t.Errorf("%s: code %q, err %v", name, code, err)
		}
		if !maps.Equal(contents, homeContents(t, home)) {
			t.Errorf("%s: the refusal changed the home", name)
		}
	}
}

func TestInstallCertRefusalCodesAreDocumented(t *testing.T) {
	for _, code := range installCertificateCodes {
		if !strings.Contains(teamInstallCertCmd.Long, code) {
			t.Errorf("--help does not name %s", code)
		}
	}
}

// The real commands take a fresh home through OATS's order: a key-only
// identity, then the certificate file its admission wrote.
func TestTheInstallCommandInstallsAnAdmittedCertificateIntoALocalHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "child")
	run := func(args ...string) (map[string]any, string, error) {
		t.Helper()
		command := exec.CommandContext(ctx, bin, append([]string{"--json", "--identity-home", home}, args...)...)
		command.Dir, command.Env = root, testCommandEnv(root)
		out, err := command.CombinedOutput()
		var result map[string]any
		_ = json.Unmarshal(out, &result)
		return result, string(out), err
	}
	created, out, err := run("id", "create", "--local")
	if err != nil {
		t.Fatalf("create --local: %v %s", err, out)
	}
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	cert := signedMemberCertificate(t, teamKey, created["did_key"].(string), "", awid.IdentityModeLocal)
	registry.register(cert, false)
	path := certificateFile(t, cert)
	installed, out, err := run("id", "team", "install-cert", "--certificate", path, "--registry", registry.server.URL)
	if err != nil || installed["status"] != "installed" || installed["certificate_id"] != cert.CertificateID {
		t.Fatalf("install-cert: %v %s", err, out)
	}
	again, out, err := run("id", "team", "install-cert", "--certificate", path, "--registry", registry.server.URL)
	if err != nil || again["status"] != "already_installed" {
		t.Fatalf("rerun: %v %s", err, out)
	}
	stored, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, installTeamID)
	if err != nil || stored.CertificateID != cert.CertificateID {
		t.Fatalf("stored %+v, %v", stored, err)
	}

	// The installed home is what aw service init connects.
	var connected connectRequest
	var connectedWith string
	service := newLocalHTTPServerHandlerWithURL(t, func(serviceURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": serviceURL, "aweb_url": serviceURL})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectedWith = requireCertificateAuthForTest(t, r).CertificateID
			_ = json.NewDecoder(r.Body).Decode(&connected)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": installTeamID, "alias": "agent-1", "agent_id": "agent-1-id",
				"workspace_id": "workspace-1", "team_did_key": registry.teamKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1-id", installTeamID, "agent-1")
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	})
	if _, out, err := run("service", "init", "--service", service.URL, "--team", installTeamID); err != nil {
		t.Fatalf("service init: %v %s", err, out)
	}
	if connectedWith != cert.CertificateID || connected.WorkspacePath != home {
		t.Fatalf("connected with %q for %q", connectedWith, connected.WorkspacePath)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(home, "workspace.yaml"))
	if err != nil || workspace.Membership(installTeamID) == nil || workspace.Membership(installTeamID).WorkspaceID != "workspace-1" {
		t.Fatalf("workspace %+v, %v", workspace, err)
	}
}

// A local identity belongs to exactly one team: a home holding any trace of
// another team refuses, before anything is written.
func TestALocalHomeOfAnotherTeamRefusesTheCertificateAndIsLeftUnchanged(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	const priorTeam = "frontend:example.com"
	for name, prepare := range map[string]func(t *testing.T, registry *certificateRegistry, home, didKey string){
		"a membership with its certificate": func(t *testing.T, registry *certificateRegistry, home, didKey string) {
			saveOtherTeamCertificate(t, teamKey, home, didKey, priorTeam)
			saveOtherTeamMembership(t, registry, home, priorTeam)
		},
		"only the other team's certificate file": func(t *testing.T, _ *certificateRegistry, home, didKey string) {
			saveOtherTeamCertificate(t, teamKey, home, didKey, priorTeam)
		},
		"only the other team's membership": func(t *testing.T, registry *certificateRegistry, home, _ string) {
			saveOtherTeamMembership(t, registry, home, priorTeam)
		},
	} {
		registry := newCertificateRegistry(t, teamKey)
		home, didKey := keyOnlyHome(t)
		prepare(t, registry, home, didKey)
		cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
		registry.register(cert, false)
		contents := homeContents(t, home)
		_, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert)))
		if errorCodeOf(err) != "certificate_conflict" {
			t.Errorf("%s: err %v", name, err)
		}
		if !maps.Equal(contents, homeContents(t, home)) {
			t.Errorf("%s: the refusal changed the home", name)
		}
	}
}

func TestAGlobalHomeInAnotherTeamInstallsTheCertificate(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home := t.TempDir()
	created, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, newMappingRegistry(t), home))
	if err != nil {
		t.Fatal(err)
	}
	didKey, didAW := created["did_key"].(string), created["did_aw"].(string)
	const priorTeam = "frontend:example.com"
	prior, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: priorTeam, MemberDIDKey: didKey, MemberDIDAW: didAW,
		Alias: "first", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, priorTeam, prior); err != nil {
		t.Fatal(err)
	}
	saveOtherTeamMembership(t, registry, home, priorTeam)
	cert := signedMemberCertificate(t, teamKey, didKey, didAW, awid.IdentityModeGlobal)
	registry.register(cert, false)
	result, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert)))
	if err != nil || result["status"] != "installed" || result["did_aw"] != didAW {
		t.Fatalf("result %v, %v", result, err)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil || state.Membership(priorTeam) == nil || state.Membership(installTeamID) == nil {
		t.Fatalf("memberships %+v, %v", state, err)
	}
}

// The membership an interrupted install's rerun records names the registry
// the certificate was checked at.
func TestAnInterruptedInstallRecordsTheRegistryItChecked(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, installTeamID, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert))); err != nil {
		t.Fatal(err)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil || state.Membership(installTeamID) == nil || state.Membership(installTeamID).RegistryURL != registry.server.URL {
		t.Fatalf("membership %+v, %v; want registry %s", state, err, registry.server.URL)
	}
}

func saveOtherTeamCertificate(t *testing.T, teamKey ed25519.PrivateKey, home, didKey, team string) {
	t.Helper()
	prior, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team, MemberDIDKey: didKey, Alias: "first",
		IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, team, prior); err != nil {
		t.Fatal(err)
	}
}

func saveOtherTeamMembership(t *testing.T, registry *certificateRegistry, home, team string) {
	t.Helper()
	if err := awconfig.SaveTeamStateToIdentityHome(home, &awconfig.TeamState{ActiveTeam: team, Memberships: []awconfig.TeamMembership{{
		TeamID: team, Alias: "first", CertPath: awconfig.TeamCertificateRelativePath(team), RegistryURL: registry.server.URL}}}); err != nil {
		t.Fatal(err)
	}
}

func TestARefusedInstallDoesNotRenewTheHomesIdentity(t *testing.T) {
	certificate := filepath.Join(t.TempDir(), "invalid.cert")
	if err := os.WriteFile(certificate, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRefusalDoesNotRenew(t, "certificate_invalid", func(string) []string {
		return []string{"id", "team", "install-cert", "--certificate", certificate}
	})
}

// fetch-cert records an already-installed certificate with no registry,
// which keeps the existing membership's own.
func TestRecordingAnInstalledCertificateWithNoRegistryKeepsTheMembershipsRegistry(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert))); err != nil {
		t.Fatal(err)
	}
	if _, err := commitTeamCertificate(t.TempDir(), home, "fetch-cert", cert, "", func() (string, error) { return "already_installed", nil }); err != nil {
		t.Fatal(err)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil || state.Membership(installTeamID) == nil || state.Membership(installTeamID).RegistryURL != registry.server.URL {
		t.Fatalf("membership %+v, %v; want registry %s kept", state, err, registry.server.URL)
	}
}

// Two installs of different teams' certificates into one local home, both
// past the read-only check before either writes, install exactly one.
func TestConcurrentInstallsOfTwoTeamsIntoOneLocalHomeInstallOnlyOne(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	home, didKey := keyOnlyHome(t)
	certs, paths := map[string]*awid.TeamCertificate{}, map[string]string{}
	for _, name := range []string{"frontend", "backend"} {
		cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: name + ":example.com", MemberDIDKey: didKey,
			Alias: "worker", IdentityScope: awid.IdentityModeLocal})
		if err != nil {
			t.Fatal(err)
		}
		certs[name], paths[name] = cert, certificateFile(t, cert)
	}
	reached, release := make(chan string, 2), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		name, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/namespaces/example.com/teams/"), "/")
		cert := certs[name]
		if cert == nil {
			http.NotFound(w, r)
			return
		}
		if rest != "certificates/"+cert.CertificateID+"/status" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":{"code":"team_private","message":"Team is private"}}`))
			return
		}
		reached <- name
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"team_id": cert.Team, "team_did_key": cert.TeamDIDKey, "status": "active", "revoked_at": nil})
	}))
	defer func() { unblock(); server.Close() }()
	errs := make(chan error, 2)
	for _, name := range []string{"frontend", "backend"} {
		client, err := newConfiguredRegistryClient(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.TrustRegistryOrigin(server.URL); err != nil {
			t.Fatal(err)
		}
		request := teamCertificateInstall{WorkingDir: t.TempDir(), Home: home, CertificatePath: paths[name], RegistryURL: server.URL, Registry: client}
		go func() {
			_, err := installTeamCertificateFile(context.Background(), request)
			errs <- err
		}()
	}
	for range 2 {
		select {
		case <-reached:
		case <-time.After(10 * time.Second):
			t.Fatal("both installs did not pass the read-only check")
		}
	}
	unblock()
	installed, refused := 0, 0
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			installed++
		case errorCodeOf(err) == "certificate_conflict":
			refused++
		default:
			t.Errorf("unexpected error %v", err)
		}
	}
	stored := 0
	for _, cert := range certs {
		if got, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, cert.Team); err == nil && got.CertificateID == cert.CertificateID {
			stored++
		}
	}
	if installed != 1 || refused != 1 || stored != 1 {
		t.Fatalf("installed %d, refused %d, stored %d; want one of each", installed, refused, stored)
	}
}

// An older aw takes only the released home install lock. A new install that
// waits on that lock while the older one installs another team rechecks under
// both locks and refuses: a local identity still ends in one team.
func TestANewInstallWaitingOnAnOlderInstallOfAnotherTeamRefuses(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	older, err := awconfig.LockExclusive(filepath.Join(home, teamCertificateInstallLock))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, cert)))
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		lock, err := awconfig.LockCredentialsShared(home)
		if errors.Is(err, awconfig.ErrLockUnavailable) {
			break
		}
		if err == nil {
			_ = lock.Close()
		}
		if time.Now().After(deadline) {
			t.Fatal("the new install never took the credential lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	const otherTeam = "frontend:example.com"
	saveOtherTeamCertificate(t, teamKey, home, didKey, otherTeam)
	saveOtherTeamMembership(t, registry, home, otherTeam)
	_ = older.Close()
	if err := <-done; errorCodeOf(err) != "certificate_conflict" {
		t.Fatalf("err %v", err)
	}
	if _, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, installTeamID); !os.IsNotExist(err) {
		t.Fatalf("the waiting install wrote its certificate: %v", err)
	}
}

// While custody serves the home, a home changed without publishing a
// generation is not installed into: the change would otherwise be published
// with the install. With no reader, the install publishes over it, as
// ordinary setup (accept, then connect or install) needs.
func TestAnInstallIntoAHomeChangedWithoutPublishingRefusesOnlyWhileServed(t *testing.T) {
	for name, served := range map[string]bool{"served by custody": true, "with no reader": false} {
		_, teamKey, _ := awid.GenerateKeypair()
		registry := newCertificateRegistry(t, teamKey)
		home, didKey := keyOnlyHome(t)
		first := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
		registry.register(first, false)
		if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, first))); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, "id-chain.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if served {
			reader, err := awconfig.LockCredentialReader(home)
			if err != nil {
				t.Fatal(err)
			}
			contents := homeContents(t, home)
			_, err = installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, first)))
			_ = reader.Close()
			if errorCodeOf(err) != "credential_update_unpublished" {
				t.Errorf("%s: err %v", name, err)
			}
			if !maps.Equal(contents, homeContents(t, home)) {
				t.Errorf("%s: the refused install changed the home", name)
			}
			continue
		}
		if _, err := installTeamCertificateFile(context.Background(), installRequest(t, registry, home, certificateFile(t, first))); err != nil {
			t.Errorf("%s: err %v", name, err)
		}
	}
}
