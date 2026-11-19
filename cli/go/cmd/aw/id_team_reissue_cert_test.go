package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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

// reissueCertWorld is a real world seen from its controller's machine: the
// team key is installed where aw team admin reissue-cert loads it.
func reissueCertWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	resetTeamReissueCertGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	world := newRealCommandWorld(t)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	teamReissueCertTeam = "backend"
	teamReissueCertNamespace = world.Domain
	teamReissueCertRegistryURL = world.Stack.RegistryURL
	return world
}

// failFirstCertificateRegister answers the first certificate registration with
// a 500, as a crash between the old certificate's revocation and the fresh
// one's registration would leave it.
func failFirstCertificateRegister(world *realCommandWorld) registryFault {
	var failed atomic.Bool
	path := "/v1/namespaces/" + world.Domain + "/teams/backend/certificates"
	return registryFault{Answer: func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != path || !failed.CompareAndSwap(false, true) {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"simulated crash before registration"}`))
		return true
	}}
}

func activeCertificates(certificates []awid.RegistryCertificate) []awid.RegistryCertificate {
	var active []awid.RegistryCertificate
	for _, certificate := range certificates {
		if certificate.RevokedAt == "" {
			active = append(active, certificate)
		}
	}
	return active
}

func TestTeamReissueCertRevokesRegisteredOldThenRegistersFresh(t *testing.T) {
	world := reissueCertWorld(t)
	memberDID := didOf(newKey(t))
	old := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: memberDID, Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	teamReissueCertDID = memberDID

	var runErr error
	printed := captureStdout(t, func() {
		runErr = runTeamReissueCert(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatalf("runTeamReissueCert: %v", runErr)
	}
	// The registry allows one active certificate per alias, so a fresh one
	// registered before the old one's revocation would have been refused.
	certs := world.aliasCertificates(t, "alice")
	active := activeCertificates(certs)
	if len(certs) != 2 || len(active) != 1 {
		t.Fatalf("certificates=%+v", certs)
	}
	fresh := active[0]
	if fresh.CertificateID == old.CertificateID || fresh.MemberDIDKey != memberDID || fresh.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("fresh certificate=%+v", fresh)
	}
	for _, want := range []string{
		"old certificate " + old.CertificateID + " revoked",
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
	world := reissueCertWorld(t)
	memberDID := didOf(newKey(t))
	teamReissueCertDID = memberDID

	var runErr error
	printed := captureStdout(t, func() {
		runErr = runTeamReissueCert(nil, []string{"alice"})
	})
	if runErr != nil {
		t.Fatalf("runTeamReissueCert: %v", runErr)
	}
	certs := world.aliasCertificates(t, "alice")
	if len(certs) != 1 || certs[0].RevokedAt != "" || certs[0].MemberDIDKey != memberDID {
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
	world := reissueCertWorld(t)
	memberDID := didOf(newKey(t))
	old := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: memberDID, Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	teamReissueCertRegistryURL = world.frontRegistry(t, failFirstCertificateRegister(world))
	teamReissueCertDID = memberDID

	err := runTeamReissueCert(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected the simulated crash between revoke and register to surface")
	}
	for _, want := range []string{"was revoked but fresh certificate", "re-running this command is safe", "fresh certificate material"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	if active := activeCertificates(world.aliasCertificates(t, "alice")); len(active) != 0 {
		t.Fatalf("crash window must leave no active certificate for the alias: %+v", active)
	}

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("re-run after crash: %v", err)
	}
	// One revoked (the original) and one active: the re-run registered only.
	certs := world.aliasCertificates(t, "alice")
	active := activeCertificates(certs)
	if len(certs) != 2 || len(active) != 1 || active[0].CertificateID == old.CertificateID || active[0].MemberDIDKey != memberDID {
		t.Fatalf("certificates after re-run=%+v", certs)
	}
}

func TestTeamReissueCertGlobalRerunRecoversFactsAfterRevokeAndRegisterFailure(t *testing.T) {
	world := reissueCertWorld(t)
	member := world.registerGlobalMember(t, "alice")
	world.registerMemberCertificate(t, awid.TeamCertificateFields{
		MemberDIDKey: member.DIDKey, MemberDIDAW: member.DIDAW, MemberAddress: member.Address,
		Alias: "alice", IdentityScope: awid.IdentityModeGlobal,
	})
	teamReissueCertRegistryURL = world.frontRegistry(t, failFirstCertificateRegister(world))
	teamReissueCertDID = member.DIDKey

	if err := runTeamReissueCert(nil, []string{"alice"}); err == nil {
		t.Fatal("expected the simulated failure after revocation")
	}
	if active := activeCertificates(world.aliasCertificates(t, "alice")); len(active) != 0 {
		t.Fatalf("failed first run must leave no active certificate: %+v", active)
	}

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("re-run after partial global reissue: %v", err)
	}
	active := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(active) != 1 || active[0].IdentityScope != awid.IdentityModeGlobal ||
		active[0].MemberDIDAW != member.DIDAW || active[0].MemberAddress != member.Address {
		t.Fatalf("re-run must preserve the revoked global certificate facts: %+v", active)
	}
}

func TestTeamReissueCertRefusesAmbiguousNewestRevokedMemberFacts(t *testing.T) {
	world := reissueCertWorld(t)
	member := world.registerGlobalMember(t, "alice")
	for _, fields := range []awid.TeamCertificateFields{
		{MemberDIDKey: member.DIDKey, MemberDIDAW: member.DIDAW, MemberAddress: member.Address, Alias: "alice", IdentityScope: awid.IdentityModeGlobal},
		{MemberDIDKey: member.DIDKey, Alias: "alice", IdentityScope: awid.IdentityModeLocal},
	} {
		certificate := world.registerMemberCertificate(t, fields)
		if err := world.Registry.RevokeCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", certificate.CertificateID, world.TeamKey); err != nil {
			t.Fatal(err)
		}
	}
	// The registry stamps each registration with its own time, so two of its
	// records never tie; another registry's history can, which is what the
	// command must refuse to guess between.
	teamReissueCertRegistryURL = world.frontRegistry(t, registryFault{Rewrite: func(response *http.Response) error {
		if response.Request.Method != http.MethodGet || !strings.HasSuffix(response.Request.URL.Path, "/teams/backend/certificates") {
			return nil
		}
		return rewriteJSONBody(response, func(page map[string]any) {
			certificates, _ := page["certificates"].([]any)
			for _, item := range certificates {
				if certificate, ok := item.(map[string]any); ok && certificate["alias"] == "alice" {
					certificate["issued_at"] = "2026-08-01T00:00:00Z"
				}
			}
		})
	}})
	teamReissueCertDID = member.DIDKey

	err := runTeamReissueCert(nil, []string{"alice"})
	if err == nil || !strings.Contains(err.Error(), "certificate history") ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguous history refusal, got %v", err)
	}
	if active := activeCertificates(world.aliasCertificates(t, "alice")); len(active) != 0 {
		t.Fatalf("ambiguous history must not register a replacement: %+v", active)
	}
}

// A run against an already-reissued member is the chosen idempotency behavior:
// mint-and-swap again. The registry ends with exactly one active certificate
// for the alias either way, and no run can 409 against the active-alias index.
func TestTeamReissueCertSecondRunSwapsAgain(t *testing.T) {
	world := reissueCertWorld(t)
	teamReissueCertDID = didOf(newKey(t))

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	first := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(first) != 1 {
		t.Fatalf("first run active certificates=%+v", first)
	}
	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("second run: %v", err)
	}
	second := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(second) != 1 || second[0].CertificateID == first[0].CertificateID {
		t.Fatalf("second run must swap in a fresh certificate: first=%+v second=%+v", first, second)
	}
}

func TestTeamReissueCertInstallsFreshBlobIntoReachableHome(t *testing.T) {
	world := reissueCertWorld(t)
	member := world.addLocalMember(t, "alice")
	agentHome := filepath.Dir(member.Home)
	// A provisioned member home whose certificate blob is lost: membership
	// state and signing key are intact, the blob is absent.
	if err := os.Remove(awconfig.TeamCertificatePath(agentHome, world.TeamID)); err != nil {
		t.Fatal(err)
	}
	teamReissueCertHome = agentHome

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("runTeamReissueCert: %v", err)
	}
	installed, err := awconfig.LoadTeamCertificateForTeam(agentHome, world.TeamID)
	if err != nil {
		t.Fatalf("fresh blob not installed: %v", err)
	}
	active := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(active) != 1 || installed.CertificateID != active[0].CertificateID ||
		installed.CertificateID == member.Certificate.CertificateID || installed.MemberDIDKey != member.Certificate.MemberDIDKey {
		t.Fatalf("installed=%+v registered=%+v", installed, active)
	}
	if err := awid.CheckDecodedTeamCertificate(installed, didOf(world.TeamKey)); err != nil {
		t.Fatalf("installed certificate does not verify against the team key: %v", err)
	}
}

func TestTeamReissueCertWithoutHomePrintsPlacementMaterial(t *testing.T) {
	world := reissueCertWorld(t)
	memberDID := didOf(newKey(t))
	teamReissueCertDID = memberDID
	jsonFlag = true

	var runErr error
	printed := captureStdout(t, func() {
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
	active := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(active) != 1 || cert.CertificateID != active[0].CertificateID || cert.MemberDIDKey != memberDID {
		t.Fatalf("printed certificate=%+v registered=%+v", cert, active)
	}
	if output["old_certificate_action"] != certificateNoneRegistered {
		t.Fatalf("old_certificate_action=%v", output["old_certificate_action"])
	}
}

func TestTeamReissueCertKeepsGlobalMemberFactsFromRegisteredCertificate(t *testing.T) {
	world := reissueCertWorld(t)
	member := world.registerGlobalMember(t, "alice")
	world.registerMemberCertificate(t, awid.TeamCertificateFields{
		MemberDIDKey: member.DIDKey, MemberDIDAW: member.DIDAW, MemberAddress: member.Address,
		Alias: "alice", IdentityScope: awid.IdentityModeGlobal,
	})
	teamReissueCertDID = member.DIDKey

	if err := runTeamReissueCert(nil, []string{"alice"}); err != nil {
		t.Fatalf("runTeamReissueCert: %v", err)
	}
	active := activeCertificates(world.aliasCertificates(t, "alice"))
	if len(active) != 1 || active[0].IdentityScope != awid.IdentityModeGlobal ||
		active[0].MemberDIDAW != member.DIDAW || active[0].MemberAddress != member.Address {
		t.Fatalf("fresh certificate must keep the registered global member facts: %+v", active)
	}
}

func TestTeamReissueCertRefusesRegisteredKeyMismatchPointsToReplaceKey(t *testing.T) {
	world := reissueCertWorld(t)
	registered := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(newKey(t)), Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	teamReissueCertDID = didOf(newKey(t))

	err := runTeamReissueCert(nil, []string{"alice"})
	if err == nil {
		t.Fatal("expected key-mismatch refusal")
	}
	for _, want := range []string{"never changes the member key", "aw team admin replace-key"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	// Nothing revoked and nothing registered.
	if certs := world.aliasCertificates(t, "alice"); len(certs) != 1 || certs[0].CertificateID != registered.CertificateID || certs[0].RevokedAt != "" {
		t.Fatalf("registered certificate must be untouched: %+v", certs)
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
