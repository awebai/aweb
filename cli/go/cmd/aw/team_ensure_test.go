package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

func TestTeamEnsureRefusesLocalWorkspaceKeyBeforeHTTP(t *testing.T) {
	oldKey, oldJSON, oldHome := teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "local//tmp/repo"
	jsonFlag = true
	identityHome := filepath.Join(t.TempDir(), ".aw")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() { teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome = oldKey, oldJSON, oldHome })

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "workspace-key-not-portable") {
		t.Fatalf("err=%v, want workspace-key-not-portable", err)
	}
	if called {
		t.Fatal("server was called before local workspace key was rejected")
	}
}

func TestTeamEnsureRefusesMismatchedExpectedAccountBeforeMutation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureExpectedAccountID = "acct-expected"
	jsonFlag = true
	wd := t.TempDir()
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(wd, "principal"), Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
	})
	t.Chdir(wd)

	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-other", "handle": "bob"}})
		case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
			mutated = true
			t.Fatalf("mutation endpoint called for mismatched account: %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)
	teamEnsureExpectedAccountID = "acct-expected"

	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "does not match expected account") {
		t.Fatalf("err=%v, want expected-account mismatch", err)
	}
	if mutated {
		t.Fatal("mutation endpoint was called")
	}
}

func TestTeamEnsureReportsUnsupportedServerDiagnostics(t *testing.T) {
	cases := []struct {
		name      string
		missing   string
		wantPath  string
		wantStage string
	}{
		{name: "cli auth status", missing: "/api/v1/cli-auth/status", wantPath: "/api/v1/cli-auth/status", wantStage: "CLI auth status"},
		{name: "ensure", missing: workspaceTeamEnsurePath, wantPath: workspaceTeamEnsurePath, wantStage: "workspace's default team ensure"},
		{name: "enroll", missing: workspaceTeamEnrollPath, wantPath: workspaceTeamEnrollPath, wantStage: "workspace's default team enroll"},
		{name: "spawn authority", missing: "/api/v1/spawn/authority", wantPath: "/api/v1/spawn/authority", wantStage: "installed-root spawn authority proof"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldKey, oldLabel, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome
			teamEnsureWorkspaceKey = "aweb.ai/org/unsupported-" + strings.ReplaceAll(tc.name, " ", "-")
			teamEnsureLabel = "Unsupported"
			jsonFlag = true
			wd := t.TempDir()
			identityHome := filepath.Join(wd, "principal")
			activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
			t.Cleanup(func() {
				teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome = oldKey, oldLabel, oldJSON, oldHome
			})
			t.Chdir(wd)

			_, teamPriv, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			teamID := "3c0e24cc-ef76-4d98-ae4d-55b9c2f14dad"
			canonicalTeamID := "unsupported:abjj-enroll.aweb.ai"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.missing {
					http.NotFound(w, r)
					return
				}
				switch r.URL.Path {
				case "/api/v1/cli-auth/status":
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
				case workspaceTeamEnsurePath:
					_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
				case workspaceTeamEnrollPath:
					var req workspaceTeamEnrollRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Fatal(err)
					}
					cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{Team: canonicalTeamID, MemberDIDKey: req.Identity.DID, Alias: req.Identity.Alias, IdentityScope: req.Identity.IdentityScope})
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Fatal(err)
					}
					_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-unsupported", AgentID: "agent-unsupported", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: true, TeamCert: encoded})
				case "/api/v1/spawn/authority":
					_ = json.NewEncoder(w).Encode(teamSpawnAuthorityOutput{TeamID: teamID, ActorAgentID: "agent-unsupported", AuthKind: "team_key", LiveAgent: true, CanSpawn: true})
				case "/v1/agents/heartbeat", "/api/v1/agents/heartbeat":
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

			err = runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
			if err == nil {
				t.Fatal("expected unsupported-server error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "unsupported-server") || !strings.Contains(msg, tc.wantStage) || !strings.Contains(msg, tc.wantPath) || !strings.Contains(msg, "upgrade") {
				t.Fatalf("err=%q, want unsupported-server diagnostic for %s %s", msg, tc.wantStage, tc.wantPath)
			}
		})
	}
}

func TestTeamEnsureLostFirstEnrollResponseRetriesSameKeyAndBinds(t *testing.T) {
	oldKey, oldLabel, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureLabel = "Demo Workspace"
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome = oldKey, oldLabel, oldJSON, oldHome
	})
	t.Chdir(wd)

	teamPub, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = teamPub
	teamID := "d6bd1ee9-284a-49b9-a3d6-05322613527c"
	canonicalTeamID := "local-empty:abjj-enroll.aweb.ai"
	var enrollDID string
	var firstEnrollSeen bool
	var enrollCount int
	var spawnAuthSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			if got := r.Header.Get("Authorization"); got != "Bearer awcli_test" {
				t.Fatalf("status Authorization=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
		case workspaceTeamEnsurePath:
			if got := r.Header.Get("Authorization"); got != "Bearer awcli_test" {
				t.Fatalf("ensure Authorization=%q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["workspace_key_format"].(float64) != 1 || len(body["workspace_key_sha256"].(string)) != 64 {
				t.Fatalf("bad ensure body: %#v", body)
			}
			if body["expected_account_id"] != "acct-test" {
				t.Fatalf("expected_account_id=%#v", body["expected_account_id"])
			}
			if strings.Contains(body["workspace_key_sha256"].(string), "workspace") {
				t.Fatalf("digest leaked raw workspace key: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID, Label: "Demo"})
		case workspaceTeamEnrollPath:
			enrollCount++
			if got := r.Header.Get("Authorization"); got != "Bearer awcli_test" {
				t.Fatalf("enroll Authorization=%q", got)
			}
			var req workspaceTeamEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Identity.Alias != "demo" && req.Identity.Alias != "demo_workspace" && req.Identity.Alias != "demoworkspace" {
				t.Fatalf("alias=%q", req.Identity.Alias)
			}
			if req.ExpectedAccountID != "acct-test" {
				t.Fatalf("enroll expected_account_id=%q", req.ExpectedAccountID)
			}
			if req.Proof.Type != "didkey-intent-v1" || req.Proof.Signature == "" {
				t.Fatalf("missing proof: %#v", req.Proof)
			}
			if req.Identity.StableID != "" || req.Identity.IdentityScope != awid.IdentityModeLocal {
				t.Fatalf("local identity scope/stable_id wrong: %#v", req.Identity)
			}
			if req.Identity.PublicKey != "" {
				t.Fatalf("public_key helper should be omitted, got %q", req.Identity.PublicKey)
			}
			if firstEnrollSeen && req.Identity.DID != enrollDID {
				t.Fatalf("retry DID=%q want original %q", req.Identity.DID, enrollDID)
			}
			enrollDID = req.Identity.DID
			cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{Team: canonicalTeamID, MemberDIDKey: req.Identity.DID, Alias: req.Identity.Alias, IdentityScope: req.Identity.IdentityScope})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			if !firstEnrollSeen {
				firstEnrollSeen = true
				http.Error(w, "lost after commit", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-1", AgentID: "agent-1", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: false, APIKeyCreated: false, TeamCert: encoded, SpawnAuthorityCheck: &workspaceTeamSpawnAdvisory{TeamID: teamID, CanSpawn: false}})
		case "/api/v1/spawn/authority":
			spawnAuthSeen = true
			if got := r.URL.Query().Get("team_id"); got != teamID {
				t.Fatalf("spawn team_id query=%q", got)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey ") || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("spawn auth=%q cert=%q", r.Header.Get("Authorization"), r.Header.Get("X-AWID-Team-Certificate"))
			}
			_ = json.NewEncoder(w).Encode(teamSpawnAuthorityOutput{TeamID: teamID, ActorAgentID: "agent-1", AuthKind: "team_key", LiveAgent: true, CanSpawn: true})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	var firstOut bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&firstOut)
	err = runTeamEnsure(t.Context(), cmd)
	if err == nil || !strings.Contains(err.Error(), "http 500") {
		t.Fatalf("first run err=%v, want lost response 500", err)
	}
	if _, err := os.Stat(filepath.Join(identityHome, "signing.key")); !os.IsNotExist(err) {
		t.Fatalf("signing key installed before successful retry: %v", err)
	}
	if _, err := os.Stat(filepath.Join(identityHome, "workspace-team-ensure.yaml")); err != nil {
		t.Fatalf("partial state missing after lost response: %v", err)
	}

	var out bytes.Buffer
	cmd = &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamEnsure(t.Context(), cmd); err != nil {
		t.Fatalf("retry runTeamEnsure: %v", err)
	}
	if enrollCount != 2 {
		t.Fatalf("enrollCount=%d", enrollCount)
	}
	if !spawnAuthSeen {
		t.Fatal("spawn authority was not checked")
	}
	if _, err := os.Stat(filepath.Join(identityHome, "workspace-team-ensure.yaml")); !os.IsNotExist(err) {
		t.Fatalf("partial state was not removed after bind: %v", err)
	}
	bindingPath, err := workspaceTeamBindingPath(identityHome)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bindingPath); err != nil {
		t.Fatalf("binding marker missing after live spawn proof: %v", err)
	}
	var decoded teamEnsureOutput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v\n%s", err, out.String())
	}
	if decoded.Status != "bound" || !decoded.CanSpawn || decoded.TeamID != teamID || decoded.CanonicalTeamID != canonicalTeamID || decoded.Created || decoded.AccountID != "acct-test" || decoded.AccountHandle != "alice" {
		t.Fatalf("output=%+v", decoded)
	}
	binding, err := loadWorkspaceTeamBindingMarker(identityHome)
	if err != nil {
		t.Fatal(err)
	}
	if binding == nil || binding.ExpectedAccountID != "acct-test" || binding.AccountHandle != "alice" {
		t.Fatalf("binding=%+v", binding)
	}
	teamState, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.ActiveTeam != canonicalTeamID || teamState.Membership(canonicalTeamID) == nil || teamState.Membership(teamID) != nil {
		t.Fatalf("team state stored wrong team domain: %+v", teamState)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(identityHome, "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if workspace.Membership(canonicalTeamID) == nil || workspace.Membership(teamID) != nil {
		t.Fatalf("workspace membership stored wrong team domain: %+v", workspace.Memberships)
	}
}

func TestTeamEnsureOccupiedRootPreservesBytesAndSkipsHTTP(t *testing.T) {
	oldKey, oldJSON, oldHome := teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	jsonFlag = true
	identityHome := filepath.Join(t.TempDir(), "principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() { teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome = oldKey, oldJSON, oldHome })
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(identityHome, "foreign.txt")
	if err := os.WriteFile(marker, []byte("do not change"), 0o600); err != nil {
		t.Fatal(err)
	}
	enrollCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
		case workspaceTeamEnsurePath:
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: "default:workspace.aweb.ai", CanonicalTeamID: "default:workspace.aweb.ai"})
		case workspaceTeamEnrollPath:
			enrollCalled = true
			t.Fatalf("enroll was called for occupied root")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "identity-home-occupied") {
		t.Fatalf("err=%v, want identity-home-occupied", err)
	}
	if enrollCalled {
		t.Fatal("enroll mutation was called for occupied root")
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != "do not change" {
		t.Fatalf("occupied bytes changed: %q err=%v", string(data), err)
	}
}

func TestTeamEnsureForeignLocalRootPreservesBytesAndSkipsEnroll(t *testing.T) {
	oldKey, oldJSON, oldHome := teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "foreign-principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() { teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome = oldKey, oldJSON, oldHome })
	t.Chdir(wd)

	foreignPub, foreignKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	foreignTeam := "foreign:team"
	foreignAlias := "foreign"
	foreignDID := awid.ComputeDIDKey(foreignPub)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: foreignTeam, MemberDIDKey: foreignDID, Alias: foreignAlias, IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistLocalSigningKeyAndCertificateAt(wd, identityHome, foreignKey, cert); err != nil {
		t.Fatalf("persist foreign root: %v", err)
	}
	certPath := awconfig.TeamCertificateRelativePath(foreignTeam)
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, &awconfig.TeamState{ActiveTeam: foreignTeam, Memberships: []awconfig.TeamMembership{{TeamID: foreignTeam, Alias: foreignAlias, CertPath: certPath, JoinedAt: cert.IssuedAt, AwebURL: "https://foreign.example"}}}); err != nil {
		t.Fatalf("save foreign teams: %v", err)
	}
	workspacePath := filepath.Join(identityHome, "workspace.yaml")
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, &awconfig.WorktreeWorkspace{AwebURL: "https://foreign.example", WorkspacePath: identityHome, Memberships: []awconfig.WorktreeMembership{{TeamID: foreignTeam, Alias: foreignAlias, CertPath: certPath, JoinedAt: cert.IssuedAt}}, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("save foreign workspace: %v", err)
	}
	before := fileDigestsForTest(t, identityHome)

	var enrollCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
		case workspaceTeamEnsurePath:
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: "default:workspace.aweb.ai", CanonicalTeamID: "default:workspace.aweb.ai"})
		case workspaceTeamEnrollPath:
			enrollCalled = true
			t.Fatalf("enroll was called for foreign local root")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	err = runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "identity-home-occupied") {
		t.Fatalf("err=%v, want identity-home-occupied", err)
	}
	if enrollCalled {
		t.Fatal("enroll mutation was called")
	}
	after := fileDigestsForTest(t, identityHome)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("foreign root bytes changed\nbefore=%v\nafter=%v", before, after)
	}
}

func TestTeamEnsureExistingGlobalPreservesStableIDAndUsesServerReturnedStableID(t *testing.T) {
	oldKey, oldLabel, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/global-workspace"
	teamEnsureLabel = "Global"
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "global-principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureLabel, jsonFlag, activeIdentityHome = oldKey, oldLabel, oldJSON, oldHome
	})
	t.Chdir(wd)

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := "did:aw:rotated-stable-id"
	if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), signingKey); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(identityHome, "identity.yaml"), &awconfig.WorktreeIdentity{DID: did, StableID: stableID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "registered", CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	teamID := "0b63f663-530d-44df-81ce-37ca8ecb84cf"
	canonicalTeamID := "global:abjj-enroll.aweb.ai"
	_, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var sawGlobalEnroll bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
		case workspaceTeamEnsurePath:
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
		case workspaceTeamEnrollPath:
			var req workspaceTeamEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Identity.IdentityScope != awid.IdentityModeGlobal || req.Identity.StableID != stableID || req.Identity.DID != did {
				t.Fatalf("global enroll identity=%+v want did=%s stable=%s", req.Identity, did, stableID)
			}
			if req.Identity.PublicKey != "" {
				t.Fatalf("public_key helper should be omitted for global, got %q", req.Identity.PublicKey)
			}
			sawGlobalEnroll = true
			cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{Team: canonicalTeamID, MemberDIDKey: did, MemberDIDAW: stableID, Alias: req.Identity.Alias, IdentityScope: awid.IdentityModeGlobal})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-global", AgentID: "agent-global", Alias: req.Identity.Alias, DID: did, StableID: stableID, IdentityScope: awid.IdentityModeGlobal, Created: true, APIKeyCreated: false, TeamCert: encoded})
		case "/api/v1/spawn/authority":
			_ = json.NewEncoder(w).Encode(teamSpawnAuthorityOutput{TeamID: teamID, ActorAgentID: "agent-global", AuthKind: "team_key", LiveAgent: true, CanSpawn: true})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamEnsure(t.Context(), cmd); err != nil {
		t.Fatalf("runTeamEnsure global: %v", err)
	}
	if !sawGlobalEnroll {
		t.Fatal("global enroll was not called")
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(identityHome, "identity.yaml"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if identity.StableID != stableID || identity.DID != did || identity.IdentityScope != awid.IdentityModeGlobal {
		t.Fatalf("identity after ensure=%+v", identity)
	}
	var decoded teamEnsureOutput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v\n%s", err, out.String())
	}
	if decoded.Status != "bound" || decoded.StableID != stableID || decoded.IdentityScope != awid.IdentityModeGlobal {
		t.Fatalf("output=%+v", decoded)
	}
}

func TestTeamEnsureDoesNotReturnBoundWhenSpawnAuthorityFails(t *testing.T) {
	oldKey, oldJSON, oldHome := teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/no-spawn"
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() { teamEnsureWorkspaceKey, jsonFlag, activeIdentityHome = oldKey, oldJSON, oldHome })
	t.Chdir(wd)

	_, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamID := "3c0e24cc-ef76-4d98-ae4d-55b9c2f14dad"
	canonicalTeamID := "no-spawn:abjj-enroll.aweb.ai"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-test", "handle": "alice"}})
		case workspaceTeamEnsurePath:
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
		case workspaceTeamEnrollPath:
			var req workspaceTeamEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{Team: canonicalTeamID, MemberDIDKey: req.Identity.DID, Alias: req.Identity.Alias, IdentityScope: req.Identity.IdentityScope})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-no-spawn", AgentID: "agent-no-spawn", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: true, APIKeyCreated: false, TeamCert: encoded, SpawnAuthorityCheck: &workspaceTeamSpawnAdvisory{TeamID: teamID, CanSpawn: true}})
		case "/api/v1/spawn/authority":
			_ = json.NewEncoder(w).Encode(teamSpawnAuthorityOutput{TeamID: teamID, ActorAgentID: "agent-no-spawn", AuthKind: "team_key", LiveAgent: true, CanSpawn: false})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	err = runTeamEnsure(t.Context(), cmd)
	if err == nil || !strings.Contains(err.Error(), "spawn authority denied") {
		t.Fatalf("err=%v, want spawn authority denied", err)
	}
	if strings.Contains(out.String(), "bound") {
		t.Fatalf("reported bound despite failed spawn authority: %s", out.String())
	}
	bindingPath, pathErr := workspaceTeamBindingPath(identityHome)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if _, statErr := os.Stat(bindingPath); !os.IsNotExist(statErr) {
		t.Fatalf("binding marker exists after failed spawn authority: %v", statErr)
	}
}

func writeCLIAuthConfigForTeamEnsureTest(t *testing.T, issuer string) {
	t.Helper()
	oldExpected := teamEnsureExpectedAccountID
	teamEnsureExpectedAccountID = "acct-test"
	t.Cleanup(func() { teamEnsureExpectedAccountID = oldExpected })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: issuer, Resource: cliAuthResource(issuer), Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "awcli_test", RefreshToken: "awcli_refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("save auth config: %v", err)
	}
}

func TestTeamEnsureRefusesMissingAccountEvidenceBeforeMutation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureExpectedAccountID = "acct-test"
	jsonFlag = true
	wd := t.TempDir()
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(wd, "principal"), Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
	})
	t.Chdir(wd)
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
			mutated = true
			t.Fatalf("mutation endpoint called without account evidence: %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)
	teamEnsureExpectedAccountID = "acct-test"
	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "did not include account.id") {
		t.Fatalf("err=%v, want missing account evidence", err)
	}
	if mutated {
		t.Fatal("mutation endpoint was called")
	}
}

func TestTeamEnsureRefusesExplicitRecordedOwnerConflictBeforeMutation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureExpectedAccountID = "acct-explicit"
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
	})
	t.Chdir(wd)
	if err := saveWorkspaceTeamBindingMarker(identityHome, workspaceTeamBindingState{Version: workspaceTeamPartialVersion, Issuer: "https://example.invalid", WorkspaceKeySHA256: strings.Repeat("a", 64), TeamID: "team", ExpectedAccountID: "acct-recorded", AccountHandle: "recorded"}); err != nil {
		t.Fatal(err)
	}
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-explicit", "handle": "explicit"}})
		case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
			mutated = true
			t.Fatalf("mutation endpoint called for explicit/recorded conflict")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)
	teamEnsureExpectedAccountID = "acct-explicit"
	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "explicit expected account") || !strings.Contains(err.Error(), "recorded") {
		t.Fatalf("err=%v, want explicit/recorded conflict", err)
	}
	if mutated {
		t.Fatal("mutation endpoint was called")
	}
}

func TestTeamEnsureOnlyTranslatesOwnerMismatchConflict(t *testing.T) {
	cfg := cliAuthConfig{Issuer: "", AccessToken: "token"}
	for _, tc := range []struct{ name, body, want, notWant string }{
		{name: "owner", body: `{"error":"cli_account_owner_mismatch"}`, want: "cli_account_owner_mismatch"},
		{name: "other", body: `{"error":"identity_conflict"}`, want: "identity_conflict", notWant: "cli_account_owner_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != workspaceTeamEnsurePath {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			cfg.Issuer = server.URL
			_, err := postWorkspaceTeamEnsure(t.Context(), cfg, workspaceTeamEnsureRequest{WorkspaceKeyFormat: 1, WorkspaceKeySHA256: strings.Repeat("a", 64), ExpectedAccountID: "acct-test"})
			if err == nil || !strings.Contains(err.Error(), tc.want) || (tc.notWant != "" && strings.Contains(err.Error(), tc.notWant)) {
				t.Fatalf("err=%v want %q not %q", err, tc.want, tc.notWant)
			}
		})
	}
}

func TestTeamEnsureRefusesRefreshedTokenDifferentAccountBeforeMutation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome, oldServer := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome, serverFlag
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureExpectedAccountID = "acct-expected"
	jsonFlag = true
	wd := t.TempDir()
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(wd, "principal"), Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome, serverFlag = oldKey, oldExpected, oldJSON, oldHome, oldServer
	})
	t.Chdir(wd)
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "refresh_token": "new-refresh", "token_type": "bearer", "expires_in": 3600, "scope": cliAuthScope, "resource": serverFlag + "/cli"})
		case "/api/v1/cli-auth/status":
			if got := r.Header.Get("Authorization"); got != "Bearer new-access" {
				t.Fatalf("status Authorization=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-other", "handle": "bob"}})
		case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
			mutated = true
			t.Fatalf("mutation endpoint called after refreshed owner mismatch")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverFlag = server.URL
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(-time.Hour), UpdatedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "bob (acct-other)") || !strings.Contains(err.Error(), "acct-expected") || !strings.Contains(err.Error(), "aw auth logout --scope cli.workspace_team && aw auth login --scope cli.workspace_team") {
		t.Fatalf("err=%v, want refreshed account mismatch with fix", err)
	}
	if mutated {
		t.Fatal("mutation endpoint was called")
	}
}

func workspaceTeamEnrollProofErrorForTest(req workspaceTeamEnrollRequest, aud, expectedAccountID string) error {
	payload := map[string]any{
		"operation":            workspaceTeamEnrollOperation,
		"aud":                  aud,
		"method":               http.MethodPost,
		"path":                 workspaceTeamEnrollPath,
		"workspace_key_format": workspaceTeamKeyFormat,
		"workspace_key_sha256": req.WorkspaceKeySHA256,
		"team_id":              strings.TrimSpace(req.TeamID),
		"canonical_team_id":    strings.TrimSpace(req.CanonicalTeamID),
		"expected_account_id":  strings.TrimSpace(expectedAccountID),
		"did":                  req.Identity.DID,
		"stable_id":            req.Identity.StableID,
		"identity_scope":       req.Identity.IdentityScope,
		"alias":                req.Identity.Alias,
		"timestamp":            req.Proof.Timestamp,
	}
	canonical, err := awid.CanonicalJSONValue(payload)
	if err != nil {
		return err
	}
	pub, err := awid.ExtractPublicKey(req.Identity.DID)
	if err != nil {
		return err
	}
	sig, err := base64.RawStdEncoding.DecodeString(req.Proof.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		return fmt.Errorf("enroll signature did not verify over expected_account_id=%q canonical=%s", expectedAccountID, canonical)
	}
	return nil
}

func verifyWorkspaceTeamEnrollProofForTest(t *testing.T, req workspaceTeamEnrollRequest, aud, expectedAccountID string) {
	t.Helper()
	if err := workspaceTeamEnrollProofErrorForTest(req, aud, expectedAccountID); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceTeamEnrollSignatureBindsExpectedAccountID(t *testing.T) {
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	material := workspaceTeamIdentityMaterial{SigningKey: priv, DIDKey: awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey)), IdentityScope: awid.IdentityModeLocal, Alias: "demo"}
	cfg := cliAuthConfig{Issuer: "http://issuer.example", AccessToken: "token"}
	ensure := &workspaceTeamEnsureResponse{TeamID: "team", CanonicalTeamID: "team"}
	var captured workspaceTeamEnrollRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != workspaceTeamEnrollPath {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatal(err)
		}
		verifyWorkspaceTeamEnrollProofForTest(t, captured, cfg.Issuer, "acct-a")
		_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: "team", CanonicalTeamID: "team", IdentityID: "ident", AgentID: "agent", Alias: "demo", DID: material.DIDKey, IdentityScope: awid.IdentityModeLocal, TeamCert: "unused"})
	}))
	defer server.Close()
	cfg.Issuer = server.URL
	if _, err := postWorkspaceTeamEnroll(t.Context(), cfg, ensure, strings.Repeat("a", 64), material, "acct-a"); err != nil {
		t.Fatalf("post enroll: %v", err)
	}
	if captured.ExpectedAccountID != "acct-a" {
		t.Fatalf("expected_account_id=%q", captured.ExpectedAccountID)
	}
	if err := workspaceTeamEnrollProofErrorForTest(captured, cfg.Issuer, "acct-b"); err == nil {
		t.Fatal("tampered expected_account_id unexpectedly verified")
	}
}

func TestTeamEnsureRefusesRecordedOwnerMismatchBeforeMutation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	teamEnsureExpectedAccountID = ""
	jsonFlag = true
	wd := t.TempDir()
	identityHome := filepath.Join(wd, "principal")
	activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
	})
	t.Chdir(wd)
	if err := saveWorkspaceTeamBindingMarker(identityHome, workspaceTeamBindingState{Version: workspaceTeamPartialVersion, Issuer: "https://example.invalid", WorkspaceKeySHA256: strings.Repeat("a", 64), TeamID: "team", ExpectedAccountID: "acct-a", AccountHandle: "alice"}); err != nil {
		t.Fatal(err)
	}
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": "acct-b", "handle": "bob"}})
		case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
			mutated = true
			t.Fatalf("mutation endpoint called for recorded owner mismatch")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	writeCLIAuthConfigForTeamEnsureTest(t, server.URL)
	teamEnsureExpectedAccountID = ""
	err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "alice (acct-a)") || !strings.Contains(err.Error(), "bob (acct-b)") || !strings.Contains(err.Error(), "aw auth logout --scope cli.workspace_team && aw auth login --scope cli.workspace_team") {
		t.Fatalf("err=%v, want recorded owner mismatch with accounts and fix", err)
	}
	if mutated {
		t.Fatal("mutation endpoint was called")
	}
}

func TestTeamEnsureAuthStatus401And403RefuseBeforeMutation(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
			teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
			teamEnsureExpectedAccountID = "acct-test"
			jsonFlag = true
			wd := t.TempDir()
			activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(wd, "principal"), Source: awconfig.IdentityHomeFlag}
			t.Cleanup(func() {
				teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
			})
			t.Chdir(wd)
			mutated := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/cli-auth/status":
					w.WriteHeader(status)
					_, _ = w.Write([]byte(`{"detail":"not authorized"}`))
				case workspaceTeamEnsurePath, workspaceTeamEnrollPath:
					mutated = true
					t.Fatalf("mutation endpoint called after status %d", status)
				default:
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
			}))
			defer server.Close()
			writeCLIAuthConfigForTeamEnsureTest(t, server.URL)
			teamEnsureExpectedAccountID = "acct-test"
			err := runTeamEnsure(t.Context(), &cobra.Command{Use: "test"})
			if err == nil || !strings.Contains(err.Error(), "authorization-required") || !strings.Contains(err.Error(), "aw auth login") {
				t.Fatalf("err=%v, want authorization-required relogin", err)
			}
			if mutated {
				t.Fatal("mutation endpoint was called")
			}
		})
	}
}

func TestTeamEnsureTwoAccountsSameHomeRecordedOwnerIsolation(t *testing.T) {
	oldKey, oldExpected, oldJSON, oldHome := teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome
	teamEnsureWorkspaceKey = "aweb.ai/org/workspace"
	jsonFlag = true
	t.Cleanup(func() {
		teamEnsureWorkspaceKey, teamEnsureExpectedAccountID, jsonFlag, activeIdentityHome = oldKey, oldExpected, oldJSON, oldHome
	})
	wd := t.TempDir()
	t.Chdir(wd)
	hostHome := t.TempDir()
	t.Setenv("HOME", hostHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(hostHome, ".config"))
	teamID := "default:workspace.aweb.ai"
	canonicalTeamID := "default:workspace.aweb.ai"
	_, teamPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	mutationCounts := map[string]int{"acct-a": 0, "acct-b": 0}
	serverURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner := ""
		switch r.Header.Get("Authorization") {
		case "Bearer access-a":
			owner = "acct-a"
		case "Bearer access-b":
			owner = "acct-b"
		}
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			if owner == "" {
				t.Fatalf("unexpected Authorization=%q", r.Header.Get("Authorization"))
			}
			handle := map[string]string{"acct-a": "alice", "acct-b": "bob"}[owner]
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized", "account": map[string]string{"id": owner, "handle": handle}})
		case workspaceTeamEnsurePath:
			mutationCounts[owner]++
			var req workspaceTeamEnsureRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.ExpectedAccountID != owner {
				t.Fatalf("ensure expected_account_id=%q owner=%q", req.ExpectedAccountID, owner)
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
		case workspaceTeamEnrollPath:
			mutationCounts[owner]++
			var req workspaceTeamEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.ExpectedAccountID != owner {
				t.Fatalf("enroll expected_account_id=%q owner=%q", req.ExpectedAccountID, owner)
			}
			verifyWorkspaceTeamEnrollProofForTest(t, req, serverURL, owner)
			cert, err := awid.SignTeamCertificate(teamPriv, awid.TeamCertificateFields{Team: canonicalTeamID, MemberDIDKey: req.Identity.DID, Alias: req.Identity.Alias, IdentityScope: req.Identity.IdentityScope})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(workspaceTeamEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-" + owner, AgentID: "agent-" + owner, Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: true, TeamCert: encoded})
		case "/api/v1/spawn/authority":
			_ = json.NewEncoder(w).Encode(teamSpawnAuthorityOutput{TeamID: teamID, ActorAgentID: "agent-" + owner, AuthKind: "team_key", LiveAgent: true, CanSpawn: true})
		case "/v1/agents/heartbeat", "/api/v1/agents/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverURL = server.URL
	saveAuth := func(access string) {
		t.Helper()
		if err := saveCLIAuthConfig(cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: access, RefreshToken: "refresh-" + access, TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	runEnsure := func(identityHome, expected string) error {
		t.Helper()
		activeIdentityHome = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
		teamEnsureExpectedAccountID = expected
		cmd := &cobra.Command{Use: "test"}
		cmd.SetOut(&bytes.Buffer{})
		return runTeamEnsure(t.Context(), cmd)
	}
	home1 := filepath.Join(wd, "home1")
	home2 := filepath.Join(wd, "home2")
	saveAuth("access-a")
	if err := runEnsure(home1, "acct-a"); err != nil {
		t.Fatalf("home1 account A ensure: %v", err)
	}
	binding1, err := loadWorkspaceTeamBindingMarker(home1)
	if err != nil {
		t.Fatal(err)
	}
	if binding1 == nil || binding1.ExpectedAccountID != "acct-a" || binding1.AccountHandle != "alice" {
		t.Fatalf("home1 binding after A=%+v", binding1)
	}
	beforeA, beforeB := mutationCounts["acct-a"], mutationCounts["acct-b"]
	saveAuth("access-b")
	err = runEnsure(home1, "")
	if err == nil || !strings.Contains(err.Error(), "alice (acct-a)") || !strings.Contains(err.Error(), "bob (acct-b)") {
		t.Fatalf("home1 retry as B err=%v, want owner mismatch", err)
	}
	if mutationCounts["acct-a"] != beforeA || mutationCounts["acct-b"] != beforeB {
		t.Fatalf("mutation counts changed after mismatch: before A=%d B=%d after=%v", beforeA, beforeB, mutationCounts)
	}
	if err := runEnsure(home2, "acct-b"); err != nil {
		t.Fatalf("home2 account B ensure: %v", err)
	}
	binding2, err := loadWorkspaceTeamBindingMarker(home2)
	if err != nil {
		t.Fatal(err)
	}
	if binding2 == nil || binding2.ExpectedAccountID != "acct-b" || binding2.AccountHandle != "bob" {
		t.Fatalf("home2 binding after B=%+v", binding2)
	}
	binding1Again, err := loadWorkspaceTeamBindingMarker(home1)
	if err != nil {
		t.Fatal(err)
	}
	if binding1Again == nil || binding1Again.ExpectedAccountID != "acct-a" || binding1Again.AccountHandle != "alice" {
		t.Fatalf("home1 binding changed after home2 B=%+v", binding1Again)
	}
}

func TestSelectExpectedWorkspaceTeamAccountIDNormalizesCase(t *testing.T) {
	got, err := selectExpectedWorkspaceTeamAccountID("550E8400-E29B-41D4-A716-446655440000", nil, cliAuthAccount{ID: "550e8400-e29b-41d4-a716-446655440000", Handle: "alice"})
	if err != nil {
		t.Fatalf("select expected account: %v", err)
	}
	if got != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("normalized id=%q", got)
	}
}
