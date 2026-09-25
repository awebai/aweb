package main

import (
	"bytes"
	"encoding/json"
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

func TestTeamEnsureReportsUnsupportedServerDiagnostics(t *testing.T) {
	cases := []struct {
		name      string
		missing   string
		wantPath  string
		wantStage string
	}{
		{name: "cli auth status", missing: "/api/v1/cli-auth/status", wantPath: "/api/v1/cli-auth/status", wantStage: "CLI auth status"},
		{name: "ensure", missing: personalWorkspaceEnsurePath, wantPath: personalWorkspaceEnsurePath, wantStage: "personal workspace ensure"},
		{name: "enroll", missing: personalWorkspaceEnrollPath, wantPath: personalWorkspaceEnrollPath, wantStage: "personal workspace enroll"},
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
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
				case personalWorkspaceEnsurePath:
					_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
				case personalWorkspaceEnrollPath:
					var req personalWorkspaceEnrollRequest
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
					_ = json.NewEncoder(w).Encode(personalWorkspaceEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-unsupported", AgentID: "agent-unsupported", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: true, TeamCert: encoded})
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case personalWorkspaceEnsurePath:
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
			if strings.Contains(body["workspace_key_sha256"].(string), "workspace") {
				t.Fatalf("digest leaked raw workspace key: %#v", body)
			}
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID, Label: "Demo"})
		case personalWorkspaceEnrollPath:
			enrollCount++
			if got := r.Header.Get("Authorization"); got != "Bearer awcli_test" {
				t.Fatalf("enroll Authorization=%q", got)
			}
			var req personalWorkspaceEnrollRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Identity.Alias != "demo" && req.Identity.Alias != "demo_workspace" && req.Identity.Alias != "demoworkspace" {
				t.Fatalf("alias=%q", req.Identity.Alias)
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
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-1", AgentID: "agent-1", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: false, APIKeyCreated: false, TeamCert: encoded, SpawnAuthorityCheck: &personalWorkspaceSpawnAdvisory{TeamID: teamID, CanSpawn: false}})
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
	if _, err := os.Stat(filepath.Join(identityHome, "personal-workspace-ensure.yaml")); err != nil {
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
	if _, err := os.Stat(filepath.Join(identityHome, "personal-workspace-ensure.yaml")); !os.IsNotExist(err) {
		t.Fatalf("partial state was not removed after bind: %v", err)
	}
	bindingPath, err := personalWorkspaceBindingPath(identityHome)
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
	if decoded.Status != "bound" || !decoded.CanSpawn || decoded.TeamID != teamID || decoded.CanonicalTeamID != canonicalTeamID || decoded.Created {
		t.Fatalf("output=%+v", decoded)
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case personalWorkspaceEnsurePath:
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: "personal:team", CanonicalTeamID: "default:personal.aweb.ai"})
		case personalWorkspaceEnrollPath:
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case personalWorkspaceEnsurePath:
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: "personal:team", CanonicalTeamID: "default:personal.aweb.ai"})
		case personalWorkspaceEnrollPath:
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case personalWorkspaceEnsurePath:
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
		case personalWorkspaceEnrollPath:
			var req personalWorkspaceEnrollRequest
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
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-global", AgentID: "agent-global", Alias: req.Identity.Alias, DID: did, StableID: stableID, IdentityScope: awid.IdentityModeGlobal, Created: true, APIKeyCreated: false, TeamCert: encoded})
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case personalWorkspaceEnsurePath:
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnsureResponse{State: "ready", TeamID: teamID, CanonicalTeamID: canonicalTeamID})
		case personalWorkspaceEnrollPath:
			var req personalWorkspaceEnrollRequest
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
			_ = json.NewEncoder(w).Encode(personalWorkspaceEnrollResponse{State: "enrolled", TeamID: teamID, CanonicalTeamID: canonicalTeamID, IdentityID: "ident-no-spawn", AgentID: "agent-no-spawn", Alias: req.Identity.Alias, DID: req.Identity.DID, IdentityScope: req.Identity.IdentityScope, Created: true, APIKeyCreated: false, TeamCert: encoded, SpawnAuthorityCheck: &personalWorkspaceSpawnAdvisory{TeamID: teamID, CanSpawn: true}})
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
	bindingPath, pathErr := personalWorkspaceBindingPath(identityHome)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if _, statErr := os.Stat(bindingPath); !os.IsNotExist(statErr) {
		t.Fatalf("binding marker exists after failed spawn authority: %v", statErr)
	}
}

func writeCLIAuthConfigForTeamEnsureTest(t *testing.T, issuer string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	if err := saveCLIAuthConfig(cliAuthConfig{Issuer: issuer, Resource: cliAuthResource(issuer), Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "awcli_test", RefreshToken: "awcli_refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatalf("save auth config: %v", err)
	}
}
