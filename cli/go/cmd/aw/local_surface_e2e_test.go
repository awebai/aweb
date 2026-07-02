package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
)

func TestLocalSurfaceE2EEmptyProfileCreateAdd(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AW_CONFIG_PATH", "")

	var sawTeamCreate, sawCertificate bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": "", "aweb_url": r.Host, "registry_url": r.Host})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"namespace_id": "ns-local", "domain": "local", "controller_did": body["controller_did"], "verification_status": "verified", "created_at": "2026-06-19T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "eng" {
				t.Fatalf("team create name=%v, want eng", body["name"])
			}
			sawTeamCreate = true
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "domain": "local", "name": "eng", "display_name": "", "team_did_key": body["team_did_key"], "visibility": "private", "created_at": "2026-06-19T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/eng/certificates":
			sawCertificate = true
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "alias": "eng", "agent_id": "agent-eng", "workspace_id": "workspace-eng", "repo_id": "", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent", "eng:local", "developer")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	oldInitAwebURL := initAwebURL
	oldInitAWIDRegistry := initAWIDRegistry
	initAwebURL = server.URL
	initAWIDRegistry = server.URL
	t.Cleanup(func() {
		initAwebURL = oldInitAwebURL
		initAWIDRegistry = oldInitAWIDRegistry
	})

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("team create: %v", err)
	}
	if !sawTeamCreate || !sawCertificate {
		t.Fatalf("real init_local did not create team/certificate: team=%v cert=%v", sawTeamCreate, sawCertificate)
	}
	if err := runTeamHumanAdd(nil, []string{"developer"}); err != nil {
		t.Fatalf("team add: %v", err)
	}
	home := filepath.Join(root, "agents", "instances", "developer")
	for _, rel := range []string{".aw"} {
		if info, err := os.Stat(filepath.Join(home, rel)); err != nil || !info.IsDir() {
			t.Fatalf("identity-only home missing %s: info=%v err=%v", rel, info, err)
		}
	}
	for _, rel := range []string{"AGENTS.md", ".aw/profile", "skills", "artifacts"} {
		if _, err := os.Stat(filepath.Join(home, rel)); !os.IsNotExist(err) {
			t.Fatalf("empty-profile home unexpectedly has %s (err=%v)", rel, err)
		}
	}
}

func TestLocalSurfaceE2ELibraryBoundCreateAndAdd(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AW_CONFIG_PATH", "")

	profileFiles := func(profileRef string) []blueprint.LibraryProfilePayloadFile {
		return withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
			{Path: "profile.yaml", ContentUTF8: "id: " + profileRef + "\nname: " + profileRef + "\nversion: 0.1.0\nmission: Work with the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", ContentUTF8: "Work together.\n"},
		})
	}
	profileDigests := map[string]string{}
	for _, profileRef := range []string{"coordinator", "reviewer"} {
		profileDigests[profileRef] = testLibraryProfilePayloadDigestForProfile(t, profileRef, profileFiles(profileRef))
	}
	runtimeHints := func(profileRef string) []string {
		switch profileRef {
		case "coordinator":
			return []string{"claude-code"}
		case "reviewer":
			return []string{"pi", "claude-code"}
		default:
			return nil
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/aweb-app.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + serverOriginForTest(r) + `"},"tools":[{"name":"get-profile","auth":"none","method":"GET","path":"/v1/blueprints/{blueprint_ref}/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"blueprint_ref":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"blueprint_ref","in":"path"},{"name":"profile_ref","in":"path"}],"mutation":false},{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_blueprint_ref":{"type":"string"},"source_blueprint_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_blueprint_ref","in":"body"},{"name":"source_blueprint_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_blueprint_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_blueprint_ref","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": "", "aweb_url": r.Host, "registry_url": r.Host})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"namespace_id": "ns-local", "domain": "local", "controller_did": body["controller_did"], "verification_status": "verified", "created_at": "2026-06-19T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "domain": "local", "name": "eng", "display_name": "", "team_did_key": body["team_did_key"], "visibility": "private", "created_at": "2026-06-19T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/eng/certificates":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/eng/certificates/revoke":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"certificate_id": body["certificate_id"]})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "alias": "coordinator", "agent_id": "agent-coordinator", "workspace_id": "workspace-coordinator", "repo_id": "", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-coordinator", "eng:local", "coordinator")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/blueprints/aweb.engineering/profiles/"):
			profileRef := strings.TrimPrefix(r.URL.Path, "/v1/blueprints/aweb.engineering/profiles/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blueprint_ref":       "aweb.engineering",
				"blueprint_version":   "0.1.0",
				"profile_ref":         profileRef,
				"version":             "0.1.0",
				"digest":              profileDigests[profileRef],
				"runtime_assumptions": []string{"local shell"},
				"runtime_hints":       runtimeHints(profileRef),
				"files":               profileFiles(profileRef),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shelf/import":
			t.Fatalf("public team materialization must not import to the private shelf")
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/agents/") && strings.HasSuffix(r.URL.Path, "/profile-binding"):
			t.Fatalf("public team materialization must not bind via the Library plugin")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/materialize":
			t.Fatalf("server materialize must not be called in local-compose flow")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	oldInitAwebURL := initAwebURL
	oldInitAWIDRegistry := initAWIDRegistry
	initAwebURL = server.URL
	initAWIDRegistry = server.URL
	t.Cleanup(func() {
		initAwebURL = oldInitAwebURL
		initAWIDRegistry = oldInitAWIDRegistry
	})
	teamHumanCreateProfiles = []string{"aweb.engineering/coordinator=claude-code", "aweb.engineering/reviewer=pi"}
	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("team create roster --profile: %v", err)
	}
	for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("first listed create agent home missing %s in cwd: %v", rel, err)
		}
	}
	assertMaterializedHomeHasAwebCoordination(t, root)
	if _, err := os.Readlink(filepath.Join(root, "CLAUDE.md")); err != nil {
		t.Fatalf("coordinator claude-code home missing CLAUDE.md symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "coordinator")); !os.IsNotExist(err) {
		t.Fatalf("team create --profile created extra profile-less/default coordinator home, stat err=%v", err)
	}
	reviewerHome := filepath.Join(root, "agents", "instances", "reviewer")
	for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
		if _, err := os.Lstat(filepath.Join(reviewerHome, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("profile-bound roster home reviewer missing %s: %v", rel, err)
		}
	}
	assertMaterializedHomeHasAwebCoordination(t, reviewerHome)
	if _, err := os.Lstat(filepath.Join(reviewerHome, "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("reviewer pi home unexpectedly has CLAUDE.md (first supported runtime_hints should choose pi), stat err=%v", err)
	}

	teamHumanCreateProfiles = nil
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	teamHumanAddHome = filepath.Join(root, "auditor-home")
	teamHumanAddRuntime = "local-shell"
	if err := runTeamHumanAdd(nil, []string{"auditor@aweb.engineering/coordinator"}); err != nil {
		t.Fatalf("team add profile: %v", err)
	}
	if err := runTeamHumanAdd(nil, []string{"auditor@aweb.engineering/coordinator"}); err != nil {
		t.Fatalf("rerun team add profile: %v", err)
	}
	agentHome := teamHumanAddHome
	for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
		if _, err := os.Lstat(filepath.Join(agentHome, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("profile-bound agent home missing %s: %v", rel, err)
		}
	}
	assertMaterializedHomeHasAwebCoordination(t, agentHome)
	if _, err := os.Lstat(filepath.Join(agentHome, "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("auditor local-shell home unexpectedly has CLAUDE.md, stat err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "auditor")); !os.IsNotExist(err) {
		t.Fatalf("team add --home wrote default agent home, stat err=%v", err)
	}
	teamHumanAddRuntime = ""
	teamHumanAddHome = ""
	for _, tc := range []struct {
		name        string
		prepareHome func(t *testing.T, home string) (outsidePath string, wantContent string)
	}{
		{
			name: "unsafeclaudedir",
			prepareHome: func(t *testing.T, home string) (string, string) {
				t.Helper()
				outsideDir := t.TempDir()
				outside := filepath.Join(outsideDir, "settings.json")
				if err := os.Symlink(outsideDir, filepath.Join(home, ".claude")); err != nil {
					t.Fatal(err)
				}
				return outside, ""
			},
		},
		{
			name: "unsafeclaudesettings",
			prepareHome: func(t *testing.T, home string) (string, string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "settings.json")
				want := `{"hooks":{}}`
				if err := os.WriteFile(outside, []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(home, ".claude", "settings.json")); err != nil {
					t.Fatal(err)
				}
				return outside, want
			},
		},
	} {
		t.Run("unsafe coordination config "+tc.name, func(t *testing.T) {
			unsafeHome := filepath.Join(root, tc.name+"-home")
			if err := os.MkdirAll(unsafeHome, 0o755); err != nil {
				t.Fatal(err)
			}
			outsidePath, wantContent := tc.prepareHome(t, unsafeHome)
			teamHumanAddHome = unsafeHome
			err := runTeamHumanAdd(nil, []string{tc.name + "@aweb.engineering/coordinator"})
			teamHumanAddHome = ""
			if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
				t.Fatalf("unsafe profile add error=%v", err)
			}
			data, readErr := os.ReadFile(outsidePath)
			if wantContent == "" {
				if !os.IsNotExist(readErr) {
					t.Fatalf("outside settings created through symlink: data=%q err=%v", data, readErr)
				}
			} else if readErr != nil || string(data) != wantContent {
				t.Fatalf("outside file mutated: data=%q err=%v", data, readErr)
			}
		})
	}
}

// TestHostedTeamAddProfiledAgentMaterializesAndAppliesRuntime is the homepage
// case: a hosted-team owner with a connected workspace (no local team key) runs
// `aw team add NAME@BLUEPRINT/PROFILE=RUNTIME`. The listed agent must mint via
// the owner's hosted member authority (spawn create/accept-invite), materialize
// the Library profile into its own home, and apply the requested runtime.
func TestHostedTeamAddProfiledAgentMaterializesAndAppliesRuntime(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	root := t.TempDir()
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	teamID := "default:gracehosted.aweb.ai"
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	profileFiles := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: reviewer\nname: Reviewer\nversion: 0.1.0\nmission: Review work.\naccepted_work: [review]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Review carefully.\n"},
	})
	profileDigest := testLibraryProfilePayloadDigestForProfile(t, "reviewer", profileFiles)

	var createInviteCalls, acceptInviteCalls int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/create-invite":
			cert := requireCertificateAuthForTest(t, r)
			if cert.Team != teamID {
				t.Fatalf("create invite cert team=%q want %q", cert.Team, teamID)
			}
			createInviteCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":      "invite-hosted-1",
				"token":          "aw_inv_hosted_add_token",
				"token_prefix":   "hosted_t",
				"access_mode":    "open",
				"max_uses":       1,
				"expires_at":     "2026-08-17T00:00:00Z",
				"namespace_slug": "gracehosted",
				"namespace":      "gracehosted.aweb.ai",
				"server_url":     server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			acceptInviteCalls++
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatal(err)
			}
			didKey, _ := req["did"].(string)
			if didKey == "" {
				t.Fatal("accept request missing did")
			}
			alias, _ := req["alias"].(string)
			cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{
				Team:         teamID,
				MemberDIDKey: didKey,
				Alias:        alias,
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "server-team-id",
				"team_slug":      "default",
				"namespace_slug": "gracehosted",
				"namespace":      "gracehosted.aweb.ai",
				"identity_id":    "agent-" + alias,
				"alias":          alias,
				"api_key":        "aw_sk_child_not_printed",
				"server_url":     server.URL,
				"did":            didKey,
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
				"created":        true,
				"team_cert":      encoded,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"onboarding_url": server.URL, "aweb_url": server.URL, "registry_url": server.URL})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": teamID, "alias": "rev", "agent_id": "agent-rev", "workspace_id": "workspace-rev", "repo_id": "", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-rev", "gracehosted.aweb.ai", "rev")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/blueprints/aweb.engineering/profiles/"):
			profileRef := strings.TrimPrefix(r.URL.Path, "/v1/blueprints/aweb.engineering/profiles/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blueprint_ref":       "aweb.engineering",
				"blueprint_version":   "0.1.0",
				"profile_ref":         profileRef,
				"version":             "0.1.0",
				"digest":              profileDigest,
				"runtime_assumptions": []string{"local shell"},
				"runtime_hints":       []string{"pi", "claude-code"},
				"files":               profileFiles,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shelf/import":
			t.Fatalf("public team materialization must not import to the private shelf")
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/agents/") && strings.HasSuffix(r.URL.Path, "/profile-binding"):
			t.Fatalf("public team materialization must not bind via the Library plugin")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/materialize":
			t.Fatalf("server materialize must not be called in local-compose flow")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)

	// The owner's connected workspace: hosted membership, cert, and signing key,
	// but no local team key (hosted authority mints via the member cert).
	ownerDir := filepath.Join(root, "owner")
	if err := os.MkdirAll(ownerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceBindingForTest(t, ownerDir, awconfig.WorktreeWorkspace{
		AwebURL: server.URL,
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "owner",
			WorkspaceID: "workspace-owner",
			CertPath:    awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-05-16T00:00:00Z",
		}},
	})
	t.Chdir(ownerDir)

	teamHumanAddRuntime = ""
	if err := runTeamHumanAdd(nil, []string{"rev@aweb.engineering/reviewer=pi"}); err != nil {
		t.Fatalf("hosted team add profiled agent: %v", err)
	}

	if createInviteCalls != 1 || acceptInviteCalls != 1 {
		t.Fatalf("hosted mint calls create=%d accept=%d", createInviteCalls, acceptInviteCalls)
	}
	agentHome := filepath.Join(ownerDir, "agents", "instances", "rev")
	// Profile materialized into the agent's own home.
	for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
		if _, err := os.Lstat(filepath.Join(agentHome, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("profile-bound agent home missing %s: %v", rel, err)
		}
	}
	assertMaterializedHomeHasAwebCoordination(t, agentHome)
	// =pi runtime applied: the pi runtime must not write a claude-code CLAUDE.md.
	if _, err := os.Lstat(filepath.Join(agentHome, "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("=pi runtime unexpectedly wrote CLAUDE.md, stat err=%v", err)
	}
	// The freshly-minted agent identity is recorded in its home.
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(agentHome, teamID))
	if err != nil {
		t.Fatalf("load minted agent cert: %v", err)
	}
	if cert.Team != teamID || cert.Alias != "rev" {
		t.Fatalf("minted cert team=%q alias=%q", cert.Team, cert.Alias)
	}
}

func assertMaterializedHomeHasAwebCoordination(t *testing.T, home string) {
	t.Helper()
	agents, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	text := string(agents)
	for _, want := range []string{awDocsMarkerStart, "Use aw.", awDocsMarkerEnd} {
		if !strings.Contains(text, want) {
			t.Fatalf("AGENTS.md missing coordination block %q:\n%s", want, text)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".mcp.json")); !os.IsNotExist(err) {
		t.Fatalf("materialized home unexpectedly has per-home channel .mcp.json: %v", err)
	}
	hooksRaw, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("materialized home missing Claude hook config: %v", err)
	}
	if !strings.Contains(string(hooksRaw), notifyHookCommand) {
		t.Fatalf("Claude settings missing notify hook: %s", hooksRaw)
	}
}

func testLibraryProfilePayloadDigestForProfile(t *testing.T, profileRef string, files []blueprint.LibraryProfilePayloadFile) string {
	t.Helper()
	result, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        t.TempDir(),
		BlueprintRef:     "aweb.engineering",
		BlueprintVersion: "0.1.0",
		ProfileRef:       profileRef,
		ProfileVersion:   "0.1.0",
		RuntimeKind:      "local-shell",
		Files:            files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.ProfileDigest
}
