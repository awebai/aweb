package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/internal/profilepack"
)

func TestLocalSurfaceE2EEmptyProfileCreateAddStartFailure(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	resetAgentRuntimeGlobals(t)
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
	agentHomeFlag = home
	err := runAgentStart(nil, []string{"developer"})
	if err == nil || !strings.Contains(err.Error(), "profile materialization missing") {
		t.Fatalf("start unmaterialized empty home error=%v", err)
	}
}

func TestLocalSurfaceE2ELibraryBoundCreateAndAdd(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AW_CONFIG_PATH", "")

	profileFiles := func(profileRef string) []profilepack.LibraryProfilePayloadFile {
		return []profilepack.LibraryProfilePayloadFile{
			{Path: "profile.yaml", ContentUTF8: "id: " + profileRef + "\nname: " + profileRef + "\nversion: 0.1.0\nmission: Work with the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", ContentUTF8: "Work together.\n"},
		}
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

	var importCalls, bindCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/.well-known/aweb-app.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + serverOriginForTest(r) + `"},"tools":[{"name":"get-profile","auth":"none","method":"GET","path":"/v1/profile-packs/{pack_ref}/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"pack_ref":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"pack_ref","in":"path"},{"name":"profile_ref","in":"path"}],"mutation":false},{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_profile_pack_ref":{"type":"string"},"source_profile_pack_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_profile_pack_ref","in":"body"},{"name":"source_profile_pack_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_profile_pack_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_profile_pack_ref","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`))
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
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "alias": "eng", "agent_id": "agent-eng", "workspace_id": "workspace-eng", "repo_id": "", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent", "eng:local", "agent")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/profile-packs/aweb.engineering-pack/profiles/"):
			profileRef := strings.TrimPrefix(r.URL.Path, "/v1/profile-packs/aweb.engineering-pack/profiles/")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pack_ref":            "aweb.engineering-pack",
				"pack_version":        "0.1.0",
				"profile_ref":         profileRef,
				"version":             "0.1.0",
				"digest":              profileDigests[profileRef],
				"runtime_assumptions": []string{"local shell"},
				"runtime_hints":       runtimeHints(profileRef),
				"files":               profileFiles(profileRef),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shelf/import":
			importCalls++
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("import-to-shelf missing signed headers")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			profileRef, _ := body["profile_ref"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"profile_ref": profileRef, "version": "0.1.0", "digest": profileDigests[profileRef], "source_profile_pack_ref": "aweb.engineering-pack", "source_profile_pack_version": "0.1.0", "source_profile_pack_digest": "sha256:pack", "created": true})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/agents/") && strings.HasSuffix(r.URL.Path, "/profile-binding"):
			bindCalls++
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("bind missing signed headers")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			profileRef, _ := body["profile_ref"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/agents/"), "/profile-binding"), "profile_ref": profileRef, "profile_version": "0.1.0", "profile_digest": profileDigests[profileRef]})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/materialize":
			t.Fatalf("server materialize must not be called in local-compose flow")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	oldInitAwebURL := initAwebURL
	oldInitAWIDRegistry := initAWIDRegistry
	initAwebURL = server.URL
	initAWIDRegistry = server.URL
	t.Cleanup(func() {
		initAwebURL = oldInitAwebURL
		initAWIDRegistry = oldInitAWIDRegistry
	})
	if _, err := installManifestPlugin(server.URL, filepath.Join(filepath.Join(root, "home"), ".aw", "plugins")); err != nil {
		t.Fatalf("install library manifest: %v", err)
	}

	teamHumanCreateProfiles = []string{"aweb.engineering-pack/coordinator", "aweb.engineering-pack/reviewer"}
	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("team create roster --profile: %v", err)
	}
	for _, agent := range []string{"coordinator", "reviewer"} {
		agentHome := filepath.Join(root, "agents", "instances", agent)
		for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
			if _, err := os.Lstat(filepath.Join(agentHome, filepath.FromSlash(rel))); err != nil {
				t.Fatalf("profile-bound roster home %s missing %s: %v", agent, rel, err)
			}
		}
	}
	if _, err := os.Readlink(filepath.Join(root, "agents", "instances", "coordinator", "CLAUDE.md")); err != nil {
		t.Fatalf("coordinator claude-code home missing CLAUDE.md symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "reviewer", "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("reviewer pi home unexpectedly has CLAUDE.md (first supported runtime_hints should choose pi), stat err=%v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("team create roster materialized profile into cwd, stat err=%v", err)
	}

	teamHumanCreateProfiles = nil
	if err := os.Chdir(filepath.Join(root, "agents", "instances", "coordinator")); err != nil {
		t.Fatal(err)
	}
	teamHumanAddHome = filepath.Join(root, "auditor-home")
	if err := runTeamHumanAdd(nil, []string{"auditor@aweb.engineering-pack/coordinator"}); err != nil {
		t.Fatalf("team add profile: %v", err)
	}
	if err := runTeamHumanAdd(nil, []string{"auditor@aweb.engineering-pack/coordinator"}); err != nil {
		t.Fatalf("rerun team add profile: %v", err)
	}
	agentHome := teamHumanAddHome
	for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"} {
		if _, err := os.Lstat(filepath.Join(agentHome, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("profile-bound agent home missing %s: %v", rel, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "agents", "instances", "auditor")); !os.IsNotExist(err) {
		t.Fatalf("team add --home wrote default agent home, stat err=%v", err)
	}
	teamHumanAddHome = ""
	if importCalls != 4 || bindCalls != 4 {
		t.Fatalf("library calls import=%d bind=%d", importCalls, bindCalls)
	}
}

func testLibraryProfilePayloadDigestForProfile(t *testing.T, profileRef string, files []profilepack.LibraryProfilePayloadFile) string {
	t.Helper()
	result, err := profilepack.MaterializeLibraryProfilePayload(profilepack.MaterializeLibraryProfilePayloadOptions{
		TargetDir:      t.TempDir(),
		PackRef:        "aweb.engineering-pack",
		PackVersion:    "0.1.0",
		ProfileRef:     profileRef,
		ProfileVersion: "0.1.0",
		RuntimeKind:    "local-shell",
		Files:          files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.ProfileDigest
}

func TestLocalSurfaceE2ELocalPackMaterializeStartStatusStop(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	fixture := engineeringProfilePackFixtureRoot(t)
	home := t.TempDir()
	var materializeOut bytes.Buffer
	if err := runProfilePackMaterialize(&materializeOut, filepath.Join(fixture, "source"), "developer", home, false, false); err != nil {
		t.Fatalf("materialize local pack: %v", err)
	}
	for _, rel := range []string{"AGENTS.md", "CLAUDE.md", ".aw/profile/profile.yaml", "skills/implement/SKILL.md", "artifacts/handoff-template.md"} {
		if _, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("materialized home missing %s: %v", rel, err)
		}
	}
	profile, err := loadAgentProfileRuntime(home)
	if err != nil {
		t.Fatalf("load runtime assumptions: %v", err)
	}
	runtime, _, err := selectAgentRuntime(profile.RuntimeAssumptions, "", "")
	if err != nil {
		t.Fatalf("select runtime from assumptions %v: %v", profile.RuntimeAssumptions, err)
	}
	if runtime != "local-shell" {
		t.Fatalf("runtime=%q, want local-shell", runtime)
	}

	agentHomeFlag = home
	if err := runAgentStart(nil, []string{"developer"}); err != nil {
		t.Fatalf("agent start: %v", err)
	}
	defer func() { _ = runAgentStop(nil, []string{"developer"}) }()
	status, err := loadAgentStatus("developer", home)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Status != "running" || status.Runtime != "local-shell" || status.PID == 0 {
		t.Fatalf("status=%+v", status)
	}
	if err := runAgentStatus(nil, []string{"developer"}); err != nil {
		t.Fatalf("agent status command: %v", err)
	}
	if err := runAgentStop(nil, []string{"developer"}); err != nil {
		t.Fatalf("agent stop: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for processAlive(status.PID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if processAlive(status.PID) {
		t.Fatalf("agent pid %d still alive after stop", status.PID)
	}
}
