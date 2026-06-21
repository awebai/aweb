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

	"github.com/awebai/aw/internal/blueprint"
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

	profileFiles := func(profileRef string) []blueprint.LibraryProfilePayloadFile {
		return []blueprint.LibraryProfilePayloadFile{
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
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "alias": "eng", "agent_id": "agent-eng", "workspace_id": "workspace-eng", "repo_id": "", "team_did_key": "did:key:z6MkiTeam"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodGet && (r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent", "eng:local", "agent")
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
			importCalls++
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("import-to-shelf missing signed headers")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			profileRef, _ := body["profile_ref"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"profile_ref": profileRef, "version": "0.1.0", "digest": profileDigests[profileRef], "source_blueprint_ref": "aweb.engineering", "source_blueprint_version": "0.1.0", "source_blueprint_digest": "sha256:blueprint", "created": true})
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

	teamHumanCreateProfiles = []string{"aweb.engineering/coordinator=claude-code", "aweb.engineering/reviewer=pi"}
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
		assertMaterializedHomeHasAwebCoordination(t, agentHome)
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
	if importCalls != 4 || bindCalls != 4 {
		t.Fatalf("library calls import=%d bind=%d", importCalls, bindCalls)
	}

	for _, tc := range []struct {
		name        string
		prepareHome func(t *testing.T, home string) (outsidePath string, wantContent string)
	}{
		{
			name: "unsafemcp",
			prepareHome: func(t *testing.T, home string) (string, string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "outside-mcp.json")
				want := `{"mcpServers":{}}`
				if err := os.WriteFile(outside, []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, filepath.Join(home, ".mcp.json")); err != nil {
					t.Fatal(err)
				}
				return outside, want
			},
		},
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
	mcpRaw, err := os.ReadFile(filepath.Join(home, ".mcp.json"))
	if err != nil {
		t.Fatalf("materialized home missing channel MCP config: %v", err)
	}
	var mcp map[string]any
	if err := json.Unmarshal(mcpRaw, &mcp); err != nil {
		t.Fatalf("invalid .mcp.json: %v", err)
	}
	servers, _ := mcp["mcpServers"].(map[string]any)
	if _, ok := servers["aweb"]; !ok {
		t.Fatalf(".mcp.json missing aweb server: %s", mcpRaw)
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

func TestLocalSurfaceE2ELocalPackMaterializeStartStatusStop(t *testing.T) {
	resetAgentRuntimeGlobals(t)
	fixture := engineeringBlueprintFixtureRoot(t)
	home := t.TempDir()
	var materializeOut bytes.Buffer
	if err := runBlueprintMaterialize(&materializeOut, filepath.Join(fixture, "source"), "developer", home, false, false); err != nil {
		t.Fatalf("materialize local blueprint: %v", err)
	}
	for _, rel := range []string{"AGENTS.md", "CLAUDE.md", ".aw/profile/profile.yaml", "skills/implement/SKILL.md", "artifacts/handoff-template.md"} {
		if _, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("materialized home missing %s: %v", rel, err)
		}
	}
	agentHomeFlag = home
	if err := runAgentStart(nil, []string{"developer"}); err == nil || !strings.Contains(err.Error(), "runtime is required") {
		t.Fatalf("agent start without explicit runtime error=%v", err)
	}
	agentRuntimeFlag = "local-shell"
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
