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
