package main

import (
	"bytes"
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
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	root := t.TempDir()
	t.Chdir(root)

	var created implicitLocalInitRequest
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		created = req
		if err := os.MkdirAll(filepath.Join(req.WorkingDir, ".aw"), 0o755); err != nil {
			return connectOutput{}, err
		}
		if err := os.WriteFile(filepath.Join(req.WorkingDir, ".aw", "workspace.yaml"), []byte("team_id: eng:local\nalias: eng\n"), 0o600); err != nil {
			return connectOutput{}, err
		}
		return connectOutput{Status: "connected", TeamID: "eng:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-eng"}, nil
	}
	teamHumanAddEmptyAgent = func(anchorDir, homeDir, alias string, global bool) (*acceptedTeamInvite, error) {
		if anchorDir != root {
			t.Fatalf("anchorDir=%q, want %q", anchorDir, root)
		}
		if global {
			t.Fatal("empty e2e should add local agent")
		}
		if err := os.MkdirAll(filepath.Join(homeDir, ".aw"), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(homeDir, ".aw", "workspace.yaml"), []byte("team_id: eng:local\nalias: "+alias+"\n"), 0o600); err != nil {
			return nil, err
		}
		return &acceptedTeamInvite{Output: &teamAcceptInviteOutput{Status: "accepted", TeamID: "eng:local", Alias: alias, CertPath: filepath.Join(homeDir, ".aw", "team-certificates", "eng-local.jwt")}}, nil
	}

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("team create: %v", err)
	}
	if created.TeamName != "eng" || created.Alias != "eng" {
		t.Fatalf("created request=%+v, want team/alias eng", created)
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
