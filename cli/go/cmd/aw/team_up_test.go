package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func resetTeamUpDetectorsForTest(t *testing.T) {
	t.Helper()
	oldDetect := teamUpDetectActiveHomes
	t.Cleanup(func() { teamUpDetectActiveHomes = oldDetect })
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) { return map[string]teamUpRunningProcess{}, nil }
}

func writeMaterializedAgentForTeamUp(t *testing.T, root, name, runtimeKind string) string {
	t.Helper()
	home := filepath.Join(root, "agents", "instances", name)
	if err := os.MkdirAll(filepath.Join(home, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aw", "profile", "profile.yaml"), []byte("id: "+name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := recordedProfileRef{ProfileRef: name, ProfileVersion: "0.1.0", ProfileDigest: "sha256:test", RuntimeKind: runtimeKind}
	data, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aw", "profile", "ref.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestTeamUpPlanEnumeratesMaterializedAgents(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	devHome := writeMaterializedAgentForTeamUp(t, root, "developer", "claude-code")
	piHome := writeMaterializedAgentForTeamUp(t, root, "reviewer", "pi")
	if err := os.MkdirAll(filepath.Join(root, "agents", "instances", "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	plan, err := buildTeamUpPlan(root, "eng:local", false, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	if plan.Session != "eng-local" {
		t.Fatalf("session=%q", plan.Session)
	}
	if len(plan.Agents) != 2 {
		t.Fatalf("agents=%+v", plan.Agents)
	}
	if plan.Agents[0].Name != "developer" || plan.Agents[0].HomeDir != devHome || plan.Agents[0].Action != teamUpActionStart || strings.Join(plan.Agents[0].Command, " ") != "claude --dangerously-skip-permissions --dangerously-load-development-channels server:aweb" {
		t.Fatalf("developer plan=%+v", plan.Agents[0])
	}
	if plan.Agents[1].Name != "reviewer" || plan.Agents[1].HomeDir != piHome || strings.Join(plan.Agents[1].Command, " ") != "pi" {
		t.Fatalf("reviewer plan=%+v", plan.Agents[1])
	}
}

func TestTeamUpPlanDefaultsMissingRuntimeKindToClaudeCode(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "")
	plan, err := buildTeamUpPlan(root, "", false, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	if got := plan.Agents[0].RuntimeKind; got != "claude-code" {
		t.Fatalf("runtime=%q", got)
	}
}

func TestTeamUpPlanRejectsUnsupportedRuntime(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "coder", "codex")
	_, err := buildTeamUpPlan(root, "aw-team", false, false)
	if err == nil || !strings.Contains(err.Error(), "only claude-code and pi are supported") {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamUpPlanSkipsHomeWithActiveProcess(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	home := writeMaterializedAgentForTeamUp(t, root, "developer", "claude-code")
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) {
		return map[string]teamUpRunningProcess{canonicalTeamUpPath(home): {PID: 123, Command: "node", CWD: home}}, nil
	}
	plan, err := buildTeamUpPlan(root, "aw-team", false, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	got := plan.Agents[0]
	if got.Action != teamUpActionSkip || got.RunningPID != 123 || !strings.Contains(got.Reason, "cwd") {
		t.Fatalf("agent plan=%+v", got)
	}
}

func TestTeamUpPlanForceIgnoresActiveProcess(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "claude-code")
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) {
		t.Fatal("active process detector should not run when force is true")
		return nil, nil
	}
	plan, err := buildTeamUpPlan(root, "aw-team", true, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	if got := plan.Agents[0].Action; got != teamUpActionStart {
		t.Fatalf("action=%q", got)
	}
}

func TestTeamUpPlanRecreateIgnoresActiveProcess(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "claude-code")
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) {
		t.Fatal("active process detector should not run when recreate is true")
		return nil, nil
	}
	plan, err := buildTeamUpPlan(root, "aw-team", false, true)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	if got := plan.Agents[0].Action; got != teamUpActionStart {
		t.Fatalf("action=%q", got)
	}
}

func TestPrintTeamUpDryRunPlan(t *testing.T) {
	oldJSON := jsonFlag
	jsonFlag = false
	t.Cleanup(func() { jsonFlag = oldJSON })
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{{Name: "developer", HomeDir: "/tmp/dev", RuntimeKind: "claude-code", Command: []string{"claude", "--dangerously-skip-permissions", "--dangerously-load-development-channels", "server:aweb"}, Action: teamUpActionStart}}}
	var out bytes.Buffer
	if err := printTeamUpPlan(&out, plan); err != nil {
		t.Fatalf("printTeamUpPlan: %v", err)
	}
	text := out.String()
	for _, want := range []string{"tmux session: aw-team", "reconcile: 1 to start, 0 already up", "developer (claude-code): start", "claude --dangerously-skip-permissions --dangerously-load-development-channels server:aweb"} {
		if !strings.Contains(text, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, text)
		}
	}
}

func TestTeamUpCommandRegistered(t *testing.T) {
	cmd, _, err := teamHumanCmd.Find([]string{"up"})
	if err != nil || cmd == nil || cmd.Name() != "up" {
		t.Fatalf("team up command missing: cmd=%v err=%v", cmd, err)
	}
}
