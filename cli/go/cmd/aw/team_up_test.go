package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func resetTeamUpDetectorsForTest(t *testing.T) {
	t.Helper()
	oldDetect := teamUpDetectActiveHomes
	t.Cleanup(func() { teamUpDetectActiveHomes = oldDetect })
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) { return map[string]teamUpRunningProcess{}, nil }
}

func resetTeamUpTmuxForTest(t *testing.T) {
	t.Helper()
	oldExists := teamUpSessionExists
	oldRun := teamUpRunTmux
	oldOutput := teamUpRunTmuxOutput
	oldGuardedPath := teamUpGuardedAgentPath
	oldWait := teamUpConfirmClaudePromptWait
	t.Cleanup(func() {
		teamUpSessionExists = oldExists
		teamUpRunTmux = oldRun
		teamUpRunTmuxOutput = oldOutput
		teamUpGuardedAgentPath = oldGuardedPath
		teamUpConfirmClaudePromptWait = oldWait
	})
	teamUpGuardedAgentPath = func() (string, error) { return "/guard/bin:/usr/bin:/bin", nil }
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
	// A materialized home records where it is; the launcher requires it to be right.
	writeTeamUpWorkspaceYAML(t, home, home)
	return home
}

// writeTeamUpWorkspaceYAML writes a workspace.yaml recording recordedPath as the home's
// own location. A copied home keeps the ORIGINAL's path here, which is what the launcher
// refuses on, so tests pass the two independently.
func writeTeamUpWorkspaceYAML(t *testing.T, home, recordedPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(home, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "aweb_url: https://aweb.invalid\n" +
		"memberships:\n" +
		"  - team_id: eng:local\n" +
		"    cert_path: team-certs/eng__local.pem\n" +
		"workspace_path: " + recordedPath + "\n"
	if err := os.WriteFile(filepath.Join(home, ".aw", "workspace.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
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
	if plan.Agents[0].Name != "developer" || plan.Agents[0].HomeDir != devHome || plan.Agents[0].Action != teamUpActionStart || strings.Join(plan.Agents[0].Command, " ") != "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace" {
		t.Fatalf("developer plan=%+v", plan.Agents[0])
	}
	if plan.Agents[1].Name != "reviewer" || plan.Agents[1].HomeDir != piHome || strings.Join(plan.Agents[1].Command, " ") != "pi --approve" {
		t.Fatalf("reviewer plan=%+v", plan.Agents[1])
	}
}

func TestTeamUpPlanNormalizesDottedSessionNameForTmux(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	plan, err := buildTeamUpPlan(root, "aweb-juan.aweb.ai", false, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}
	if got, want := plan.Session, "aweb-juan_aweb_ai"; got != want {
		t.Fatalf("session=%q, want %q", got, want)
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

func TestPreflightTeamUpCommandsWithoutTmuxPrintsManualFallback(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{
		{Name: "developer", HomeDir: "/work/agents/instances/developer", RuntimeKind: "claude-code", Command: []string{"claude", "--dangerously-skip-permissions", "--dangerously-load-development-channels", claudeChannelSpec}, Action: teamUpActionStart},
		{Name: "reviewer", HomeDir: "/work/agents/instances/reviewer", RuntimeKind: "pi", Command: []string{"pi", "--approve"}, Action: teamUpActionStart},
	}}

	err := preflightTeamUpCommands(plan)
	if err == nil {
		t.Fatal("expected tmux guidance error")
	}
	text := err.Error()
	for _, want := range []string{
		"Install tmux, then re-run `aw team up`",
		"With tmux installed, `aw team up` automatically starts and wires every agent",
		"channel plugin",
		"trust/dev-channel prompts",
		"pi --approve",
		"developer (claude-code)",
		"cd '/work/agents/instances/developer' && claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace",
		"reviewer (pi)",
		"cd '/work/agents/instances/reviewer' && pi --approve",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("tmux fallback guidance missing %q:\n%s", want, text)
		}
	}
}

func TestPreflightTeamUpCommandsEnsuresPiChannelExtensionForStartingPiAgent(t *testing.T) {
	withFakeCommandOnPath(t, "tmux")
	withFakePiOnPath(t)
	calls := withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		return []byte("User packages:\n  npm:@awebai/pi\n"), nil
	})
	plan := teamUpPlan{Agents: []teamUpAgentPlan{{Name: "reviewer", RuntimeKind: "pi", Action: teamUpActionStart}}}
	if err := preflightTeamUpCommands(plan); err != nil {
		t.Fatalf("preflightTeamUpCommands: %v", err)
	}
	want := [][]string{{"list", "--no-approve"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("pi ensure calls=%v, want %v", *calls, want)
	}
}

func TestPreflightTeamUpCommandsSkipsPiEnsureWhenPiAgentAlreadyRunning(t *testing.T) {
	withFakeCommandOnPath(t, "tmux")
	withFakePiOnPath(t)
	calls := withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		t.Fatalf("pi ensure should not run for skipped agents: %v", args)
		return nil, nil
	})
	plan := teamUpPlan{Agents: []teamUpAgentPlan{{Name: "reviewer", RuntimeKind: "pi", Action: teamUpActionSkip}}}
	if err := preflightTeamUpCommands(plan); err != nil {
		t.Fatalf("preflightTeamUpCommands: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("pi ensure calls=%v, want none", *calls)
	}
}

func TestPreflightTeamUpCommandsFailsWhenPiEnsureFails(t *testing.T) {
	withFakeCommandOnPath(t, "tmux")
	withFakePiOnPath(t)
	withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		return []byte("No packages installed\n"), nil
	})
	plan := teamUpPlan{Agents: []teamUpAgentPlan{{Name: "reviewer", RuntimeKind: "pi", Action: teamUpActionStart}}}
	if err := preflightTeamUpCommands(plan); err == nil || !strings.Contains(err.Error(), "did not show npm:@awebai/pi") {
		t.Fatalf("expected loud pi ensure failure, got %v", err)
	}
}

func TestPrintTeamUpDryRunPlan(t *testing.T) {
	oldJSON := jsonFlag
	jsonFlag = false
	t.Cleanup(func() { jsonFlag = oldJSON })
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{{Name: "developer", HomeDir: "/tmp/dev", RuntimeKind: "claude-code", Command: []string{"claude", "--dangerously-skip-permissions", "--dangerously-load-development-channels", "plugin:aweb-channel@awebai-marketplace"}, Action: teamUpActionStart}}}
	var out bytes.Buffer
	if err := printTeamUpPlan(&out, plan); err != nil {
		t.Fatalf("printTeamUpPlan: %v", err)
	}
	text := out.String()
	for _, want := range []string{"tmux session: aw-team", "reconcile: 1 to start, 0 already up", "developer (claude-code): start", "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace"} {
		if !strings.Contains(text, want) {
			t.Fatalf("dry-run output missing %q:\n%s", want, text)
		}
	}
}

func installFakeTmuxForEnvTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tmux-env.log")
	script := "#!/bin/sh\n" +
		"printf 'TMUX_TMPDIR=%s TMUX=%s args=%s\\n' \"$TMUX_TMPDIR\" \"$TMUX\" \"$*\" >> \"$AW_TMUX_LOG\"\n" +
		"printf 'ok\\n'\n"
	path := filepath.Join(dir, "tmux")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AW_TMUX_LOG", logPath)
	return logPath
}

func readFakeTmuxEnvLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tmux env log: %v", err)
	}
	return string(data)
}

func TestTeamUpTmuxCommandsHonorAwebTmuxTmpdirEnv(t *testing.T) {
	logPath := installFakeTmuxForEnvTest(t)
	dedicated := filepath.Join(t.TempDir(), "agent-socket")
	t.Setenv("AWEB_TMUX_TMPDIR", dedicated)
	t.Setenv("TMUX_TMPDIR", filepath.Join(t.TempDir(), "human-socket"))
	t.Setenv("TMUX", filepath.Join(t.TempDir(), "human-tmux")+",123,0")

	if !tmuxSessionExists("aw-team") {
		t.Fatal("fake tmux should report session exists")
	}
	if err := runTmux(nil, "new-session", "-d", "-s", "aw-team"); err != nil {
		t.Fatalf("runTmux: %v", err)
	}
	if out, err := runTmuxOutput("list-windows", "-t", "aw-team"); err != nil || !strings.Contains(out, "ok") {
		t.Fatalf("runTmuxOutput out=%q err=%v", out, err)
	}

	log := readFakeTmuxEnvLog(t, logPath)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != 3 {
		t.Fatalf("log lines=%q", log)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "TMUX_TMPDIR="+dedicated+" TMUX= ") {
			t.Fatalf("tmux invocation did not use AWEB_TMUX_TMPDIR %q with inherited TMUX stripped:\n%s", dedicated, log)
		}
	}
}

func TestTeamUpTmuxCommandsUseWorkspaceConfiguredTmpdir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	dedicated := filepath.Join(t.TempDir(), "workspace-agent-socket")
	workspaceYAML := "aweb_url: https://app.aweb.ai\n" +
		"aweb_tmux_tmpdir: " + filepath.ToSlash(dedicated) + "\n" +
		"memberships:\n" +
		"  - team_id: default:example.aweb.ai\n" +
		"    alias: owner\n" +
		"    cert_path: team-certs/default__example.aweb.ai.pem\n"
	if err := os.WriteFile(filepath.Join(root, ".aw", "workspace.yaml"), []byte(workspaceYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })
	logPath := installFakeTmuxForEnvTest(t)
	t.Setenv("AWEB_TMUX_TMPDIR", "")
	t.Setenv("TMUX_TMPDIR", filepath.Join(t.TempDir(), "human-socket"))
	t.Setenv("TMUX", filepath.Join(t.TempDir(), "human-tmux")+",123,0")

	if err := runTmux(nil, "new-session", "-d", "-s", "aw-team"); err != nil {
		t.Fatalf("runTmux: %v", err)
	}
	log := readFakeTmuxEnvLog(t, logPath)
	if !strings.HasPrefix(strings.TrimSpace(log), "TMUX_TMPDIR="+dedicated+" TMUX= ") {
		t.Fatalf("tmux invocation did not use workspace aweb_tmux_tmpdir %q with inherited TMUX stripped:\n%s", dedicated, log)
	}
}

func TestTeamUpTmuxCommandsWithoutAwebTmpdirPreserveInheritedEnvironment(t *testing.T) {
	logPath := installFakeTmuxForEnvTest(t)
	inherited := filepath.Join(t.TempDir(), "existing-socket")
	t.Setenv("AWEB_TMUX_TMPDIR", "")
	t.Setenv("TMUX_TMPDIR", inherited)
	inheritedTMUX := filepath.Join(t.TempDir(), "default-tmux") + ",123,0"
	t.Setenv("TMUX", inheritedTMUX)

	if err := runTmux(nil, "display-message", "hello"); err != nil {
		t.Fatalf("runTmux: %v", err)
	}
	log := readFakeTmuxEnvLog(t, logPath)
	if !strings.HasPrefix(strings.TrimSpace(log), "TMUX_TMPDIR="+inherited+" TMUX="+inheritedTMUX+" ") {
		t.Fatalf("tmux invocation should preserve inherited TMUX_TMPDIR/TMUX when AWEB_TMUX_TMPDIR/workspace config are unset:\n%s", log)
	}
}

func TestAttachTeamUpSessionUsesAttachWhenAwebTmuxTmpdirIsSetInsideTmux(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	t.Setenv("AWEB_TMUX_TMPDIR", filepath.Join(t.TempDir(), "agent-socket"))
	t.Setenv("TMUX", filepath.Join(t.TempDir(), "human-tmux")+",123,0")
	var calls []string
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	if err := attachTeamUpSession(&cobra.Command{}, teamUpConfiguredTmuxContext, "aw-team"); err != nil {
		t.Fatalf("attachTeamUpSession: %v", err)
	}
	if len(calls) != 1 || calls[0] != "attach-session -t aw-team:" {
		t.Fatalf("isolated attach should not switch the inherited tmux client across sockets: %v", calls)
	}
}

func TestAttachTeamUpSessionPreservesSwitchClientWithoutAwebTmuxTmpdir(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	t.Setenv("AWEB_TMUX_TMPDIR", "")
	t.Setenv("TMUX", filepath.Join(t.TempDir(), "human-tmux")+",123,0")
	var calls []string
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		return nil
	}
	if err := attachTeamUpSession(&cobra.Command{}, teamUpConfiguredTmuxContext, "aw-team"); err != nil {
		t.Fatalf("attachTeamUpSession: %v", err)
	}
	if len(calls) != 1 || calls[0] != "switch-client -t aw-team:" {
		t.Fatalf("default-socket attach should preserve switch-client behavior inside tmux: %v", calls)
	}
}

func TestAttachTeamUpCallerSessionPreservesContextWithAwebTmpdir(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	logPath := installFakeTmuxForEnvTest(t)
	callerTMUX := "/tmp/aary5-caller,123,0"
	overrideTmpdir := filepath.Join(t.TempDir(), "override-socket")
	t.Setenv(tmuxEnv, callerTMUX)
	t.Setenv(tmuxTmpdirEnv, overrideTmpdir)
	t.Setenv(teamUpTmuxTmpdirEnv, filepath.Join(t.TempDir(), "configured-socket"))

	if err := attachTeamUpSession(&cobra.Command{}, teamUpCallerTmuxContext, "aary5.caller"); err != nil {
		t.Fatalf("attachTeamUpSession: %v", err)
	}
	log := strings.TrimSpace(readFakeTmuxEnvLog(t, logPath))
	if !strings.HasPrefix(log, "TMUX_TMPDIR="+overrideTmpdir+" TMUX="+callerTMUX+" args=switch-client -t aary5.caller:") {
		t.Fatalf("caller attach left inherited tmux context: %s", log)
	}
}

func TestTeamUpRecreateRefusesSessionWithRunningAgentWindow(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	resetTeamUpTmuxForTest(t)
	root := t.TempDir()
	home := writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{{Name: "developer", HomeDir: home, RuntimeKind: "pi", Command: []string{"pi", "--approve"}, Action: teamUpActionStart}}}
	teamUpSessionExists = func(string) bool { return true }
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		if strings.Join(args, " ") == "list-windows -t aw-team: -F #W" {
			return "developer\nzsh\n", nil
		}
		return "", nil
	}
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) {
		return map[string]teamUpRunningProcess{canonicalTeamUpPath(home): {PID: 123, Command: "pi", CWD: home}}, nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		t.Fatalf("tmux should not kill protected session: %v", args)
		return nil
	}
	_, err := executeTeamUpPlan(&cobra.Command{}, plan, true, false, false)
	if err == nil || !strings.Contains(err.Error(), "refusing aw team up --recreate") || !strings.Contains(err.Error(), "developer(pid 123)") || !strings.Contains(err.Error(), "--force-kill") {
		t.Fatalf("expected protected recreate error, got %v", err)
	}
}

func TestTeamUpRecreateForceKillAllowsSessionKill(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	resetTeamUpTmuxForTest(t)
	root := t.TempDir()
	home := writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{{Name: "developer", HomeDir: home, RuntimeKind: "pi", Command: []string{"pi", "--approve"}, Action: teamUpActionStart}}}
	killed := false
	teamUpSessionExists = func(session string) bool { return session == "aw-team" && !killed }
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		t.Fatalf("guard should be skipped with forceKill: %v", args)
		return "", nil
	}
	var calls []string
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if strings.Join(args, " ") == "kill-session -t aw-team" {
			killed = true
		}
		return nil
	}
	if _, err := executeTeamUpPlan(&cobra.Command{}, plan, true, true, false); err != nil {
		t.Fatalf("executeTeamUpPlan: %v", err)
	}
	if len(calls) < 2 || calls[0] != "kill-session -t aw-team" || !strings.Contains(calls[1], "new-session -d -s aw-team -n developer") {
		t.Fatalf("tmux calls=%v", calls)
	}
}

func TestTeamUpRecreateAllowsSessionWithoutRunningAgentWindow(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	resetTeamUpTmuxForTest(t)
	root := t.TempDir()
	home := writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	plan := teamUpPlan{Session: "aw-team", Agents: []teamUpAgentPlan{{Name: "developer", HomeDir: home, RuntimeKind: "pi", Command: []string{"pi", "--approve"}, Action: teamUpActionStart}}}
	killed := false
	teamUpSessionExists = func(session string) bool { return session == "aw-team" && !killed }
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		return "zsh\n", nil
	}
	teamUpDetectActiveHomes = func(string) (map[string]teamUpRunningProcess, error) {
		return map[string]teamUpRunningProcess{canonicalTeamUpPath(home): {PID: 123, Command: "pi", CWD: home}}, nil
	}
	var calls []string
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		calls = append(calls, strings.Join(args, " "))
		if strings.Join(args, " ") == "kill-session -t aw-team" {
			killed = true
		}
		return nil
	}
	if _, err := executeTeamUpPlan(&cobra.Command{}, plan, true, false, false); err != nil {
		t.Fatalf("executeTeamUpPlan: %v", err)
	}
	if len(calls) < 2 || calls[0] != "kill-session -t aw-team" {
		t.Fatalf("tmux calls=%v", calls)
	}
}

func TestLaunchAgentWindowCreatesSessionOrWindow(t *testing.T) {
	for _, tc := range []struct {
		name          string
		sessionExists bool
		wantPrefix    string
	}{
		{name: "new-session", sessionExists: false, wantPrefix: "new-session -d -s aw-team -n developer "},
		{name: "new-window", sessionExists: true, wantPrefix: "new-window -t aw-team: -n developer "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTeamUpTmuxForTest(t)
			teamUpSessionExists = func(string) bool { return tc.sessionExists }
			var got []string
			teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
				got = append(got, strings.Join(args, " "))
				return nil
			}
			agent := teamUpAgentPlan{Name: "developer", HomeDir: "/tmp/dev home", Command: []string{"claude", "--flag"}}
			if err := launchAgentWindow(nil, teamUpConfiguredTmuxContext, "aw-team", agent); err != nil {
				t.Fatalf("launchAgentWindow: %v", err)
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.wantPrefix) || !strings.Contains(got[0], "unset AWEB_TMUX_KILL_OK && export PATH='/guard/bin:/usr/bin:/bin' && cd '/tmp/dev home' && exec 'claude' '--flag'") {
				t.Fatalf("tmux calls=%v", got)
			}
		})
	}
}

func TestLaunchAgentWindowTargetsCollidingSessionName(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux is required for the launcher integration test")
	}
	resetTeamUpTmuxForTest(t)
	teamUpSessionExists = tmuxSessionExists
	teamUpRunTmux = runTmux
	teamUpRunTmuxOutput = runTmuxOutput

	repoRoot := resolveRepoRoot(".")
	guardDir := filepath.Join(repoRoot, "scripts", "guard-bin")
	if _, err := os.Stat(filepath.Join(guardDir, "tmux")); err != nil {
		t.Fatalf("tmux guard missing: %v", err)
	}
	t.Setenv("PATH", guardDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	socketDir, err := os.MkdirTemp("/tmp", "awtmux-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	t.Setenv(teamUpTmuxTmpdirEnv, socketDir)
	t.Setenv(tmuxTmpdirEnv, socketDir)
	t.Setenv(tmuxEnv, "")

	const session = "aary4-collision"
	if output, err := teamUpTmuxCommand(teamUpConfiguredTmuxContext, "new-session", "-d", "-s", session, "-n", session, "sleep 120").CombinedOutput(); err != nil {
		t.Fatalf("create isolated colliding session: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		_ = teamUpRunTmux(nil, "kill-session", "-t", session)
	})

	agent := teamUpAgentPlan{Name: "developer", HomeDir: t.TempDir(), Command: []string{"sleep", "120"}}
	if err := launchAgentWindow(nil, teamUpConfiguredTmuxContext, session, agent); err != nil {
		diagnostic, _ := teamUpTmuxCommand(teamUpConfiguredTmuxContext, "new-window", "-t", session, "-n", "diagnostic", "sleep 120").CombinedOutput()
		t.Fatalf("launch into session whose window shares its name: %v; bare-target diagnostic: %s", err, strings.TrimSpace(string(diagnostic)))
	}
	windows, err := teamUpRunTmuxOutput("list-windows", "-t", session, "-F", "#W")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(windows, session) || !strings.Contains(windows, "developer") {
		t.Fatalf("windows=%q, want colliding original plus developer", windows)
	}
}

func TestTeamUpWindowNameNormalizesDotsForTargetSafety(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "developer", want: "developer"},
		{name: "aw-docs", want: "aw-docs"},
		{name: "dev.team", want: "dev_team"},
	} {
		if got := teamUpWindowName(tc.name); got != tc.want {
			t.Fatalf("teamUpWindowName(%q)=%q, want %q", tc.name, got, tc.want)
		}
	}
	if got, want := teamUpWindowTarget(teamUpConfiguredTmuxContext, "aw-team", "dev.team"), "aw-team:dev_team"; got != want {
		t.Fatalf("window target=%q, want %q", got, want)
	}
	if got, want := teamUpWindowTarget(teamUpConfiguredTmuxContext, "aweb-juan.aweb.ai", "dev.team"), "aweb-juan_aweb_ai:dev_team"; got != want {
		t.Fatalf("window target with dotted session=%q, want %q", got, want)
	}
}

func TestConfirmClaudeChannelPromptAnswersTrustThenDevChannelPrompts(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 2 * time.Second
	outputs := []string{
		"Is this a project you created or one you trust?\n1. Yes, I trust this folder\n2. No, exit\n",
		"WARNING: Loading development channels\n1. I am using this for local development\n2. Exit\n",
		"Welcome back\n⏵⏵ bypass permissions on\n1 MCP server needs authentication - run /mcp\n",
	}
	captures := 0
	var sent []string
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		if captures >= len(outputs) {
			return outputs[len(outputs)-1], nil
		}
		out := outputs[captures]
		captures++
		return out, nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	if err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent}); err != nil {
		t.Fatalf("confirmStartedClaudeChannelPrompts: %v", err)
	}
	want := []string{"send-keys -t aw-team:developer Enter", "send-keys -t aw-team:developer Enter"}
	if strings.Join(sent, "|") != strings.Join(want, "|") {
		t.Fatalf("sent=%v, want %v", sent, want)
	}
}

func TestConfirmClaudeChannelPromptDoesNotTreatBypassWithActivePromptAsComplete(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 2 * time.Second
	outputs := []string{
		"⏵⏵ bypass permissions on\nWARNING: Loading development channels\n1. I am using this for local development\n2. Exit\n",
		"Welcome back\n⏵⏵ bypass permissions on\n1 MCP server needs authentication - run /mcp\n",
	}
	captures := 0
	var sent []string
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		if captures >= len(outputs) {
			return outputs[len(outputs)-1], nil
		}
		out := outputs[captures]
		captures++
		return out, nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	if err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent}); err != nil {
		t.Fatalf("confirmStartedClaudeChannelPrompts: %v", err)
	}
	if len(sent) != 1 || sent[0] != "send-keys -t aw-team:developer Enter" {
		t.Fatalf("sent=%v", sent)
	}
}

func TestConfirmClaudeChannelPromptHandlesStaleTrustTextAboveDevPrompt(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 2 * time.Second
	outputs := []string{
		"Is this a project you created or one you trust?\n1. Yes, I trust this folder\n2. No, exit\n",
		"Is this a project you created or one you trust?\n1. Yes, I trust this folder\n2. No, exit\n\nWARNING: Loading development channels\n1. I am using this for local development\n2. Exit\n",
		"Is this a project you created or one you trust?\n1. Yes, I trust this folder\n2. No, exit\n\nWARNING: Loading development channels\n1. I am using this for local development\n2. Exit\n\nWelcome back\n⏵⏵ bypass permissions on\n1 MCP server needs authentication - run /mcp\n",
	}
	captures := 0
	var sent []string
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		if captures >= len(outputs) {
			return outputs[len(outputs)-1], nil
		}
		out := outputs[captures]
		captures++
		return out, nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	if err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent}); err != nil {
		t.Fatalf("confirmStartedClaudeChannelPrompts: %v", err)
	}
	want := []string{"send-keys -t aw-team:developer Enter", "send-keys -t aw-team:developer Enter"}
	if strings.Join(sent, "|") != strings.Join(want, "|") {
		t.Fatalf("sent=%v, want %v", sent, want)
	}
}

func TestConfirmClaudeChannelPromptSendsEnterAfterSeeingPrompt(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 2 * time.Second
	captures := 0
	var sent []string
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		captures++
		if captures == 1 {
			return "1. I am using this for local development\n2. Exit\n", nil
		}
		return "Welcome back\n⏵⏵ bypass permissions on\n1 MCP server needs authentication - run /mcp\n", nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		sent = append(sent, strings.Join(args, " "))
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	if err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent}); err != nil {
		t.Fatalf("confirmStartedClaudeChannelPrompts: %v", err)
	}
	if len(sent) != 1 || sent[0] != "send-keys -t aw-team:developer Enter" {
		t.Fatalf("sent=%v", sent)
	}
}

func TestConfirmClaudeChannelPromptAlreadyCompleteSendsNothing(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 2 * time.Second
	teamUpRunTmuxOutput = func(args ...string) (string, error) {
		return "Welcome back\n⏵⏵ bypass permissions on\n1 MCP server needs authentication - run /mcp\n", nil
	}
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		t.Fatalf("send-keys should not run when channel is already complete: %v", args)
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	if err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent}); err != nil {
		t.Fatalf("confirmStartedClaudeChannelPrompts: %v", err)
	}
}

func TestConfirmClaudeChannelPromptDoesNotSendBlindBeforePrompt(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpConfirmClaudePromptWait = 20 * time.Millisecond
	teamUpRunTmuxOutput = func(args ...string) (string, error) { return "loading plugin...", nil }
	teamUpRunTmux = func(_ *cobra.Command, args ...string) error {
		t.Fatalf("send-keys should not run before prompt is visible: %v", args)
		return nil
	}
	agent := teamUpAgentPlan{Name: "developer", RuntimeKind: "claude-code"}
	err := confirmStartedClaudeChannelPrompts("aw-team", []teamUpAgentPlan{agent})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	for _, want := range []string{"timed out waiting", "no known prompt (trust-folder / dev-channel)", "prompt wording may have changed", "claudeChannelPromptVisible", "claudeTrustFolderPromptVisible", "loading plugin..."} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("timeout error missing %q:\n%v", want, err)
		}
	}
}

func TestTeamUpInsideTmuxFailsClosedWhenCallerSessionCannotBeResolved(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	oldSession, oldDryRun := teamUpSession, teamUpDryRun
	t.Cleanup(func() {
		teamUpSession = oldSession
		teamUpDryRun = oldDryRun
	})
	teamUpSession = ""
	teamUpDryRun = true
	t.Setenv(tmuxEnv, "/tmp/nonexistent-aary5,123,0")
	withFakeCommandOnPath(t, "tmux")

	err = runTeamHumanUp(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "caller tmux session") {
		t.Fatalf("expected caller-session resolution to fail closed, got %v", err)
	}
}

func TestTeamUpOutsideTmuxKeepsTeamDerivedSessionDefault(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aw", "workspace.yaml"), []byte("aweb_url: https://app.aweb.ai\nmemberships:\n  - team_id: backend:example.com\n    alias: owner\n    cert_path: team-certs/backend__example.com.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".aw", "teams.yaml"), []byte("active_team: backend:example.com\nmemberships:\n  - team_id: backend:example.com\n    alias: owner\n    cert_path: team-certs/backend__example.com.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(tmuxEnv, "")
	selection, err := resolveTeamUpSession(root, "")
	if err != nil {
		t.Fatalf("resolveTeamUpSession: %v", err)
	}
	if selection.Session != teamUpTmuxName("backend:example.com") || selection.TmuxContext != teamUpConfiguredTmuxContext {
		t.Fatalf("outside-tmux selection=%+v", selection)
	}
}

func TestTeamUpExplicitSessionBypassesCallerSessionResolution(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	writeMaterializedAgentForTeamUp(t, root, "developer", "pi")
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWD) })

	oldSession, oldDryRun := teamUpSession, teamUpDryRun
	t.Cleanup(func() {
		teamUpSession = oldSession
		teamUpDryRun = oldDryRun
	})
	teamUpSession = "explicit.session"
	teamUpDryRun = true
	t.Setenv(tmuxEnv, "/tmp/nonexistent-aary5,123,0")
	withFakeCommandOnPath(t, "tmux")

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runTeamHumanUp(cmd, nil); err != nil {
		t.Fatalf("explicit session should bypass caller resolution: %v", err)
	}
	if !strings.Contains(out.String(), "tmux session: explicit_session") {
		t.Fatalf("explicit session plan=%q", out.String())
	}
}

func isolatedTeamUpTmuxCommand(tmpdir, tmuxValue string, args ...string) *exec.Cmd {
	cmd := exec.Command("tmux", args...)
	env := envWithValueAndUnset(os.Environ(), tmuxTmpdirEnv, tmpdir, tmuxEnv, teamUpTmuxTmpdirEnv)
	if tmuxValue != "" {
		env = envWithValueAndUnset(env, tmuxEnv, tmuxValue)
	}
	cmd.Env = env
	return cmd
}

func isolatedTeamUpTmuxOutput(tmpdir, tmuxValue string, args ...string) (string, error) {
	output, err := isolatedTeamUpTmuxCommand(tmpdir, tmuxValue, args...).CombinedOutput()
	return string(output), err
}

func TestTeamUpInsideTmuxLaunchesIntoReachableCallerSession(t *testing.T) {
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux is required for the launcher integration test")
	}
	resetTeamUpTmuxForTest(t)
	teamUpSessionExists = tmuxSessionExists
	teamUpRunTmux = runTmux
	teamUpRunTmuxOutput = runTmuxOutput

	repoRoot := resolveRepoRoot(".")
	guardDir := filepath.Join(repoRoot, "scripts", "guard-bin")
	if _, err := os.Stat(filepath.Join(guardDir, "tmux")); err != nil {
		t.Fatalf("tmux guard missing: %v", err)
	}
	t.Setenv("PATH", guardDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	callerSocketDir, err := os.MkdirTemp("/tmp", "awtmux-caller-")
	if err != nil {
		t.Fatal(err)
	}
	overrideSocketDir, err := os.MkdirTemp("/tmp", "awtmux-override-")
	if err != nil {
		_ = os.RemoveAll(callerSocketDir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(overrideSocketDir) })
	t.Cleanup(func() { _ = os.RemoveAll(callerSocketDir) })

	const requestedCallerSession = "aary5.caller"
	tmuxValuePath := filepath.Join(callerSocketDir, "caller-tmux")
	captureCallerEnv := "printf '%s' \"$TMUX\" > " + shellQuote(tmuxValuePath) + "; exec sleep 120"
	if output, err := isolatedTeamUpTmuxCommand(callerSocketDir, "", "new-session", "-d", "-s", requestedCallerSession, "-n", "operator", captureCallerEnv).CombinedOutput(); err != nil {
		t.Fatalf("create isolated caller session: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		_, _ = isolatedTeamUpTmuxOutput(callerSocketDir, "", "kill-session", "-t", requestedCallerSession)
	})
	t.Cleanup(func() {
		_, _ = isolatedTeamUpTmuxOutput(overrideSocketDir, "", "kill-session", "-t", "aw-team")
		_, _ = isolatedTeamUpTmuxOutput(overrideSocketDir, "", "kill-session", "-t", requestedCallerSession)
	})

	var callerTMUX string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		data, readErr := os.ReadFile(tmuxValuePath)
		if readErr == nil && strings.TrimSpace(string(data)) != "" {
			callerTMUX = strings.TrimSpace(string(data))
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if callerTMUX == "" {
		t.Fatal("caller pane did not capture its real TMUX environment value")
	}
	callerSessionOutput, err := isolatedTeamUpTmuxOutput(callerSocketDir, callerTMUX, "display-message", "-p", "#S")
	if err != nil {
		t.Fatalf("resolve isolated caller session: %v: %s", err, strings.TrimSpace(callerSessionOutput))
	}
	callerSession := strings.TrimSpace(callerSessionOutput)

	t.Setenv(tmuxEnv, callerTMUX)
	t.Setenv(tmuxTmpdirEnv, overrideSocketDir)
	t.Setenv(teamUpTmuxTmpdirEnv, overrideSocketDir)
	selection, err := resolveTeamUpSession(t.TempDir(), "")
	if err != nil {
		t.Fatalf("select caller session: %v", err)
	}
	selectedSession := selection.Session
	agent := teamUpAgentPlan{Name: "developer", HomeDir: t.TempDir(), Command: []string{"sleep", "120"}, Action: teamUpActionStart}
	plan := teamUpPlan{Session: selectedSession, Agents: []teamUpAgentPlan{agent}, TmuxContext: selection.TmuxContext}
	var launchOutput bytes.Buffer
	launchCmd := &cobra.Command{}
	launchCmd.SetOut(&launchOutput)
	if _, err := executeTeamUpPlan(launchCmd, plan, false, false, false); err != nil {
		t.Fatalf("launch developer window: %v", err)
	}

	callerWindows, callerErr := isolatedTeamUpTmuxOutput(callerSocketDir, callerTMUX, "list-windows", "-t", callerSession+":", "-F", "#W")
	overrideSessions, overrideErr := isolatedTeamUpTmuxOutput(overrideSocketDir, "", "list-sessions", "-F", "#S")
	if selectedSession != callerSession || callerErr != nil || !strings.Contains(callerWindows, "developer") || overrideErr == nil || !strings.Contains(launchOutput.String(), "tmux session \""+callerSession+"\"") {
		t.Fatalf("caller launch selected=%q caller=%q output=%q caller_windows=%q caller_err=%v override_sessions=%q override_err=%v", selectedSession, callerSession, launchOutput.String(), callerWindows, callerErr, overrideSessions, overrideErr)
	}
}

func TestTeamUpCommandRegistered(t *testing.T) {
	cmd, _, err := teamHumanCmd.Find([]string{"up"})
	if err != nil || cmd == nil || cmd.Name() != "up" {
		t.Fatalf("team up command missing: cmd=%v err=%v", cmd, err)
	}
}

// aweb-aawn: `aw team up` treated the existence of .aw/profile/profile.yaml as the
// definition of an agent, so any directory carrying that one file was launched - a
// backup of a home included, holding the original's credentials. A home must now
// account for itself: it has a workspace identity, and that identity names the place
// the home actually is. A copy names where it was copied FROM, wherever it is put.
func TestTeamUpPlanRefusesHomesThatDoNotAccountForThemselves(t *testing.T) {
	resetTeamUpDetectorsForTest(t)
	root := t.TempDir()
	instances := filepath.Join(root, "agents", "instances")

	realHome := writeMaterializedAgentForTeamUp(t, root, "realagent", "claude-code")

	// One file, never read, and it was enough to be launched as a claude-code agent.
	bare := filepath.Join(instances, "not-an-agent-at-all")
	if err := os.MkdirAll(filepath.Join(bare, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bare, ".aw", "profile", "profile.yaml"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	// A faithful copy, the way the profile advises taking one before a refresh. Its
	// workspace.yaml still names the original's path - that is what gives it away.
	backup := filepath.Join(instances, "realagent.pre-refresh-backup")
	if err := os.MkdirAll(filepath.Join(backup, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"profile.yaml", "ref.json"} {
		data, err := os.ReadFile(filepath.Join(realHome, ".aw", "profile", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(backup, ".aw", "profile", name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	wsData, err := os.ReadFile(filepath.Join(realHome, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, ".aw", "workspace.yaml"), wsData, 0o644); err != nil {
		t.Fatal(err)
	}

	plan, err := buildTeamUpPlan(root, "aawn:local", false, false)
	if err != nil {
		t.Fatalf("buildTeamUpPlan: %v", err)
	}

	actions := map[string]string{}
	for _, agent := range plan.Agents {
		actions[agent.Name] = agent.Action
	}
	if actions["realagent"] != teamUpActionStart {
		t.Fatalf("a home that accounts for itself must still start: %+v", plan.Agents)
	}
	if actions["not-an-agent-at-all"] != teamUpActionRefuse {
		t.Fatalf("a directory with no workspace identity was not refused: action=%q", actions["not-an-agent-at-all"])
	}
	if actions["realagent.pre-refresh-backup"] != teamUpActionRefuse {
		t.Fatalf("a copied home was not refused, so it would launch holding the original's credentials: action=%q", actions["realagent.pre-refresh-backup"])
	}

	// A refusal reported as "already up" is the failure this guard exists to make
	// visible, so the summary must count it separately.
	var out bytes.Buffer
	if err := printTeamUpPlan(&out, plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2 refused") {
		t.Fatalf("refusals must be counted in their own right, not folded into 'already up':\n%s", out.String())
	}
}
