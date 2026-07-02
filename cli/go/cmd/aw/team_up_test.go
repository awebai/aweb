package main

import (
	"bytes"
	"encoding/json"
	"os"
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
	oldWait := teamUpConfirmClaudePromptWait
	t.Cleanup(func() {
		teamUpSessionExists = oldExists
		teamUpRunTmux = oldRun
		teamUpRunTmuxOutput = oldOutput
		teamUpConfirmClaudePromptWait = oldWait
	})
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

func TestLaunchAgentWindowCreatesSessionOrWindow(t *testing.T) {
	for _, tc := range []struct {
		name          string
		sessionExists bool
		wantPrefix    string
	}{
		{name: "new-session", sessionExists: false, wantPrefix: "new-session -d -s aw-team -n developer "},
		{name: "new-window", sessionExists: true, wantPrefix: "new-window -t aw-team -n developer "},
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
			if err := launchAgentWindow(nil, "aw-team", agent); err != nil {
				t.Fatalf("launchAgentWindow: %v", err)
			}
			if len(got) != 1 || !strings.HasPrefix(got[0], tc.wantPrefix) || !strings.Contains(got[0], "cd '/tmp/dev home' && exec 'claude' '--flag'") {
				t.Fatalf("tmux calls=%v", got)
			}
		})
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
	if got, want := teamUpWindowTarget("aw-team", "dev.team"), "aw-team:dev_team"; got != want {
		t.Fatalf("window target=%q, want %q", got, want)
	}
	if got, want := teamUpWindowTarget("aweb-juan.aweb.ai", "dev.team"), "aweb-juan_aweb_ai:dev_team"; got != want {
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

func TestTeamUpCommandRegistered(t *testing.T) {
	cmd, _, err := teamHumanCmd.Find([]string{"up"})
	if err != nil || cmd == nil || cmd.Name() != "up" {
		t.Fatalf("team up command missing: cmd=%v err=%v", cmd, err)
	}
}
