package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func initNextStepCommands(steps []initNextStep) string {
	var commands []string
	for _, step := range steps {
		commands = append(commands, step.Command)
	}
	return strings.Join(commands, "\n")
}

// aw init ends with the steps that fit the path it took: each the exact
// command and why, the same list in text and --json.
func TestInitNextStepsFitThePathTaken(t *testing.T) {
	const wd = "/work/alice"
	hosted := initResult{ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api"}
	for _, tc := range []struct {
		name   string
		result initResult
		want   []string
		absent []string
	}{
		{
			name:   "new hosted account",
			result: hosted,
			want: []string{
				"aw mail send --to-address aweb.ai/aida",
				"aw claim-human --email <your-email>",
				"aw init --setup-channel",
				"claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace",
				"aw init --join-from /work/alice --name <name>",
			},
			absent: []string{"aw team list"},
		},
		{
			name:   "existing account by API key",
			result: initResult{ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api", APIKeyAuth: true, Path: initPathAPIKey},
			want:   []string{"aw team invite"},
			absent: []string{"aw claim-human", "aweb.ai/aida", "--join-from"},
		},
		{
			name:   "joined a team",
			result: initResult{ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api", Path: initPathJoined},
			want:   []string{"aw workspace status", "aw mail send --to <teammate>"},
			absent: []string{"aw claim-human", "aweb.ai/aida", "--join-from"},
		},
		{
			name:   "self-hosted team",
			result: initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000"},
			want:   []string{"aw init --join-from /work/alice --name <name>"},
			absent: []string{"aw claim-human", "aweb.ai/aida"},
		},
		{
			name:   "reconnected workspace",
			result: initResult{ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api", Path: initPathReconnect},
			want:   []string{"claude --dangerously-load-development-channels"},
			absent: []string{"aw claim-human", "aweb.ai/aida", "--join-from", "aw team invite"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.result
			steps := initNextSteps(&result, wd, false, false)
			commands := initNextStepCommands(steps)
			for _, step := range steps {
				if strings.TrimSpace(step.Command) == "" || strings.TrimSpace(step.Why) == "" {
					t.Fatalf("step without a command or a reason: %+v", step)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(commands, want) {
					t.Fatalf("missing %q in:\n%s", want, commands)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(commands, absent) {
					t.Fatalf("unexpected %q in:\n%s", absent, commands)
				}
			}
			// The text lists the same steps.
			text := strings.Join(initNextStepLines(steps), "\n")
			for _, step := range steps {
				if !strings.Contains(text, step.Command) || !strings.Contains(text, step.Why) {
					t.Fatalf("text does not list %+v:\n%s", step, text)
				}
			}
		})
	}
}

// Docs injection and channel setup that already happened are not suggested.
func TestInitNextStepsOmitWhatInitAlreadyDid(t *testing.T) {
	result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000"}
	commands := initNextStepCommands(initNextSteps(&result, "/work/alice", true, true))
	for _, absent := range []string{"aw init --inject-docs", "aw init --setup-channel"} {
		if strings.Contains(commands, absent) {
			t.Fatalf("unexpected %q in:\n%s", absent, commands)
		}
	}
	commands = initNextStepCommands(initNextSteps(&result, "/work/alice", false, false))
	for _, want := range []string{"aw init --inject-docs", "aw init --setup-channel"} {
		if !strings.Contains(commands, want) {
			t.Fatalf("missing %q in:\n%s", want, commands)
		}
	}
}

// --json carries the steps and the guide, additively.
func TestInitJSONCarriesNextStepsAndTheGuide(t *testing.T) {
	out := connectOutput{Status: "connected", TeamID: "default:local", Alias: "alice", NextSteps: []initNextStep{{Command: "aw team invite", Why: "Add another agent"}}, Guide: initGuideURL}
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	steps, _ := decoded["next_steps"].([]any)
	first, _ := steps[0].(map[string]any)
	if len(steps) != 1 || first["command"] != "aw team invite" || first["why"] != "Add another agent" || decoded["guide"] != "https://aweb.ai/docs/cli-tutorial.md" {
		t.Fatalf("json %s", raw)
	}
	if bare, _ := json.Marshal(connectOutput{Status: "connected"}); strings.Contains(string(bare), "next_steps") || strings.Contains(string(bare), "guide") {
		t.Fatalf("empty steps were serialized: %s", bare)
	}
}

// The real init path prints its next steps in --json.
func TestInitJSONOnTheSelfHostedPathPrintsItsNextSteps(t *testing.T) {
	// Cannot use t.Parallel(): needs cwd, stdout and the init globals.
	oldLocalFlow, oldIsTTY, oldJSON := initRunImplicitLocalFlow, initIsTTY, jsonFlag
	oldAwebURL, oldRegistry, oldName, oldNewTeam := initAwebURL, initAWIDRegistry, initName, initNewTeam
	t.Cleanup(func() {
		initRunImplicitLocalFlow, initIsTTY, jsonFlag = oldLocalFlow, oldIsTTY, oldJSON
		initAwebURL, initAWIDRegistry, initName, initNewTeam = oldAwebURL, oldRegistry, oldName, oldNewTeam
	})
	t.Setenv("HOME", t.TempDir())
	initIsTTY = func() bool { return false }
	jsonFlag = true
	initAwebURL, initAWIDRegistry, initName, initNewTeam = "http://localhost:8100", "http://127.0.0.1:8010", "alice", true
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		return connectOutput{Status: "connected", TeamID: "default:local", Alias: "alice", AwebURL: req.AwebURL}, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetIn(strings.NewReader(""))

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	realStdout := os.Stdout
	os.Stdout = writer
	dir := t.TempDir()
	withTestWorkingDir(t, dir, func() {
		err = runInit(&cmd.Command, nil)
	})
	os.Stdout = realStdout
	writer.Close()
	raw, _ := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, raw)
	}
	var out struct {
		NextSteps []initNextStep `json:"next_steps"`
		Guide     string         `json:"guide"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, raw)
	}
	commands := initNextStepCommands(out.NextSteps)
	if !strings.Contains(commands, "aw init --join-from") || !strings.Contains(commands, "--name <name>") || out.Guide != initGuideURL {
		t.Fatalf("next steps %+v guide %q", out.NextSteps, out.Guide)
	}
}

// Every path starts by checking, against the server, that the agent is
// connected; that check also lists the team.
func TestInitNextStepsStartWithAServerCheck(t *testing.T) {
	for _, path := range []initPath{initPathNewTeam, initPathAPIKey, initPathJoined, initPathReconnect} {
		result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000", Path: path}
		steps := initNextSteps(&result, t.TempDir(), true, true)
		if len(steps) == 0 || steps[0].Command != "aw workspace status" {
			t.Fatalf("path %q does not start with the server check: %+v", path, steps)
		}
	}
}

// A new member is pointed at a command that lists teammates, not at
// aw team list, which lists only this agent's own memberships.
func TestInitNextStepsJoinedPointToTheTeamNotTeamList(t *testing.T) {
	result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000", Path: initPathJoined}
	commands := initNextStepCommands(initNextSteps(&result, t.TempDir(), true, true))
	if strings.Contains(commands, "aw team list") {
		t.Fatalf("joined steps point to aw team list:\n%s", commands)
	}
}

// Only hosted onboarding creates a separate account; on a self-hosted
// stack the step only says how to add an agent to this team.
func TestInitNextStepsSelfHostedDoNotClaimASeparateAccount(t *testing.T) {
	result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000"}
	for _, step := range initNextSteps(&result, t.TempDir(), true, true) {
		if strings.Contains(step.Why, "account") || strings.Contains(step.Why, "separate team") {
			t.Fatalf("self-hosted step claims hosted behaviour: %+v", step)
		}
	}
	hosted := initResult{ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api"}
	text := strings.Join(initNextStepLines(initNextSteps(&hosted, t.TempDir(), true, true)), "\n")
	if !strings.Contains(text, "separate team") {
		t.Fatalf("hosted steps lost the separate-team warning:\n%s", text)
	}
}

// add-worktree is offered only inside a git worktree.
func TestInitNextStepsOfferWorktreesOnlyInAGitRepo(t *testing.T) {
	result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000"}
	plain := t.TempDir()
	if commands := initNextStepCommands(initNextSteps(&result, plain, true, true)); strings.Contains(commands, "aw workspace add-worktree") {
		t.Fatalf("worktree step outside a git repo:\n%s", commands)
	}
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if commands := initNextStepCommands(initNextSteps(&result, repo, true, true)); !strings.Contains(commands, "aw workspace add-worktree <role>") {
		t.Fatalf("no worktree step inside a git repo:\n%s", commands)
	}
}

// aw init --setup-channel installs the Claude Code plugin, so the manual
// install is not a second step; Pi is named once.
func TestInitNextStepsNameEachChannelPathOnce(t *testing.T) {
	result := initResult{ServerName: "localhost", ExportBaseURL: "http://localhost:8000"}
	text := strings.Join(initNextStepLines(initNextSteps(&result, t.TempDir(), true, false)), "\n")
	if !strings.Contains(text, "aw init --setup-channel") || strings.Contains(text, "claude plugin install") {
		t.Fatalf("channel install listed twice:\n%s", text)
	}
	if n := strings.Count(text, "pi install npm:@awebai/pi@latest"); n != 1 {
		t.Fatalf("Pi install named %d times:\n%s", n, text)
	}
}

// Text output prints what init did before its next steps, so the steps and
// the guide are the last thing read.
func TestInitTextPrintsSideEffectsBeforeNextSteps(t *testing.T) {
	// Cannot use t.Parallel(): needs cwd, stdout and the init globals.
	oldLocalFlow, oldIsTTY, oldJSON := initRunImplicitLocalFlow, initIsTTY, jsonFlag
	oldAwebURL, oldRegistry, oldName, oldNewTeam := initAwebURL, initAWIDRegistry, initName, initNewTeam
	oldPrintExports := initPrintExports
	t.Cleanup(func() {
		initRunImplicitLocalFlow, initIsTTY, jsonFlag = oldLocalFlow, oldIsTTY, oldJSON
		initAwebURL, initAWIDRegistry, initName, initNewTeam = oldAwebURL, oldRegistry, oldName, oldNewTeam
		initPrintExports = oldPrintExports
	})
	t.Setenv("HOME", t.TempDir())
	initIsTTY = func() bool { return false }
	jsonFlag = false
	initPrintExports = true
	initAwebURL, initAWIDRegistry, initName, initNewTeam = "http://localhost:8100", "http://127.0.0.1:8010", "alice", true
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		return connectOutput{Status: "connected", TeamID: "default:local", Alias: "alice", AwebURL: req.AwebURL}, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetIn(strings.NewReader(""))

	var err error
	text := captureStdout(t, func() {
		withTestWorkingDir(t, t.TempDir(), func() {
			err = runInit(&cmd.Command, nil)
		})
	})
	if err != nil {
		t.Fatalf("init: %v\n%s", err, text)
	}
	created := strings.Index(text, "export AWEB_URL=")
	steps := strings.Index(text, "Next steps:")
	if created < 0 || steps < 0 || created > steps {
		t.Fatalf("side effects are not printed before the next steps:\n%s", text)
	}
	if !strings.HasSuffix(strings.TrimSpace(text), "Tell your agent: please read "+initGuideURL) {
		t.Fatalf("the guide line is not the last line:\n%s", text)
	}
}
