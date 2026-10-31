package main

import (
	"encoding/json"
	"io"
	"os"
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
				"claude plugin marketplace add awebai/claude-plugins && claude plugin install aweb-channel@awebai-marketplace",
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
			want:   []string{"aw team list", "aw mail send --to <teammate>"},
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
