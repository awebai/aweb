//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
)

// newHookConfigurationSeat creates every identity, membership and workspace
// binding through the real CLI. No server response or database row is supplied
// by the test. The existing e2e harness owns the isolated OSS/AWID services.
func newHookConfigurationSeat(t *testing.T) *e2eTeam {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	controllerDir := filepath.Join(root, "controller")
	seatDir := filepath.Join(root, "seat")
	for _, dir := range []string{home, controllerDir, seatDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"HOME=" + home, "AWEB_IDENTITY_HOME=", "AWEB_API_KEY=",
		"AWEB_URL=" + awebURL(), "AWID_REGISTRY_URL=" + awidURL(),
		"AWID_SKIP_DNS_VERIFY=1", "AWEB_FEDERATION_TEST=1", "APP_ENV=development",
		"AW_NO_UPDATE_CHECK=1", "NO_COLOR=1"}
	for _, key := range []string{"PATH", "TMPDIR", "TMP", "TEMP", "SystemRoot"} {
		if value, present := os.LookupEnv(key); present {
			env = append(env, key+"="+value)
		}
	}
	namespace := "hook-config-" + randSuffix(t) + ".test"
	controller := &e2eTeam{bin: awBinary(t), workspace: controllerDir, env: env, namespace: namespace, teamID: "default:" + namespace}
	controller.run(t, "id", "create", "--domain", namespace, "--name", "controller", "--registry", awidURL(), "--skip-dns-verify", "--root-parent")
	controller.run(t, "id", "team", "create", "--namespace", namespace, "--name", "default", "--registry", awidURL())
	stdout, stderr, err := controller.exec("--json", "id", "team", "invite", "--namespace", namespace, "--team", "default")
	if err != nil {
		t.Fatalf("create disposable member invite: %v\n%s", err, stderr)
	}
	var invite struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal([]byte(stdout), &invite); err != nil || invite.Token == "" {
		t.Fatal("real invite command did not return a member token")
	}
	seat := &e2eTeam{bin: controller.bin, workspace: seatDir, env: env, namespace: namespace, teamID: controller.teamID, alias: "hook-seat"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accept := exec.CommandContext(ctx, seat.bin, "id", "team", "accept-invite", "--token-stdin", "--name", seat.alias)
	accept.Dir, accept.Env = seat.workspace, seat.env
	accept.Stdin = strings.NewReader(invite.Token + "\n")
	if output, err := accept.CombinedOutput(); err != nil {
		t.Fatalf("accept disposable invite from stdin: %v\n%s", err, output)
	}
	seat.run(t, "init", "--url", awebURL(), "--name", seat.alias, "--do-not-touch-agents-md")
	return seat
}

// docs/runtime-hook-configuration.md:18-20: refusal leaves the settings bytes
// intact while init still injects instructions fetched from the real service.
func TestRealStackInitHookRefusalContinuesOtherActions(t *testing.T) {
	requireE2E(t)
	seat := newHookConfigurationSeat(t)
	body := "Instructions survive a hook refusal in the real service: " + randSuffix(t)
	bodyFile := filepath.Join(t.TempDir(), "instructions.md")
	if err := os.WriteFile(bodyFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	seat.run(t, "instructions", "set", "--body-file", bodyFile)
	var active struct {
		TeamInstructions *aweb.ActiveTeamInstructionsResponse `json:"team_instructions"`
	}
	if err := json.Unmarshal([]byte(seat.run(t, "--json", "instructions", "show")), &active); err != nil {
		t.Fatal(err)
	}
	if active.TeamInstructions == nil || active.TeamInstructions.TeamID != seat.teamID || active.TeamInstructions.Document.BodyMD != body {
		t.Fatal("the real service did not retain this team's instructions")
	}
	cases := []struct {
		Name, JSON, Repair string
	}{
		{Name: "invalid JSON", JSON: `{"hooks":`, Repair: "Fix the JSON syntax"},
		{Name: "duplicate key", JSON: `{"hooks":{},"\u0068ooks":{}}`, Repair: "Remove the duplicate JSON key"},
		{Name: "hooks not object", JSON: `{"hooks":[]}`, Repair: "Set hooks to a JSON object"},
	}
	settings := filepath.Join(seat.workspace, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	docs := filepath.Join(seat.workspace, "AGENTS.md")
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			if err := os.WriteFile(settings, []byte(tc.JSON), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
				if err := os.Remove(filepath.Join(seat.workspace, name)); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			stdout, stderr, err := seat.exec("init", "--inject-docs", "--setup-hooks")
			if err != nil {
				t.Fatalf("init stopped on an optional hook refusal: %v\n%s\n%s", err, stdout, stderr)
			}
			for _, part := range []string{"hook: not installed", settings, tc.Repair} {
				if !strings.Contains(stdout+stderr, part) {
					t.Fatalf("init omitted %q: %s\n%s", part, stdout, stderr)
				}
			}
			got, err := os.ReadFile(settings)
			if err != nil || string(got) != tc.JSON {
				t.Fatalf("refused settings changed: %v\n%s", err, got)
			}
			injected, err := os.ReadFile(docs)
			if err != nil || !bytes.Contains(injected, []byte(strings.TrimSpace(active.TeamInstructions.Document.BodyMD))) {
				t.Fatalf("real service instructions were not injected after refusal: %v\n%s", err, injected)
			}
		})
	}

	t.Run("valid hook installs", func(t *testing.T) {
		if err := os.WriteFile(settings, []byte(`{"hooks":{"PostToolUse":[]}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		seat.run(t, "init", "--setup-hooks")
		installed, err := os.ReadFile(settings)
		if err != nil {
			t.Fatal(err)
		}
		found, err := hasDefaultNotifyHandler(installed)
		if err != nil || !found {
			t.Fatalf("neighboring valid configuration did not install: %v\n%s", err, installed)
		}
	})
}

type hookHandlerKind string

const commandHookHandler hookHandlerKind = "command"

// hasDefaultNotifyHandler checks the actual PostToolUse group; command text in
// unrelated user fields cannot establish that a handler was installed.
func hasDefaultNotifyHandler(data []byte) (bool, error) {
	var settings struct {
		Hooks struct {
			PostToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type    hookHandlerKind `json:"type"`
					Command string          `json:"command"`
				} `json:"hooks"`
			} `json:"PostToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, err
	}
	for _, group := range settings.Hooks.PostToolUse {
		if group.Matcher != ".*" {
			continue
		}
		for _, handler := range group.Hooks {
			if handler.Type == commandHookHandler && handler.Command == "aw notify" {
				return true, nil
			}
		}
	}
	return false, nil
}

func TestDefaultNotifyHandlerRequiresExpectedPathAndFields(t *testing.T) {
	cases := []struct {
		Name string
		JSON string
		Want bool
	}{
		{Name: "unrelated command", JSON: `{"hooks":{"PostToolUse":[]},"unrelated":{"command":"aw notify"}}`},
		{Name: "different event", JSON: `{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"aw notify"}]}]}}`},
		{Name: "custom matcher", JSON: `{"hooks":{"PostToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"aw notify"}]}]}}`},
		{Name: "prompt handler", JSON: `{"hooks":{"PostToolUse":[{"matcher":".*","hooks":[{"type":"prompt","command":"aw notify"}]}]}}`},
		{Name: "different command", JSON: `{"hooks":{"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"echo other"}]}]}}`},
		{Name: "default command", JSON: `{"hooks":{"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"aw notify"}]}]}}`, Want: true},
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			found, err := hasDefaultNotifyHandler([]byte(tc.JSON))
			if err != nil {
				t.Fatal(err)
			}
			if found != tc.Want {
				t.Fatalf("default PostToolUse command handler = %v, want %v", found, tc.Want)
			}
		})
	}
}
