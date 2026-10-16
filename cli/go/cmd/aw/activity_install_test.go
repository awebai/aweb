package main

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
)

// aw activity hook install --codex writes the Codex hook entries for a host
// that OATS does not manage (docs/agent-activity.md, "Emitters").
func TestActivityHookInstallCodex(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	run := func(t *testing.T, codexHome string, env []string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), append([]string{"CODEX_HOME=" + codexHome, "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME="}, env...)...)
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &out
		code := 0
		if err := cmd.Run(); err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatal(err)
			}
			code = exitErr.ExitCode()
		}
		return out.String(), code
	}
	codexHome := func(t *testing.T) string {
		t.Helper()
		dir, err := os.MkdirTemp(root, "codex-")
		if err != nil {
			t.Fatal(err)
		}
		return dir
	}
	type handler struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		Async   bool   `json:"async"`
		Timeout int    `json:"timeout"`
	}
	type group struct {
		Matcher *string   `json:"matcher"`
		Hooks   []handler `json:"hooks"`
	}
	read := func(t *testing.T, dir string) map[string][]group {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, "hooks.json"))
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Hooks map[string][]group `json:"hooks"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("hooks.json: %v", err)
		}
		return file.Hooks
	}
	want := map[string]handler{
		"UserPromptSubmit":  {Type: "command", Command: "aw activity hook", Async: true, Timeout: 10},
		"PreToolUse":        {Type: "command", Command: "aw activity hook", Async: true, Timeout: 10},
		"PostToolUse":       {Type: "command", Command: "aw activity hook", Async: true, Timeout: 10},
		"PermissionRequest": {Type: "command", Command: "aw activity hook", Async: true, Timeout: 10},
		"Stop":              {Type: "command", Command: "aw activity hook", Timeout: 10},
		"Interrupt":         {Type: "command", Command: "aw activity hook", Timeout: 3},
		"SessionEnd":        {Type: "command", Command: "aw activity hook", Timeout: 3},
	}

	t.Run("a fresh install writes every event and names the trust step", func(t *testing.T) {
		dir := codexHome(t)
		out, code := run(t, dir, nil, "activity", "hook", "install", "--codex")
		if code != 0 || !strings.Contains(out, "with /hooks in Codex") || !strings.Contains(out, "aw activity enable") || !strings.Contains(out, "is installed") {
			t.Fatalf("install exit %d: %s", code, out)
		}
		hooks := read(t, dir)
		if len(hooks) != len(want) {
			t.Fatalf("events: %v", hooks)
		}
		for event, expected := range want {
			groups := hooks[event]
			if len(groups) != 1 || groups[0].Matcher != nil || len(groups[0].Hooks) != 1 || groups[0].Hooks[0] != expected {
				t.Fatalf("%s: %+v", event, groups)
			}
		}
		before, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
		if out, code := run(t, dir, nil, "activity", "hook", "install", "--codex"); code != 0 || !strings.Contains(out, "is already installed") {
			t.Fatalf("second install: %d %s", code, out)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
		if !bytes.Equal(before, after) {
			t.Fatalf("install is not idempotent:\n%s\n%s", before, after)
		}
	})

	t.Run("other hooks are kept", func(t *testing.T) {
		dir := codexHome(t)
		existing := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./guard.sh","timeout":30}]}],"SessionStart":[{"hooks":[{"type":"command","command":"echo hi"}]}]},"x-note":"mine"}`
		if err := os.WriteFile(filepath.Join(dir, "hooks.json"), []byte(existing), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, dir, nil, "activity", "hook", "install", "--codex"); code != 0 {
			t.Fatalf("install over existing hooks: %s", out)
		}
		hooks := read(t, dir)
		if len(hooks["PreToolUse"]) != 2 || hooks["PreToolUse"][0].Hooks[0].Command != "./guard.sh" || hooks["PreToolUse"][1].Hooks[0] != want["PreToolUse"] {
			t.Fatalf("PreToolUse: %+v", hooks["PreToolUse"])
		}
		if len(hooks["SessionStart"]) != 1 || hooks["SessionStart"][0].Hooks[0].Command != "echo hi" {
			t.Fatalf("SessionStart: %+v", hooks["SessionStart"])
		}
		data, _ := os.ReadFile(filepath.Join(dir, "hooks.json"))
		var top map[string]any
		_ = json.Unmarshal(data, &top)
		if top["x-note"] != "mine" {
			t.Fatalf("top-level key lost: %s", data)
		}
	})

	t.Run("an unknown shape is refused and left untouched", func(t *testing.T) {
		for _, content := range []string{`[]`, `{"hooks":[]}`, `{"hooks":{"Stop":{}}}`, `{"hooks":{"Stop":[1]}}`, `{"hooks":{"Stop":[{"hooks":{}}]}}`, `not json`} {
			dir := codexHome(t)
			path := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			out, code := run(t, dir, nil, "activity", "hook", "install", "--codex")
			after, _ := os.ReadFile(path)
			if code == 0 || !strings.Contains(out, path) || string(after) != content {
				t.Fatalf("shape %s: exit %d %q, file now %s", content, code, out, after)
			}
		}
	})

	t.Run("the runtime must be named", func(t *testing.T) {
		dir := codexHome(t)
		if out, code := run(t, dir, nil, "activity", "hook", "install"); code == 0 || !strings.Contains(out, "--codex") {
			t.Fatalf("install without a runtime: %d %s", code, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "hooks.json")); !os.IsNotExist(err) {
			t.Fatal("wrote hooks.json without a runtime")
		}
	})

	t.Run("an attached principal does not change where it installs", func(t *testing.T) {
		dir := codexHome(t)
		principal, err := os.MkdirTemp(root, "principal-")
		if err != nil {
			t.Fatal(err)
		}
		if out, code := run(t, dir, []string{"AWEB_IDENTITY_HOME=" + principal}, "activity", "hook", "install", "--codex"); code != 0 {
			t.Fatalf("install with an external identity home: %s", out)
		}
		if _, err := os.Stat(filepath.Join(dir, "hooks.json")); err != nil {
			t.Fatal(err)
		}
		if entries, _ := os.ReadDir(principal); len(entries) != 0 {
			t.Fatalf("install wrote into the identity home: %v", entries)
		}
	})
}
