package main

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Codex hooks.json files written by the activity installer run
// `aw activity hook` on every turn event. The command must take the event
// and exit 0 with no output, whatever identity state the session has.
func TestActivityHookDiscardsTheCodexEventAndExitsZero(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	event := []byte(`{"hook_event_name":"PreToolUse","session_id":"s","turn_id":"t","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	for name, identityHome := range map[string]string{
		"no identity":     "",
		"broken selector": filepath.Join(root, "missing", ".aw"),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, bin, "activity", "hook")
			cmd.Dir = root
			cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), "AWEB_IDENTITY_HOME="+identityHome, "AWEB_URL=", "AW_NO_UPDATE_CHECK=1")
			cmd.Stdin = bytes.NewReader(event)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("aw activity hook: %v, stderr %q", err, stderr.String())
			}
			if stdout.Len() != 0 || stderr.Len() != 0 {
				t.Fatalf("aw activity hook wrote stdout %q stderr %q", stdout.String(), stderr.String())
			}
		})
	}
	help, err := exec.CommandContext(ctx, bin, "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("aw --help: %v", err)
	}
	if strings.Contains(string(help), "activity") {
		t.Fatalf("aw --help lists activity:\n%s", help)
	}
}
