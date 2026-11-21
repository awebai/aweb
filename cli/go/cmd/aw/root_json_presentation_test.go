package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRawJSONFlagRespectsExplicitBooleanAndSeparator(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want bool
	}{
		{name: "plain", args: []string{"audit", "verify"}},
		{name: "trailing malformed command flag", args: []string{"audit", "verify", "--bad-flag", "--json"}, want: true},
		{name: "explicit true", args: []string{"audit", "verify", "--json=true"}, want: true},
		{name: "explicit false", args: []string{"audit", "verify", "--json=false"}},
		{name: "last flag wins", args: []string{"--json", "audit", "verify", "--json=false"}},
		{name: "separator hides flag", args: []string{"audit", "verify", "--", "--json"}},
		{name: "separator keeps preceding flag", args: []string{"--json", "audit", "verify", "--", "--json=false"}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := argsContainJSONFlag(test.args); got != test.want {
				t.Fatalf("JSON selection=%t, want %t", got, test.want)
			}
		})
	}
}

func TestMalformedRootFlagsUseRequestedJSONPresentation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "trailing flag", args: []string{"--invalid-root-flag", "--json"}, json: true},
		{name: "explicit true", args: []string{"--invalid-root-flag", "--json=true"}, json: true},
		{name: "explicit false", args: []string{"--invalid-root-flag", "--json=false"}},
		{name: "raw false overrides raw true", args: []string{"--invalid-root-flag", "--json", "--json=false"}},
		{name: "parsed true wins", args: []string{"--json", "--invalid-root-flag", "--json=false"}, json: true},
		{name: "parsed false wins", args: []string{"--json=false", "--invalid-root-flag", "--json"}},
		{name: "separator", args: []string{"--invalid-root-flag", "--", "--json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, bin, test.args...)
			cmd.Dir, cmd.Env = root, testCommandEnv(root)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Run(); err == nil {
				t.Fatal("malformed root flag succeeded")
			}
			if test.json {
				var envelope cliErrorEnvelope
				if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil || envelope.Error.Code == "" {
					t.Fatalf("malformed flag lost JSON envelope: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
			} else if stdout.Len() != 0 {
				t.Fatalf("plain refusal printed JSON: %q", stdout.String())
			}
		})
	}
}
