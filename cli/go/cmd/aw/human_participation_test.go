package main

import (
	"context"
	"github.com/spf13/cobra"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHumanParticipationManifestSelectorsAreNotAppArguments(t *testing.T) {
	args, _, err := parseManifestDispatchArgs([]string{"--human", "did:aw:human", "--human-domain=example.com", "--resource", "db"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := args["human"]; ok {
		t.Fatal("human selector forwarded to app")
	}
	if _, ok := args["human-domain"]; ok {
		t.Fatal("human-domain selector forwarded to app")
	}
	if args["resource"] != "db" {
		t.Fatalf("args=%v", args)
	}
}
func TestHumanParticipationRuntimeMarkers(t *testing.T) {
	for _, marker := range []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_THREAD_ID"} {
		t.Run(marker, func(t *testing.T) {
			t.Setenv("OATS_INSTANCE_HOME", "")
			t.Setenv("OATS_INSTANCE", "")
			t.Setenv(marker, "present")
			if err := humanAtTerminal(); err == nil || !strings.Contains(err.Error(), marker) {
				t.Fatalf("missing %s guard: %v", marker, err)
			}
		})
	}
}

func TestHumanParticipationSelectorStopsAtBuiltins(t *testing.T) {
	oldID, oldDomain := humanFlag, humanDomainFlag
	defer func() { humanFlag = oldID; humanDomainFlag = oldDomain }()
	humanFlag = ""
	humanDomainFlag = ""
	args := []string{"id", "parent", "request", "--human", "did:aw:local", "--domain", "example.com"}
	got, err := humanSelectorsForPlugin(args)
	if err != nil || humanFlag != "" || !reflect.DeepEqual(got, args) {
		t.Fatalf("builtin selector intercepted: %v %v", got, err)
	}
	got, err = humanSelectorsForPlugin([]string{"--human", "did:aw:selected", "secrets", "request", "--human-domain=example.com", "--resource", "db"})
	if err != nil || humanFlag != "did:aw:selected" || humanDomainFlag != "example.com" || !reflect.DeepEqual(got, []string{"secrets", "request", "--resource", "db"}) {
		t.Fatalf("manifest selector=%v %v", got, err)
	}
}

func TestHumanParticipationUnsupportedCommandsRefuseBeforeCustody(t *testing.T) {
	for _, cmd := range []*cobra.Command{idSignCmd, blueprintPublishProfileCmd, chatSendCmd} {
		if err := prepareHumanParticipation(cmd); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: %v", cmd.CommandPath(), err)
		}
	}
}

func TestHumanParticipationBinaryRefusesNonAllowlistedCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	for _, args := range [][]string{{"id", "sign", "--payload", `{"x":1}`}, {"blueprint", "publish-profile", "."}, {"chat", "send-and-leave", "bob", "hello"}} {
		args = append([]string{"--human", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "--human-domain", "example.com"}, args...)
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = t.TempDir()
		cmd.Env = append(testCommandEnv(t.TempDir()), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "--human is not supported") {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
}
