package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

func TestExternalIdentityHomePolicyDefaultsToDeny(t *testing.T) {
	unknown := &cobra.Command{Use: "future-principal-command", Run: func(*cobra.Command, []string) {}}
	root := &cobra.Command{Use: "aw"}
	root.AddCommand(unknown)
	if err := requireIdentityHomeAwareCommand(unknown, true); err == nil || !strings.Contains(err.Error(), "not yet identity-home-aware") {
		t.Fatalf("unmarked command error=%v", err)
	}
	if err := requireIdentityHomeAwareCommand(unknown, false); err != nil {
		t.Fatalf("default cwd behavior was denied: %v", err)
	}
	if err := requireIdentityHomeAwareCommand(introspectCmd, true); err != nil {
		t.Fatalf("explicitly aware command denied: %v", err)
	}
}

func TestIdentityHomeAwareAllowlistNamesExistingRunnableCommands(t *testing.T) {
	for path := range identityHomeAwareCommandPaths {
		args := strings.Fields(strings.TrimPrefix(path, "aw "))
		cmd, remaining, err := rootCmd.Find(args)
		if err != nil || len(remaining) != 0 || cmd == nil || !cmd.Runnable() || cmd.CommandPath() != path {
			t.Errorf("allowlist entry %q does not name one runnable command: cmd=%v remaining=%v err=%v", path, cmd, remaining, err)
		}
	}
}

func TestUnthreadedPrincipalCommandsRefuseExternalIdentityHomeBeforeMutation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	for _, source := range []string{"flag", "environment"} {
		for _, command := range []struct {
			name string
			args []string
		}{
			{name: "identity-create", args: []string{"id", "create", "--name", "unsafe", "--domain", "example.test"}},
			{name: "team-list", args: []string{"id", "team", "list", "--json"}},
		} {
			t.Run(source+"/"+command.name, func(t *testing.T) {
				instance := filepath.Join(root, "instances", source, command.name)
				identityHome := filepath.Join(root, "principals", source, command.name)
				if err := os.MkdirAll(instance, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(identityHome, 0o700); err != nil {
					t.Fatal(err)
				}
				args := append([]string(nil), command.args...)
				env := append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=")
				if source == "flag" {
					args = append([]string{"--identity-home", identityHome}, args...)
				} else {
					env = append(env, awconfig.IdentityHomeEnv+"="+identityHome)
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = instance
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "not yet identity-home-aware") {
					t.Fatalf("unthreaded command did not fail closed: err=%v\n%s", err, out)
				}
				if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
					t.Fatalf("command mutated instance identity state: %v", err)
				}
				entries, err := os.ReadDir(identityHome)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("refused command mutated principal: %v", entries)
				}
			})
		}
	}
}
