package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
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
	if initCmd.PersistentPreRun == nil {
		t.Fatal("init must retain its descendant persistent hook for the production shadowing regression")
	}
	if _, allowed := identityHomeAwareCommandPaths[initCmd.CommandPath()]; allowed {
		t.Fatal("init unexpectedly allowlisted")
	}
}

func TestIdentityHomeNeutralExemptionsAreExact(t *testing.T) {
	if len(identityHomeNeutralCommandExemptions) != 3 {
		t.Fatalf("identity-neutral exemption count=%d want 3", len(identityHomeNeutralCommandExemptions))
	}
	for _, cmd := range []*cobra.Command{pinStoreCompareAndSetCmd, versionCmd, upgradeCmd} {
		if _, ok := identityHomeNeutralCommandExemptions[cmd]; !ok {
			t.Fatalf("identity-neutral exemption missing command pointer %p (%s)", cmd, cmd.CommandPath())
		}
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

func TestIdentityNeutralExemptionsDoNotAccessPrincipalOrInstanceIdentityState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	identityHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"identity.yaml":  "not: [valid identity yaml",
		"signing.key":    "not a signing key",
		"workspace.yaml": "not: [valid workspace yaml",
	} {
		if err := os.WriteFile(filepath.Join(identityHome, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := fileDigestsForTest(t, identityHome)

	for _, source := range []string{"flag", "environment"} {
		for _, command := range []string{"version", "upgrade", "pin-store-cas"} {
			t.Run(source+"/"+command, func(t *testing.T) {
				instance := filepath.Join(root, "neutral", source, command)
				if err := os.MkdirAll(instance, 0o700); err != nil {
					t.Fatal(err)
				}
				args := []string{command}
				stdin := ""
				if command == "pin-store-cas" {
					args = []string{"id", "pin-store", "compare-and-set", "--path", filepath.Join(root, "pin-stores", source+".yaml")}
					stdin = `{"expected_yaml":"pins: {}\naddresses: {}\n","desired_yaml":"pins: {}\naddresses: {}\n"}`
				}
				env := append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=", "AW_NO_UPDATE_CHECK=1")
				if source == "flag" {
					args = append([]string{"--identity-home", identityHome}, args...)
				} else {
					env = append(env, awconfig.IdentityHomeEnv+"="+identityHome)
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = instance
				cmd.Env = env
				cmd.Stdin = strings.NewReader(stdin)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("identity-neutral command accessed unusable principal state: %v\n%s", err, out)
				}
				if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
					t.Fatalf("identity-neutral command touched instance identity state: %v", err)
				}
				if after := fileDigestsForTest(t, identityHome); !reflect.DeepEqual(after, before) {
					t.Fatal("identity-neutral command changed principal identity state")
				}
			})
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
	var requests atomic.Int32
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "guard must run before registry", http.StatusInternalServerError)
	}))
	defer registry.Close()

	for _, source := range []string{"flag", "environment"} {
		for _, command := range []struct {
			name string
			args []string
		}{
			{name: "roles-show", args: []string{"roles", "show", "--json"}},
			{name: "init-shadow-hook", args: []string{"init"}},
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
				env := append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=", "AWID_REGISTRY_URL="+registry.URL, "AWEB_URL="+registry.URL)
				if source == "flag" {
					args = append([]string{"--identity-home", identityHome}, args...)
				} else {
					env = append(env, awconfig.IdentityHomeEnv+"="+identityHome)
				}
				cmd := exec.CommandContext(ctx, bin, args...)
				cmd.Dir = instance
				cmd.Env = env
				beforeRequests := requests.Load()
				out, err := cmd.CombinedOutput()
				if err == nil || !strings.Contains(string(out), "not yet identity-home-aware") {
					t.Fatalf("unthreaded command did not fail closed: err=%v\n%s", err, out)
				}
				if got := requests.Load(); got != beforeRequests {
					t.Fatalf("refusal happened after registry request: before=%d after=%d", beforeRequests, got)
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
