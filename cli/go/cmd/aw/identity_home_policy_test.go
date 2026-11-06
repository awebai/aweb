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

func TestIdentityHomeNeutralExemptionsAreExact(t *testing.T) {
	want := []*cobra.Command{pinStoreCompareAndSetCmd, versionCmd, upgradeCmd, authLoginCmd, authStatusCmd, authLogoutCmd, teamAdmissionInviteCmd, orgCreateCmd, orgListCmd, orgAvailabilityCmd}
	if len(identityHomeNeutralCommandExemptions) != len(want) {
		t.Fatalf("identity-neutral exemption count=%d want %d", len(identityHomeNeutralCommandExemptions), len(want))
	}
	for _, cmd := range want {
		if _, ok := identityHomeNeutralCommandExemptions[cmd]; !ok {
			t.Fatalf("identity-neutral exemption missing command pointer %p (%s)", cmd, cmd.CommandPath())
		}
	}
}

func TestInitExternalIdentityHomeAllowedOnlyForWorkspaceTeam(t *testing.T) {
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
		http.Error(w, "guard must run before network", http.StatusInternalServerError)
	}))
	defer registry.Close()

	for _, tc := range []struct {
		name string
		args []string
		env  []string
	}{
		{name: "hosted-new-account", args: []string{"init", "--new-account", "--username", "alice", "--name", "alice"}},
		{name: "self-hosted-new-team", args: []string{"init", "--new-team", "--name", "alice"}},
		{name: "join-from", args: []string{"init", "--join-from", filepath.Join(root, "source")}},
		{name: "admission-team-id", args: []string{"init", "--admission-team-id", "team:example.com"}},
		{name: "api-key", args: []string{"init", "--new-account", "--username", "alice", "--name", "alice"}, env: []string{"AWEB_API_KEY=secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instance := filepath.Join(root, "instances", tc.name)
			identityHome := filepath.Join(root, "principals", tc.name)
			if err := os.MkdirAll(instance, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(identityHome, 0o700); err != nil {
				t.Fatal(err)
			}
			beforeRequests := requests.Load()
			args := append([]string{"--identity-home", identityHome}, tc.args...)
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = instance
			cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home", tc.name)), append([]string{awconfig.IdentityHomeEnv + "=", "AW_NO_UPDATE_CHECK=1", "AWID_REGISTRY_URL=" + registry.URL, "AWEB_URL=" + registry.URL}, tc.env...)...)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "aw init with --identity-home is only supported for --workspace-team") {
				t.Fatalf("init external-home guard error=%v\n%s", err, out)
			}
			if got := requests.Load(); got != beforeRequests {
				t.Fatalf("external-home guard ran after network: before=%d after=%d", beforeRequests, got)
			}
			if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("refused init mutated instance identity state: %v", err)
			}
			entries, err := os.ReadDir(identityHome)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("refused init mutated principal: %v", entries)
			}
		})
	}

	t.Run("workspace-team-passes-identity-home-policy", func(t *testing.T) {
		instance := filepath.Join(root, "instances", "workspace-team")
		identityHome := filepath.Join(root, "principals", "workspace-team")
		if err := os.MkdirAll(instance, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(identityHome, 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "init", "--workspace-team", "--workspace-key", "oats/workspace/test")
		cmd.Dir = instance
		cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home", "workspace-team")), awconfig.IdentityHomeEnv+"=", "AW_NO_UPDATE_CHECK=1", "AWID_REGISTRY_URL="+registry.URL, "AWEB_URL="+registry.URL)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "authorization-required") {
			t.Fatalf("workspace-team did not pass identity-home policy to team ensure: err=%v\n%s", err, out)
		}
	})
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
