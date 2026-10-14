package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

// TestSettingsCommandsProductionBinary is the identity-home regression every
// entry in identityHomeAwareCommandPaths owes.
//
// Settings are principal state: with an attached external principal, get reads
// and set writes the principal's settings.yaml. This runs both against a
// principal home whose identity files are unusable, from an empty instance
// directory, and asserts the commands answer, create nothing in the instance
// directory, and leave every other principal file unchanged.
func TestSettingsCommandsProductionBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	for _, principal := range []string{"environment", "flag"} {
		t.Run(principal, func(t *testing.T) {
			principalHome := filepath.Join(root, "principal", principal)
			if err := os.MkdirAll(principalHome, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{
				"identity.yaml":  "not: [valid identity yaml",
				"signing.key":    "not a signing key",
				"workspace.yaml": "not: [valid workspace yaml",
			} {
				if err := os.WriteFile(filepath.Join(principalHome, name), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := fileDigestsForTest(t, principalHome)
			cwd := filepath.Join(root, "cwd", principal)
			if err := os.MkdirAll(cwd, 0o700); err != nil {
				t.Fatal(err)
			}

			run := func(args ...string) string {
				full := append([]string{}, args...)
				env := append(testCommandEnv(filepath.Join(root, "user-home")), "AW_NO_UPDATE_CHECK=1", awconfig.IdentityHomeEnv+"=")
				if principal == "environment" {
					env = append(env, awconfig.IdentityHomeEnv+"="+principalHome)
				} else {
					full = append([]string{"--identity-home", principalHome}, full...)
				}
				cmd := exec.CommandContext(ctx, bin, full...)
				cmd.Dir = cwd
				cmd.Env = env
				out, err := cmd.CombinedOutput()
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) || err != nil {
					t.Fatalf("%v failed: %v\n%s", args, err, out)
				}
				return string(out)
			}
			get := func() settingOutput {
				var out settingOutput
				raw := run("settings", "get", settingEncryptByDefault, "--json")
				if err := json.Unmarshal([]byte(raw), &out); err != nil {
					t.Fatalf("decode settings get: %v\n%s", err, raw)
				}
				return out
			}

			if got := get(); got != (settingOutput{Key: settingEncryptByDefault, Value: false, Source: settingSourceDefault}) {
				t.Fatalf("unset setting = %+v", got)
			}
			run("settings", "set", settingEncryptByDefault, "true")
			if got := get(); got != (settingOutput{Key: settingEncryptByDefault, Value: true, Source: settingSourceSettings}) {
				t.Fatalf("set setting = %+v", got)
			}

			settings, err := awconfig.LoadIdentitySettings(principalHome)
			if err != nil || !settings.EncryptsByDefault() {
				t.Fatalf("principal settings.yaml = %+v, %v", settings, err)
			}
			if _, err := os.Lstat(filepath.Join(cwd, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("a settings command created instance identity state: %v", err)
			}
			if strings.TrimSpace(run("settings", "get", settingEncryptByDefault)) != settingEncryptByDefault+" = true (settings)" {
				t.Fatal("text output does not show the value and its source")
			}
			// settings.yaml was checked above; nothing else in the principal changed.
			if err := os.Remove(awconfig.IdentitySettingsPath(principalHome)); err != nil {
				t.Fatal(err)
			}
			if after := fileDigestsForTest(t, principalHome); !reflect.DeepEqual(after, before) {
				t.Fatal("a settings command changed principal identity state other than settings.yaml")
			}
		})
	}
}
