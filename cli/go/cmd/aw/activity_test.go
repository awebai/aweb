package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The host owner's activity opt-in (docs/agent-activity.md, "Host-owner
// opt-in"): aw activity enable|disable|show manage <identity root>/activity.yaml.
func TestActivityOptInCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	run := func(t *testing.T, home string, args ...string) (map[string]any, string, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = root
		cmd.Env = append(testCommandEnv(filepath.Join(root, "home")), "AWEB_IDENTITY_HOME="+home, "AW_NO_UPDATE_CHECK=1", "AWEB_URL=")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		code := 0
		if err := cmd.Run(); err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("run %v: %v", args, err)
			}
			code = exitErr.ExitCode()
		}
		var out map[string]any
		_ = json.Unmarshal(stdout.Bytes(), &out)
		return out, stdout.String() + stderr.String(), code
	}
	identityHome := func(t *testing.T, marker string) string {
		t.Helper()
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		home := filepath.Join(base, "identity")
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		if marker != "" {
			if err := os.WriteFile(filepath.Join(home, marker), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return home
	}
	read := func(t *testing.T, home string) (string, os.FileMode) {
		t.Helper()
		info, err := os.Stat(filepath.Join(home, "activity.yaml"))
		if err != nil {
			t.Fatalf("activity.yaml: %v", err)
		}
		data, err := os.ReadFile(filepath.Join(home, "activity.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(data), info.Mode().Perm()
	}

	t.Run("enable and disable write the file, show reports it", func(t *testing.T) {
		home := identityHome(t, "signing.key")
		if out, all, code := run(t, home, "activity", "show", "--json"); code != 0 || out["activity"] != "off" {
			t.Fatalf("show before enable = %v (%d) %s", out, code, all)
		}
		if _, all, code := run(t, home, "activity", "enable", "--json"); code != 0 {
			t.Fatalf("enable exit %d: %s", code, all)
		}
		content, mode := read(t, home)
		if content != "activity: status\n" || mode != 0o644 {
			t.Fatalf("after enable: %q %o", content, mode)
		}
		out, _, _ := run(t, home, "activity", "show", "--json")
		if out["activity"] != "status" || out["path"] != filepath.Join(home, "activity.yaml") {
			t.Fatalf("show after enable = %v", out)
		}
		if _, all, code := run(t, home, "activity", "disable", "--json"); code != 0 {
			t.Fatalf("disable exit %d: %s", code, all)
		}
		if content, _ := read(t, home); content != "activity: off\n" {
			t.Fatalf("after disable: %q", content)
		}
		if out, _, _ := run(t, home, "activity", "show", "--json"); out["activity"] != "off" {
			t.Fatalf("show after disable = %v", out)
		}
		entries, _ := os.ReadDir(home)
		for _, entry := range entries {
			if entry.Name() != "signing.key" && entry.Name() != "activity.yaml" {
				t.Fatalf("left behind %s", entry.Name())
			}
		}
	})

	t.Run("show fails closed on anything but exactly status", func(t *testing.T) {
		home := identityHome(t, "signing.key")
		for _, content := range []string{"activity: STATUS\n", "activity: [status\n", "activity: true\n", "- activity: status\n", ""} {
			if err := os.WriteFile(filepath.Join(home, "activity.yaml"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, all, code := run(t, home, "activity", "show", "--json"); code != 0 || out["activity"] != "off" {
				t.Fatalf("show for %q = %v (%d) %s", content, out, code, all)
			}
		}
	})

	t.Run("a grant home is an identity root", func(t *testing.T) {
		home := identityHome(t, "grant.yaml")
		if _, all, code := run(t, home, "activity", "enable"); code != 0 {
			t.Fatalf("enable in grant home exit %d: %s", code, all)
		}
		if content, _ := read(t, home); content != "activity: status\n" {
			t.Fatalf("grant home: %q", content)
		}
	})

	t.Run("a directory that is not an identity is refused and left untouched", func(t *testing.T) {
		home := identityHome(t, "")
		_, all, code := run(t, home, "activity", "enable")
		if code == 0 {
			t.Fatalf("enable outside an identity succeeded: %s", all)
		}
		if _, err := os.Stat(filepath.Join(home, "activity.yaml")); !os.IsNotExist(err) {
			t.Fatalf("activity.yaml written outside an identity: %v", err)
		}
	})
}
