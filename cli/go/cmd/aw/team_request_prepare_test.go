package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestTeamRequestPrepareLocalKey(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, context.Background(), bin)
	run := func(dir string, env []string, args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		cmd.Env = append(cmd.Env, env...)
		return cmd.CombinedOutput()
	}
	request := []string{"id", "team", "request", "--team", "backend:acme.com", "--name", "worker", "--json"}
	prepare := append(append([]string{}, request...), "--create-local-key")
	t.Run("fresh and retry", func(t *testing.T) {
		for _, external := range []bool{false, true} {
			t.Run(map[bool]string{false: "cwd", true: "explicit"}[external], func(t *testing.T) {
				dir := t.TempDir()
				root := filepath.Join(dir, ".aw")
				args := append([]string{}, prepare...)
				if external {
					parent, err := filepath.EvalSymlinks(t.TempDir())
					if err != nil {
						t.Fatal(err)
					}
					root = filepath.Join(parent, "fresh")
					args = append([]string{"--identity-home", root}, args...)
				}
				var firstKey []byte
				for i := 0; i < 2; i++ {
					out, err := run(dir, nil, args...)
					if err != nil {
						t.Fatalf("prepare: %v\n%s", err, out)
					}
					var got map[string]any
					if err := json.Unmarshal(out, &got); err != nil {
						t.Fatal(err, string(out))
					}
					keyPath := filepath.Join(root, "signing.key")
					key, err := awid.LoadSigningKey(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
					canonicalRoot, err := filepath.EvalSymlinks(root)
					if err != nil {
						t.Fatal(err)
					}
					if got["status"] != "prepared" || got["identity_scope"] != "local" || got["custody"] != "self" || got["identity_home"] != canonicalRoot || got["key_created"] != (i == 0) || got["did_key"] != did {
						t.Fatalf("receipt: %#v", got)
					}
					if got["command"] != "aw id team add-member --team backend --namespace acme.com --did "+did+" --name worker" {
						t.Fatalf("command: %v", got["command"])
					}
					entries, err := os.ReadDir(root)
					if err != nil || len(entries) != 1 || entries[0].Name() != "signing.key" {
						t.Fatalf("unexpected state: %v %v", entries, err)
					}
					info, err := os.Stat(keyPath)
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("key permissions: %v %v", info, err)
					}
					data, err := os.ReadFile(keyPath)
					if err != nil {
						t.Fatal(err)
					}
					if i == 0 {
						firstKey = data
					} else if !bytes.Equal(firstKey, data) {
						t.Fatal("retry replaced key")
					}
					if bytes.Contains(out, data) {
						t.Fatal("private key in receipt")
					}
				}
				textArgs := []string{"id", "team", "request", "--team", "backend:acme.com", "--name", "worker", "--create-local-key"}
				if external {
					textArgs = append([]string{"--identity-home", root}, textArgs...)
				}
				out, err := run(dir, nil, textArgs...)
				if err != nil || !strings.Contains(string(out), "Local signing key prepared; team membership pending controller approval") {
					t.Fatalf("text: %v %s", err, out)
				}
			})
		}
	})

	t.Run("concurrent preparation never replaces the winner", func(t *testing.T) {
		dir := t.TempDir()
		const count = 8
		type result struct {
			data []byte
			err  error
		}
		results := make(chan result, count)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; data, err := run(dir, nil, prepare...); results <- result{data, err} }()
		}
		close(start)
		wg.Wait()
		close(results)
		key, err := awid.LoadSigningKey(filepath.Join(dir, ".aw", "signing.key"))
		if err != nil {
			t.Fatal(err)
		}
		did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		created := 0
		for result := range results {
			if result.err != nil {
				continue
			} // A concurrently incomplete key may refuse; it must not be overwritten.
			var got map[string]any
			if err := json.Unmarshal(result.data, &got); err != nil {
				t.Fatal(err)
			}
			if got["did_key"] != did {
				t.Fatal("different key returned by concurrent preparation")
			}
			if got["key_created"] == true {
				created++
			}
		}
		if created != 1 {
			t.Fatalf("created receipts=%d, want exactly one", created)
		}
	})
	t.Run("offline preparation bypasses optional network work", func(t *testing.T) {
		var calls atomic.Int32
		server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); http.Error(w, "unexpected network", 500) }))
		dir := t.TempDir()
		out, err := run(dir, []string{"AW_NO_UPDATE_CHECK=", "AWID_REGISTRY_URL=" + server.URL, "AWEB_URL=" + server.URL, "HTTPS_PROXY=" + server.URL, "HTTP_PROXY=" + server.URL}, prepare...)
		if err != nil || calls.Load() != 0 {
			t.Fatalf("offline preparation: calls=%d err=%v %s", calls.Load(), err, out)
		}
	})
	t.Run("occupied state unchanged", func(t *testing.T) {
		for _, name := range []string{"identity.yaml", "teams.yaml", "grant.yaml", "workspace.yaml", "human.yaml", "unknown", "signing.key"} {
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				root := filepath.Join(dir, ".aw")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name), []byte("invalid or occupied"), 0600); err != nil {
					t.Fatal(err)
				}
				before := snapshotPreparationTree(t, root)
				out, err := run(dir, nil, prepare...)
				if err == nil || !strings.Contains(string(out), "without --create-local-key") {
					t.Fatalf("refusal: %v %s", err, out)
				}
				if !reflect.DeepEqual(before, snapshotPreparationTree(t, root)) {
					t.Fatal("refusal mutated target")
				}
			})
		}
	})
	t.Run("global refuses and no flag stays byte identical", func(t *testing.T) {
		dir := t.TempDir()
		pub, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), key); err != nil {
			t.Fatal(err)
		}
		did := awid.ComputeDIDKey(pub)
		stable := awid.ComputeStableID(pub)
		writeIdentityForTest(t, dir, awconfig.WorktreeIdentity{DID: did, StableID: stable, Address: "acme.com/worker", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://registry.invalid", CreatedAt: "2026-04-13T00:00:00Z"})
		wantCommand := "aw id team add-member --team backend --namespace acme.com --did " + did + " --name worker --global --did-aw " + stable + " --address acme.com/worker"
		// Pin the existing public JSON fields and serialization, independent of the output type.
		expected := map[string]string{"command": wantCommand, "team_id": "backend:acme.com", "team": "backend", "domain": "acme.com", "did_key": did, "alias": "worker", "name": "worker", "did_aw": stable, "address": "acme.com/worker"}
		wantBytes, err := json.MarshalIndent(expected, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		want := string(wantBytes) + "\n"

		before := snapshotPreparationTree(t, filepath.Join(dir, ".aw"))
		out, err := run(dir, nil, request...)
		if err != nil || string(out) != want {
			t.Fatalf("legacy JSON changed: %v\n%s\nwant %s", err, out, want)
		}
		out, err = run(dir, nil, prepare...)
		if err == nil || !strings.Contains(string(out), "without --create-local-key") {
			t.Fatalf("global refusal: %v %s", err, out)
		}
		if !reflect.DeepEqual(before, snapshotPreparationTree(t, filepath.Join(dir, ".aw"))) {
			t.Fatal("global target changed")
		}
		out, err = run(dir, nil, request[:len(request)-1]...)
		if err != nil || string(out) != wantCommand+"\n" {
			t.Fatalf("legacy text changed: %v %s", err, out)
		}
	})
	t.Run("selectors and paths refuse before writes", func(t *testing.T) {
		for _, scenario := range []string{"environment", "relative", "symlink-home", "symlink-key", "file-home", "invalid-team", "missing-name"} {
			t.Run(scenario, func(t *testing.T) {
				dir := t.TempDir()
				root := filepath.Join(dir, ".aw")
				args := append([]string{}, prepare...)
				var env []string
				switch scenario {
				case "environment":
					env = []string{"AWEB_IDENTITY_HOME=" + root}
				case "relative":
					args = append([]string{"--identity-home", "relative"}, args...)
				case "symlink-home":
					if err := os.Symlink(t.TempDir(), root); err != nil {
						t.Fatal(err)
					}
				case "symlink-key":
					if err := os.Mkdir(root, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(root, "signing.key")); err != nil {
						t.Fatal(err)
					}
				case "file-home":
					if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
						t.Fatal(err)
					}
				case "invalid-team":
					args[4] = "not-canonical"
				case "missing-name":
					args[6] = ""
				}
				before := snapshotPreparationTree(t, dir)
				out, err := run(dir, env, args...)
				if err == nil {
					t.Fatalf("expected refusal: %s", out)
				}
				if !reflect.DeepEqual(before, snapshotPreparationTree(t, dir)) {
					t.Fatal("refusal wrote state")
				}
			})
		}
	})
}

func snapshotPreparationTree(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += target
		} else if !entry.IsDir() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += string(data)
		}
		result[path] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
