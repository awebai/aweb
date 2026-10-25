package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// These wire tests verify selected identity, CAS and local file behavior.
// test_installation_cli.py exercises the real server's authority and revocation.
func TestPluginUninstallSelectedTeamAndSingleCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, awBinaryNameForTest())
	buildAwBinary(t, ctx, bin)
	for _, tc := range []struct {
		name       string
		flags      []string
		generation int64
		conflict   bool
		invalid    bool
		wantReads  int32
	}{
		{name: "read_then_CAS", generation: 7, wantReads: 1},
		{name: "explicit_CAS", flags: []string{"--expected-generation", "11"}, generation: 11},
		{name: "conflict_is_not_retried", generation: 7, conflict: true, wantReads: 1},
		{name: "zero_is_not_an_omitted_flag", flags: []string{"--expected-generation", "0"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			location := filepath.Join(root, tc.name)
			selected, cwd := filepath.Join(location, "selected"), filepath.Join(location, "checkout")
			var reads, writes atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if serveUnadvertisedHealth(w, r) {
					return
				}
				if r.URL.Query().Get("team_id") != "chosen:example.test" || r.Header.Get("X-AWID-Team-Certificate") == "" {
					t.Error("uninstall lost the selected team or certificate")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/apps/folio/installation":
					reads.Add(1)
					fmt.Fprint(w, `{"installation_id":"install-folio","generation":7,"state":"active"}`)
				case r.Method == http.MethodPost && r.URL.Path == "/v1/apps/folio/uninstall":
					writes.Add(1)
					var body map[string]int64
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 1 || body["expected_generation"] != tc.generation {
						t.Errorf("CAS body = %v, error %v", body, err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if tc.conflict {
						w.WriteHeader(http.StatusConflict)
						fmt.Fprint(w, `{"detail":{"code":"generation_conflict"}}`)
						return
					}
					fmt.Fprintf(w, `{"app_id":"folio","installation_id":"install-folio","generation":%d,"state":"uninstalled"}`, tc.generation+1)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			for _, home := range []struct{ path, alias string }{{selected, "chosen"}, {cwd, "decoy"}} {
				pub, key, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				writeSelectionFixtureForTest(t, home.path, testSelectionFixture{
					AwebURL: server.URL, TeamID: home.alias + ":example.test", Alias: home.alias,
					DID: awid.ComputeDIDKey(pub), SigningKey: key, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal,
				})
			}
			user := filepath.Join(location, "user")
			manifest := filepath.Join(user, ".aw", "plugins", "folio", "cached-plugin.bin")
			if err := os.MkdirAll(filepath.Dir(manifest), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manifest, []byte("retained local manifest"), 0600); err != nil {
				t.Fatal(err)
			}
			before := snapshotJoinFiles(t, cwd)
			args := append([]string{"--identity-home", filepath.Join(selected, ".aw"), "--json", "plugin", "uninstall", "folio"}, tc.flags...)
			command := exec.CommandContext(ctx, bin, args...)
			command.Dir, command.Env = cwd, testCommandEnv(user)
			output, err := command.CombinedOutput()
			if tc.invalid || tc.conflict {
				if err == nil {
					t.Fatalf("refused uninstall succeeded: %s", output)
				}
				if tc.conflict && !strings.Contains(string(output), "generation_conflict") {
					t.Fatalf("conflict was hidden: %s", output)
				}
			} else {
				if err != nil {
					t.Fatalf("uninstall: %v %s", err, output)
				}
				var result struct {
					AppID      string `json:"app_id"`
					State      string `json:"state"`
					Generation int64  `json:"generation"`
				}
				if err := json.Unmarshal(output, &result); err != nil || result.AppID != "folio" || result.State != "uninstalled" || result.Generation != tc.generation+1 {
					t.Fatalf("uninstall result: %+v, %v %s", result, err, output)
				}
			}
			wantWrites := int32(1)
			if tc.invalid {
				wantWrites = 0
			}
			if reads.Load() != tc.wantReads || writes.Load() != wantWrites {
				t.Fatalf("requests = %d reads, %d writes", reads.Load(), writes.Load())
			}
			bytes, err := os.ReadFile(manifest)
			if err != nil || string(bytes) != "retained local manifest" || !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
				t.Fatal("server uninstall changed local files")
			}
		})
	}
}
