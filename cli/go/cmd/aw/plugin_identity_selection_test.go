package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestExternalPluginHelperKeepsSelectedPrincipal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the external plugin fixture is POSIX shell")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	pub, key, _ := awid.GenerateKeypair()
	_, decoy, _ := awid.GenerateKeypair()
	var calls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/plugin-boundary" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		auth := strings.Fields(r.Header.Get("Authorization"))
		if len(auth) != 3 {
			t.Error("plugin helper lost selected authority")
			w.WriteHeader(401)
			return
		}
		sig, _ := base64.RawStdEncoding.DecodeString(auth[2])
		if auth[1] != awid.ComputeDIDKey(pub) || !ed25519.Verify(ed25519.PublicKey(pub), requestSigningPayloadForTest(t, r, body), sig) {
			t.Error("plugin helper fell back to checkout identity")
			w.WriteHeader(403)
			return
		}
		calls.Add(1)
		io.WriteString(w, `{"ok":true}`)
	}))
	selected, cwd := filepath.Join(root, "principal"), filepath.Join(root, "checkout")
	for _, fixture := range []struct {
		dir, alias string
		key        ed25519.PrivateKey
	}{{selected, "actor", key}, {cwd, "decoy", decoy}} {
		writeSelectionFixtureForTest(t, fixture.dir, testSelectionFixture{AwebURL: server.URL, TeamID: fixture.alias + ":example.test", Alias: fixture.alias, DID: awid.ComputeDIDKey(fixture.key.Public().(ed25519.PublicKey)), SigningKey: fixture.key, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal})
	}
	user := filepath.Join(root, "user")
	plugins := filepath.Join(user, ".aw", "plugins")
	if err := os.MkdirAll(plugins, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "aw-probe"), []byte("#!/bin/sh\nAW_NO_UPDATE_CHECK=1 \"$AW_HELPER\" id request GET \"$1\" --team-auth --json\n"), 0700); err != nil {
		t.Fatal(err)
	}
	before := snapshotJoinFiles(t, cwd)
	for _, mode := range []string{"flag", "environment"} {
		args := []string{"probe", server.URL + "/v1/plugin-boundary"}
		env := append(testCommandEnv(user), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME="+filepath.Join(selected, ".aw"))
		if mode == "flag" {
			env = append(env, "AWEB_IDENTITY_HOME="+filepath.Join(cwd, ".aw"))
			args = append([]string{"--identity-home", filepath.Join(selected, ".aw")}, args...)
		}
		command := exec.CommandContext(ctx, bin, args...)
		command.Dir, command.Env = cwd, env
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("plugin %s: %v %s", mode, err, out)
		}
	}
	if calls.Load() != 2 || !reflect.DeepEqual(before, snapshotJoinFiles(t, cwd)) {
		t.Fatal("plugin authority or checkout identity changed")
	}
	missing := filepath.Join(root, "missing")
	command := exec.CommandContext(ctx, bin, "probe", server.URL+"/v1/plugin-boundary")
	command.Dir, command.Env = cwd, append(testCommandEnv(user), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME="+missing)
	if out, err := command.CombinedOutput(); err == nil || !strings.Contains(string(out), missing) {
		t.Fatalf("plugin did not fail on missing selected principal: %v %s", err, out)
	}
	if calls.Load() != 2 {
		t.Fatal("missing actor reached plugin helper network")
	}
}
