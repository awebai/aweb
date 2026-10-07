package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAppApprovalManagementBinarySelectedHome(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	setGrantTestEnv(t, root)
	t.Setenv("AW_HOME", filepath.Join(root, "host"))
	var body atomic.Value
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { gets.Add(1); w.Write(body.Load().([]byte)) }))
	defer server.Close()
	body.Store([]byte(appTestManifest(server.URL, "/v1/things/{thing_id}")))
	homes := []string{}
	for _, scope := range []string{awid.IdentityModeLocal, awid.IdentityModeGlobal} {
		parent := filepath.Join(root, scope)
		writeIdentityForTest(t, parent, awconfig.WorktreeIdentity{DID: "did:key:zSynthetic", StableID: "did:aw:synthetic", Custody: awid.CustodySelf, IdentityScope: scope})
		homes = append(homes, filepath.Join(parent, ".aw"))
	}
	empty := filepath.Join(root, "empty")
	if err := os.MkdirAll(empty, 0700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(root, "decoy")
	writeIdentityForTest(t, decoy, awconfig.WorktreeIdentity{DID: "did:key:zDecoy", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal})
	if err := changeAppApproval(filepath.Join(decoy, ".aw"), "decoyapp", "https://decoy.invalid"); err != nil {
		t.Fatal(err)
	}
	decoyBefore, _ := os.ReadFile(appApprovalsPath(filepath.Join(decoy, ".aw")))
	invoke := func(cwd, home, want string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, append([]string{"--identity-home", home, "--json"}, args...)...)
		cmd.Dir = cwd
		cmd.Env = append(os.Environ(), "AW_NO_UPDATE_CHECK=1")
		out, err := cmd.CombinedOutput()
		if want == "" && err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
		if want != "" && (err == nil || !strings.Contains(string(out), want)) {
			t.Fatalf("%v expected %q: %v %s", args, want, err, out)
		}
		return out
	}
	for i, home := range homes {
		cwd := []string{empty, decoy}[i]
		invoke(cwd, home, "", "plugin", "install", server.URL)
		cat, err := loadAppApprovals(home)
		if err != nil || cat.Apps["testapp"] != server.URL {
			t.Fatalf("approval selected home: %v", err)
		}
		out := invoke(cwd, home, "", "plugin", "list")
		if !bytes.Contains(out, []byte(`"testapp"`)) {
			t.Fatal("list missed shared install")
		}
		invoke(cwd, home, "", "plugin", "update", "testapp")
	}
	// Removing resident A's approval does not remove shared state or B's authority.
	dir, _ := pluginDir()
	manifestBefore, _ := os.ReadFile(manifestPluginManifestPath(dir, "testapp"))
	invoke(decoy, homes[0], "", "plugin", "remove", "testapp")
	a, _ := loadAppApprovals(homes[0])
	b, _ := loadAppApprovals(homes[1])
	manifestAfter, _ := os.ReadFile(manifestPluginManifestPath(dir, "testapp"))
	if len(a.Apps) != 0 || len(b.Apps) != 1 || !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("remove changed another resident or host store")
	}
	invoke(empty, homes[0], "app_not_approved", "plugin", "update", "testapp")
	var noApproval pluginRemoveOutput
	if err := json.Unmarshal(invoke(empty, homes[0], "", "plugin", "remove", "testapp"), &noApproval); err != nil || !noApproval.NotApproved || noApproval.ApprovalRemoved {
		t.Fatalf("unapproved remove receipt: %+v %v", noApproval, err)
	}

	invoke(empty, homes[0], "", "plugin", "install", server.URL) // already installed, approval once
	// A changed response ID must not install a second app during update.
	body.Store([]byte(strings.ReplaceAll(appTestManifest(server.URL, "/v1/things/{thing_id}"), `"id":"testapp"`, `"id":"otherapp"`)))
	invoke(empty, homes[0], "app_manifest_mismatch", "plugin", "update", "testapp")
	if manifestPluginExists(dir, "otherapp") {
		t.Fatal("update installed another app")
	}
	body.Store([]byte(appTestManifest(server.URL, "/v1/things/{thing_id}")))
	// A host-store edit cannot silently change the resident's approved origin.
	if err := changeAppApproval(homes[0], "testapp", "https://old.invalid"); err != nil {
		t.Fatal(err)
	}
	invoke(empty, homes[0], "app_origin_mismatch", "plugin", "update", "testapp")
	invoke(empty, homes[0], "", "plugin", "install", server.URL) // explicit reinstall reapproves
	// Executable collisions are refused without invoking or overwriting anything.
	executable := filepath.Join(dir, pluginExecutableName("testapp"))
	marker := filepath.Join(root, "executed")
	payload := []byte("#!/bin/sh\ntouch " + marker + "\n")
	if err := os.WriteFile(executable, payload, 0700); err != nil {
		t.Fatal(err)
	}
	invoke(empty, homes[0], "external plugin", "plugin", "install", server.URL)
	invoke(empty, homes[0], "executable_plugin_refused", "plugin", "update", "testapp")
	invoke(empty, homes[0], "executable_plugin_refused", "plugin", "remove", "testapp")
	invoke(empty, homes[0], "executable_plugin_refused", "plugin", "install", executable)
	retained, _ := os.ReadFile(executable)
	if !bytes.Equal(payload, retained) {
		t.Fatal("executable overwritten")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("executed plugin during management")
	}
	// Worker management fails before any fetch; no cwd resident fallback.
	grantHome := filepath.Join(root, "grant")
	writeGrantHomeForTest(t, grantHome, "http://127.0.0.1:1")
	beforeGets := gets.Load()
	for _, args := range [][]string{{"plugin", "install", server.URL}, {"plugin", "update", "testapp"}, {"plugin", "remove", "testapp"}} {
		invoke(decoy, grantHome, "app_management_denied", args...)
	}
	if gets.Load() != beforeGets {
		t.Fatal("grant management fetched before refusal")
	}
	invoke(empty, grantHome, "", "plugin", "list") // read-only discovery, not delegated authority
	missing := filepath.Join(root, "missing")
	invoke(decoy, missing, "app_resident_required", "plugin", "install", server.URL)
	decoyAfter, _ := os.ReadFile(appApprovalsPath(filepath.Join(decoy, ".aw")))
	if !bytes.Equal(decoyBefore, decoyAfter) {
		t.Fatal("selected operation touched cwd catalog")
	}
	if _, err := os.Stat(filepath.Join(empty, ".aw")); !os.IsNotExist(err) {
		t.Fatal("empty instance gained principal state")
	}
	// JSON output distinguishes installed discovery from approval removal.
	var removed pluginRemoveOutput
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(invoke(empty, homes[0], "", "plugin", "remove", "testapp"), &removed); err != nil || !removed.ApprovalRemoved {
		t.Fatalf("remove receipt: %v", err)
	}
}
