package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

func TestDeployedManifestBinaryInstallAndAllVerbs(t *testing.T) {
	fixtureRoot, err := filepath.Abs("../../internal/appmanifest/testdata")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	f := setupAppCustodyFixture(t, nil)
	cert, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(f.residentHome, f.grant.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	writeSelectionFixtureForTest(t, filepath.Dir(f.residentHome), testSelectionFixture{AwebURL: f.app.server.URL, TeamID: f.grant.TeamID, Alias: "alice", WorkspaceID: "fixture", DID: f.residentDID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: f.svc.signingKey})
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(f.residentHome, f.grant.TeamID, cert); err != nil {
		t.Fatal(err)
	}
	localHome, err := filepath.EvalSymlinks(f.residentHome)
	if err != nil {
		t.Fatal(err)
	}
	grantHome, err := filepath.EvalSymlinks(f.grantHome)
	if err != nil {
		t.Fatal(err)
	}
	instance := t.TempDir()
	var served atomic.Value
	var publicPaths atomic.Value
	publicPaths.Store(map[string]bool{})
	f.app.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/aweb-app.json" {
			_, _ = w.Write(served.Load().([]byte))
			return
		}
		if publicPaths.Load().(map[string]bool)[r.Method+" "+r.URL.Path] {
			if r.Header.Get("Authorization") != "" {
				t.Error("public tool was signed")
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		f.app.handle(w, r)
	})
	invoke := func(home string, args ...string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = instance
		cmd.Env = append(os.Environ(), awconfig.IdentityHomeEnv+"="+home, "AW_NO_UPDATE_CHECK=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", strings.Join(args[:2], " "), err, out)
		}
	}
	apps := map[string]grantAppSnapshot{}
	for _, name := range []string{"folio", "library"} {
		raw, err := os.ReadFile(filepath.Join(fixtureRoot, name+"-deployed.json"))
		if err != nil {
			t.Fatal(err)
		}
		served.Store(raw)
		// Fetch the byte-identical deployed artifact. The existing explicit dev
		// origin option routes only this offline fixture to loopback; no field is
		// stripped and the installed events metadata must survive re-encoding.
		invoke("", "plugin", "install", f.app.server.URL+"/.well-known/aweb-app.json", "--dev-origin", f.app.server.URL)
		dir, _ := pluginDir()
		installed, err := os.ReadFile(manifestPluginManifestPath(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var m appmanifest.Manifest
		if err := appmanifest.DecodeSingleJSONStrict(installed, &m); err != nil {
			t.Fatal(err)
		}
		var retained struct {
			Events []json.RawMessage `json:"events"`
		}
		if err := json.Unmarshal(installed, &retained); err != nil {
			t.Fatal(err)
		}
		if name == "folio" && len(retained.Events) != 1 {
			t.Fatal("install discarded events")
		}
		var signedVerbs []string
		paths := map[string]bool{}
		calls := map[string][]string{}
		for _, tool := range m.Tools {
			args := []string{name, tool.Name}
			values := map[string]any{}
			properties, _ := tool.InputSchema["properties"].(map[string]any)
			for _, param := range tool.Params {
				prop, _ := properties[param.Name].(map[string]any)
				value := "synthetic"
				switch prop["type"] {
				case "array":
					value = "[]"
				case "object":
					value = "{}"
				case "integer":
					value = "1"
				case "boolean":
					value = "false"
				}
				if c, ok := prop["const"].(string); ok {
					value = c
				}
				if name == "library" && tool.Name == "materialize" && param.Name == "target" {
					value = "remote"
				}
				values[param.Name] = value
				args = append(args, "--"+param.Name, value)
			}
			// Avoid the mutually exclusive template input in a real create request.
			if name == "folio" && tool.Name == "create" {
				args = []string{name, "create", "--slug", "synthetic", "--title", "Synthetic", "--body", "Synthetic body"}
				values = map[string]any{"slug": "synthetic", "title": "Synthetic", "body": "Synthetic body"}
			}
			spec, err := appmanifest.Interpret(appmanifest.InterpretRequest{Manifest: m, Verb: tool.Name, Args: values})
			if err != nil {
				t.Fatalf("%s %s: %v", name, tool.Name, err)
			}
			if tool.Auth == "none" {
				paths[spec.Method+" "+strings.Split(spec.PathQuery, "?")[0]] = true
			} else {
				signedVerbs = append(signedVerbs, tool.Name)
			}
			calls[tool.Name] = args
		}
		publicPaths.Store(paths)
		snap, err := buildGrantAppSnapshots(map[string][]string{name: signedVerbs}, nil)
		if err != nil {
			t.Fatal(err)
		}
		apps[name] = snap[name]
		snapshot := &grantAppToolsSnapshot{Version: grantAppToolsSnapshotVersion, GrantID: appTestGrantID, TeamID: f.grant.TeamID, Apps: apps}
		path, _ := grantAppToolsPath(f.residentHome, appTestGrantID)
		data, _ := json.Marshal(snapshot)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		for _, tool := range m.Tools {
			t.Run(name+"/"+tool.Name, func(t *testing.T) {
				invoke(localHome, calls[tool.Name]...)
				if tool.Auth != "none" {
					invoke(grantHome, calls[tool.Name]...)
				}
			})
		}
	}
	if entries, _ := os.ReadDir(instance); len(entries) != 0 {
		t.Fatal("empty instance was mutated")
	}
	_, verified := f.app.requests()
	if len(verified) != 68 {
		t.Fatalf("verified signed calls=%d want68", len(verified))
	}
}
