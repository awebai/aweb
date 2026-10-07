package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

// This is a released-client request/signing fixture, not a Folio service emulator
// or an assertion that production has accepted the workflow.
func TestDeployedFolioBinaryWorkflow(t *testing.T) {
	raw, err := os.ReadFile("../../internal/appmanifest/testdata/folio-deployed.json")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	f := setupAppCustodyFixture(t, nil)
	manifest := strings.Replace(string(raw), "https://folio.aweb.ai", f.app.server.URL, 1)
	dir, err := pluginDir()
	if err != nil {
		t.Fatal(err)
	}
	path := manifestPluginManifestPath(dir, "folio")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	verbs := []string{"create", "show", "list", "append", "versions", "present", "revoke"}
	apps, err := buildGrantAppSnapshots(map[string][]string{"folio": verbs}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveGrantAppToolsSnapshot(f.residentHome, &grantAppToolsSnapshot{Version: grantAppToolsSnapshotVersion, GrantID: appTestGrantID, TeamID: f.grant.TeamID, Apps: apps}); err != nil {
		t.Fatal(err)
	}
	content := strings.Repeat("Synthetic Markdown paragraph.\n", 180)
	var bodyChecks int
	f.app.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		recorder := httptest.NewRecorder()
		f.app.handle(recorder, r)
		if recorder.Code != 200 {
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(recorder.Body.Bytes())
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/documents":
			var got map[string]any
			if json.Unmarshal(body, &got) != nil || got["body"] != content || got["slug"] != "synthetic" {
				t.Error("create body mismatch")
			}
			bodyChecks++
		case "POST /v1/documents/synthetic/versions":
			if string(body) != content || r.Header.Get("Content-Type") != "text/markdown; charset=utf-8" {
				t.Error("append raw body mismatch")
			}
			bodyChecks++
		case "POST /v1/present":
			var got map[string]any
			if json.Unmarshal(body, &got) != nil || got["version"] != float64(2) || got["ttl_seconds"] != float64(300) || got["editable"] != false {
				t.Error("present parameters mismatch")
			}
			bodyChecks++
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	files := t.TempDir()
	create := filepath.Join(files, "create.json")
	appendFile := filepath.Join(files, "version.md")
	payload, _ := json.Marshal(map[string]any{"slug": "synthetic", "title": "Synthetic", "body": content})
	if err := os.WriteFile(create, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appendFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	home, err := filepath.EvalSymlinks(f.grantHome)
	if err != nil {
		t.Fatal(err)
	}
	instance := t.TempDir()
	calls := [][]string{
		{"create", "--body-file", create}, {"show", "--slug", "synthetic"}, {"list"},
		{"append", "--slug", "synthetic", "--body-file", appendFile}, {"versions", "--slug", "synthetic"},
		{"present", "--slug", "synthetic", "--version", "2", "--ttl_seconds", "300", "--editable", "false"},
		{"revoke", "--token", "synthetic-token"},
	}
	for _, args := range calls {
		cmd := exec.CommandContext(ctx, bin, append([]string{"folio"}, args...)...)
		cmd.Dir = instance
		cmd.Env = append(os.Environ(), awconfig.IdentityHomeEnv+"="+home, "AW_NO_UPDATE_CHECK=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v %s", args[0], err, out)
		}
	}
	_, verified := f.app.requests()
	if len(verified) != 7 || bodyChecks != 3 {
		t.Fatalf("signed calls=%d body checks=%d", len(verified), bodyChecks)
	}
	if entries, _ := os.ReadDir(instance); len(entries) != 0 {
		t.Fatal("instance fallback mutation")
	}
	// No finite app authority: the same installed manifest cannot grant it.
	snapshot, _ := grantAppToolsPath(f.residentHome, appTestGrantID)
	if err := os.Remove(snapshot); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "folio", "show", "--slug", "synthetic")
	cmd.Dir = instance
	cmd.Env = append(os.Environ(), awconfig.IdentityHomeEnv+"="+home, "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "app_tool_denied") {
		t.Fatal("absent app authority not refused")
	}
	seen, _ := f.app.requests()
	if len(seen) != 7 {
		t.Fatal("denied call reached app")
	}
	t.Log("seven deployed-manifest command shapes and resident-signed v2 requests verified; 5KB JSON/raw bodies exact; absent snapshot refused before HTTP; no live Folio acceptance claimed")
}
