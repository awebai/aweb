package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHelpTestManifest(t *testing.T, home, origin string) {
	t.Helper()
	dir := filepath.Join(home, ".aw", "plugins", "folio")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"folio","version":"1.0.0","origin":"` + origin + `"},"tools":[` +
		`{"name":"list","description":"List presentations.","method":"GET","path":"/v1/presentations","auth":"none","input_schema":{"type":"object","properties":{"tag":{"type":"string","description":"Filter by tag."}}},"params":[{"name":"tag","in":"query"}],"mutation":false},` +
		`{"name":"create","description":"Create a presentation.","method":"POST","path":"/v1/presentations/{slug}","input_schema":{"type":"object","required":["slug","slides"],"properties":{"slug":{"type":"string","description":"Presentation slug."},"slides":{"type":"array","description":"Slide objects."}}},"params":[{"name":"slug","in":"path"},{"name":"slides","in":"body"}],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"upload","description":"Upload raw notes.","method":"POST","path":"/v1/upload","input_schema":{"type":"object","required":["payload"],"properties":{"payload":{"type":"string","description":"Raw note bytes."}}},"params":[{"name":"payload","in":"body"}],"body":{"mode":"raw","raw_param":"payload","content_type":"text/plain"},"mutation":true}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInstalledManifestHelpRendersFromDiskWithoutRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_HOME", "")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	writeHelpTestManifest(t, home, server.URL)

	appHelp, exists, err := executeInstalledManifestTool("folio", []string{"--help"})
	if err != nil || !exists {
		t.Fatalf("app help exists=%v err=%v", exists, err)
	}
	for _, want := range []string{"Available verbs:", "list", "List presentations.", "create", "Create a presentation."} {
		if !strings.Contains(string(appHelp.Body), want) {
			t.Fatalf("app help missing %q:\n%s", want, appHelp.Body)
		}
	}
	for _, args := range [][]string{{"-h"}, {"help"}} {
		aliasHelp, _, err := executeInstalledManifestTool("folio", args)
		if err != nil || string(aliasHelp.Body) != string(appHelp.Body) {
			t.Fatalf("app help alias %v mismatch err=%v", args, err)
		}
	}
	verbHelp, exists, err := executeInstalledManifestTool("folio", []string{"create", "--help"})
	if err != nil || !exists {
		t.Fatalf("verb help exists=%v err=%v", exists, err)
	}
	for _, want := range []string{"--slug", "string", "required", "Presentation slug.", "--slides", "array", "Slide objects.", "--body-file", "JSON"} {
		if !strings.Contains(string(verbHelp.Body), want) {
			t.Fatalf("verb help missing %q:\n%s", want, verbHelp.Body)
		}
	}
	viaHelp, _, err := executeInstalledManifestTool("folio", []string{"help", "create"})
	if err != nil || string(viaHelp.Body) != string(verbHelp.Body) {
		t.Fatalf("help verb mismatch err=%v\n%s\n%s", err, viaHelp.Body, verbHelp.Body)
	}
	rawHelp, _, err := executeInstalledManifestTool("folio", []string{"upload", "-h"})
	if err != nil {
		t.Fatalf("raw help: %v", err)
	}
	for _, want := range []string{"--payload", "Raw note bytes.", "--body-file", "raw parameter: --payload", "text/plain"} {
		if !strings.Contains(string(rawHelp.Body), want) {
			t.Fatalf("raw help missing %q:\n%s", want, rawHelp.Body)
		}
	}
	if called {
		t.Fatal("help made a manifest endpoint request")
	}
}

func TestInstalledManifestDispatchRejectsUnknownFlagBeforeRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_HOME", "")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()
	writeHelpTestManifest(t, home, server.URL)

	_, exists, err := executeInstalledManifestTool("folio", []string{"list", "--profile_ref", "developer"})
	if !exists || err == nil {
		t.Fatalf("unknown flag exists=%v err=%v", exists, err)
	}
	for _, want := range []string{"unknown flag --profile_ref", "valid flags", "--tag"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("unknown flag error missing %q: %v", want, err)
		}
	}
	if called {
		t.Fatal("unknown flag reached the manifest endpoint")
	}
}
