package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/internal/appmanifest"
)

// notesManifestV2 is a v2 manifest with an agent verb, a surface page, a
// surface-only answer tool and a hook-only target.
func notesManifestV2(t *testing.T, origin string, answerContexts []string) []byte {
	t.Helper()
	object := map[string]any{"type": "object"}
	idProp := map[string]any{"type": "string"}
	tool := func(name, method, path string, props map[string]any, params []map[string]string, mutation bool, contexts []string) map[string]any {
		out := map[string]any{
			"name": name, "method": method, "path": path, "mutation": mutation,
			"input_schema": map[string]any{"type": "object", "properties": props},
			"params":       params, "body": map[string]any{"mode": "json"},
			"scopes": []string{"notes:read"},
		}
		if mutation {
			out["scopes"] = []string{"notes:write"}
		}
		if name == "ingest" {
			out["scopes"] = []string{"notes:ingest"}
		}
		if contexts != nil {
			out["invocation_contexts"] = contexts
		}
		return out
	}
	manifest := map[string]any{
		"manifest_version": 2,
		"app":              map[string]any{"id": "notes", "version": "2.0.0", "origin": origin},
		"tools": []any{
			tool("list", "GET", "/v1/notes", map[string]any{}, []map[string]string{}, false, nil),
			tool("show", "GET", "/v1/notes/{id}", map[string]any{"id": idProp}, []map[string]string{{"name": "id", "in": "path"}}, false, nil),
			tool("invoke", "POST", "/v1/notes/{id}/invoke", map[string]any{"id": idProp, "request": object},
				[]map[string]string{{"name": "id", "in": "path"}, {"name": "request", "in": "body"}}, true, nil),
			tool("answer", "POST", "/v1/notes/{id}/answers", map[string]any{"id": idProp, "request": object},
				[]map[string]string{{"name": "id", "in": "path"}, {"name": "request", "in": "body"}}, true, answerContexts),
			tool("ingest", "POST", "/v1/ingest", map[string]any{"request": object},
				[]map[string]string{{"name": "request", "in": "body"}}, true, []string{"hook"}),
		},
		"surfaces": []any{map[string]any{
			"id": "notes", "label": "Notes", "format": "aweb.page/1",
			"list_tool": "list", "read_tool": "show", "invoke_tool": "invoke", "answer_tool": "answer",
			"inputs": map[string]any{"resource": "id", "invocation": "request"},
		}},
		"hooks": map[string]any{"registration_version": 1, "registrations": []any{map[string]any{
			"catalog": map[string]any{"id": "example.hooks", "version": 1}, "hook": "example.after", "tool": "ingest",
		}}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// serveNoManifestCatalog answers the variant catalog path the way an app
// that publishes only a legacy v1 manifest does: 404.
func serveNoManifestCatalog(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/.well-known/aweb-app-versions.json" {
		http.NotFound(w, r)
		return true
	}
	return false
}

func notesManifestV1(t *testing.T, origin string) []byte {
	t.Helper()
	return []byte(`{"manifest_version":1,"app":{"id":"notes","version":"1.0.0","origin":"` + origin + `"},"tools":[{"name":"list","method":"GET","path":"/v1/notes","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false}]}`)
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func variantCatalog(t *testing.T, variants map[int][]byte) []byte {
	t.Helper()
	entries := []map[string]any{}
	for version := 1; version <= 2; version++ {
		if body, ok := variants[version]; ok {
			entries = append(entries, map[string]any{"manifest_version": version, "url": "/manifests/v" + string(rune('0'+version)) + ".json", "digest": sha256Digest(body)})
		}
	}
	data, err := json.Marshal(map[string]any{"catalog_version": 1, "app_id": "notes", "variants": entries})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// variantAppServer serves whatever its routes hold and records every request.
type variantAppServer struct {
	mu     sync.Mutex
	routes map[string]func() (int, []byte)
	seen   []string
	server *httptest.Server
}

func newVariantAppServer(t *testing.T) *variantAppServer {
	t.Helper()
	s := &variantAppServer{routes: map[string]func() (int, []byte){}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.seen = append(s.seen, r.Method+" "+r.URL.Path)
		route, ok := s.routes[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		status, body := route()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *variantAppServer) serve(path string, status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[path] = func() (int, []byte) { return status, body }
}

func (s *variantAppServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func runAwForTest(ctx context.Context, bin, home string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	return cmd.CombinedOutput()
}

func TestPluginInstallSelectsCatalogV2VariantAndExposesOnlyAgentTools(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	app := newVariantAppServer(t)
	v1 := notesManifestV1(t, app.server.URL)
	v2 := notesManifestV2(t, app.server.URL, []string{"surface"})
	app.serve("/.well-known/aweb-app-versions.json", 200, variantCatalog(t, map[int][]byte{1: v1, 2: v2}))
	app.serve("/manifests/v1.json", 200, v1)
	app.serve("/manifests/v2.json", 200, v2)
	app.serve("/.well-known/aweb-app.json", 200, v1)

	if out, err := runAwForTest(ctx, bin, home, "plugin", "install", app.server.URL); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	stored, err := os.ReadFile(filepath.Join(home, ".aw", "plugins", "notes", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, v2) {
		t.Fatalf("stored manifest is not the selected v2 variant bytes")
	}
	var provenance struct {
		ManifestVersion string `json:"manifest_version"`
		ManifestURL     string `json:"manifest_url"`
		Digest          string `json:"digest"`
	}
	data, err := os.ReadFile(filepath.Join(home, ".aw", "plugins", "notes", "provenance.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.ManifestVersion != "2" || provenance.ManifestURL != app.server.URL+"/manifests/v2.json" || provenance.Digest != sha256Digest(v2) {
		t.Fatalf("provenance %+v does not record the selected variant", provenance)
	}

	help, err := runAwForTest(ctx, bin, home, "notes", "--help")
	if err != nil {
		t.Fatalf("help: %v\n%s", err, help)
	}
	for _, verb := range []string{"list", "show", "invoke"} {
		if !strings.Contains(string(help), verb) {
			t.Fatalf("help omits agent verb %q:\n%s", verb, help)
		}
	}
	for _, verb := range []string{"answer", "ingest"} {
		if strings.Contains(string(help), verb) {
			t.Fatalf("help lists non-agent verb %q:\n%s", verb, help)
		}
	}

	for _, args := range [][]string{
		{"notes", "answer", "--id", "n1", "--request", `{"answer":"yes"}`},
		{"notes", "help", "answer"},
		{"notes", "ingest", "--request", `{}`},
	} {
		out, err := runAwForTest(ctx, bin, home, args...)
		if err == nil || !strings.Contains(string(out), "tool_context_denied") {
			t.Fatalf("%v: err=%v, want tool_context_denied\n%s", args, err, out)
		}
	}
	for _, request := range app.requests() {
		if strings.Contains(request, "/answers") || strings.Contains(request, "/ingest") {
			t.Fatalf("a denied tool reached the app: %v", app.requests())
		}
	}
}

func TestPluginInstallRefusesAgentVisibleAnswerPath(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	app := newVariantAppServer(t)
	v2 := notesManifestV2(t, app.server.URL, nil)
	app.serve("/.well-known/aweb-app-versions.json", 200, variantCatalog(t, map[int][]byte{2: v2}))
	app.serve("/manifests/v2.json", 200, v2)

	out, err := runAwForTest(ctx, bin, home, "plugin", "install", app.server.URL)
	if err == nil || !strings.Contains(string(out), "answer_tool_contexts_invalid") {
		t.Fatalf("install err=%v, want answer_tool_contexts_invalid\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw", "plugins", "notes", "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("refused manifest was stored: %v", err)
	}
}

func TestPluginInstallCatalogFailureDoesNotFallBackToLegacy(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	app := newVariantAppServer(t)
	app.serve("/.well-known/aweb-app-versions.json", 500, []byte(`{"error":"down"}`))
	app.serve("/.well-known/aweb-app.json", 200, notesManifestV1(t, app.server.URL))

	out, err := runAwForTest(ctx, bin, home, "plugin", "install", app.server.URL)
	if err == nil || !strings.Contains(string(out), "catalog_unavailable") {
		t.Fatalf("install err=%v, want catalog_unavailable\n%s", err, out)
	}
	for _, request := range app.requests() {
		if strings.HasSuffix(request, "/.well-known/aweb-app.json") {
			t.Fatalf("legacy manifest fetched after a catalog failure: %v", app.requests())
		}
	}
}

func TestPluginUpdateKeepsLastGoodManifestWhenVariantIsCorrupt(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	app := newVariantAppServer(t)
	v1 := notesManifestV1(t, app.server.URL)
	app.serve("/.well-known/aweb-app.json", 200, v1)
	if out, err := runAwForTest(ctx, bin, home, "plugin", "install", app.server.URL); err != nil {
		t.Fatalf("legacy install: %v\n%s", err, out)
	}

	v2 := notesManifestV2(t, app.server.URL, []string{"surface"})
	app.serve("/.well-known/aweb-app-versions.json", 200, variantCatalog(t, map[int][]byte{1: v1, 2: v2}))
	app.serve("/manifests/v1.json", 200, v1)
	app.serve("/manifests/v2.json", 200, append(append([]byte{}, v2...), '\n'))

	out, err := runAwForTest(ctx, bin, home, "plugin", "update", "notes")
	if err == nil || !strings.Contains(string(out), "variant_digest_mismatch") {
		t.Fatalf("update err=%v, want variant_digest_mismatch\n%s", err, out)
	}
	stored, err := os.ReadFile(filepath.Join(home, ".aw", "plugins", "notes", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, v1) {
		t.Fatalf("a failed update replaced the installed manifest")
	}
}

func TestGrantSnapshotHoldsOnlyAgentTools(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	awHome := filepath.Join(tmp, "aw-home")
	t.Setenv("AW_HOME", awHome)
	origin := "https://notes.example"
	path := manifestPluginManifestPath(filepath.Join(awHome, "plugins"), "notes")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, notesManifestV2(t, origin, []string{"surface"}), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, verb := range []string{"answer", "ingest"} {
		if _, err := buildGrantAppSnapshots(map[string][]string{"notes": {verb}}, nil); err == nil || !strings.Contains(err.Error(), "tool_context_denied") {
			t.Fatalf("%s: err=%v, want tool_context_denied", verb, err)
		}
	}

	snapshots, err := buildGrantAppSnapshotsWithApprovals(map[string][]string{"notes": {"list"}}, nil, map[string]string{"notes": origin})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tool := range snapshots["notes"].Tools {
		names[tool.Name] = true
	}
	if len(names) != 3 || !names["list"] || !names["show"] || !names["invoke"] {
		t.Fatalf("resident snapshot tools = %v, want only the agent tools list, show and invoke", names)
	}
}

func TestCustodyDeniesSnapshotToolOutsideAgentContext(t *testing.T) {
	f := setupAppCustodyFixture(t, []string{"get-thing"})
	path, err := grantAppToolsPath(f.residentHome, appTestGrantID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot grantAppToolsSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	app := snapshot.Apps["testapp"]
	app.ManifestVersion = 2
	for i := range app.Tools {
		app.Tools[i].InvocationContexts = []string{"surface"}
	}
	snapshot.Apps["testapp"] = app
	rewritten, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := runAppTool(t, "get-thing", "--thing_id", "t1"); err == nil || !strings.Contains(err.Error(), "app_tool_denied") {
		t.Fatalf("err=%v, want app_tool_denied for a surface-only snapshot tool", err)
	}
	if seen, _ := f.app.requests(); len(seen) != 0 {
		t.Fatalf("request reached the app: %v", seen)
	}
}

func TestManifestRegistrationDerivesKeysOnTheServer(t *testing.T) {
	manifest := map[string]any{}
	if err := json.Unmarshal(notesManifestV2(t, "https://notes.example", []string{"surface"}), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["app_keys"] = []any{
		map[string]any{"kid": "events", "did_key": "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd", "purposes": []string{"app-event", "app-request"}},
		map[string]any{"kid": "usage", "did_key": "did:key:z6MkhFwXNFWosLeugvSf4wcL9t3uuRXueGSFTRgSvHhWj5G2", "purposes": []string{"app-usage"}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := appmanifest.Load(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := installRegistrationBody(resolved, "sha256:"+strings.Repeat("0", 64), nil, resolved.InstallScopes)
	for _, field := range []string{"event_emitters", "manifest_version", "events", "manifest", "app_version"} {
		if _, ok := body[field]; ok {
			t.Fatalf("separately supplied %s in confirmation: %#v", field, body)
		}
	}

	scopes, _ := body["granted_scopes"].([]string)
	if strings.Join(scopes, ",") != "notes:read,notes:write" {
		t.Fatalf("granted_scopes = %v, want the agent and surface tools' scopes without the hook-only notes:ingest", scopes)
	}
}
