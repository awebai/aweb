package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestReservedAppIDsArtifactMatchesLiveCobraReservedNames(t *testing.T) {
	artifactPath := filepath.Join(cmdMonorepoRootForTest(t), "test-vectors", "reserved-app-ids-v1.json")
	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	var artifact reservedAppIDsOutput
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	live := reservedAppIDsArtifact()
	if artifact.Schema != live.Schema {
		t.Fatalf("schema got %q want %q", artifact.Schema, live.Schema)
	}
	if strings.Join(artifact.ReservedAppIDs, "\n") != strings.Join(live.ReservedAppIDs, "\n") {
		t.Fatalf("reserved app ids artifact drifted\nartifact=%v\nlive=%v", artifact.ReservedAppIDs, live.ReservedAppIDs)
	}
}

func TestPluginReservedNamesCommandJSON(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	cmd := exec.CommandContext(ctx, bin, "plugin", "reserved-names", "--json")
	cmd.Env = append(os.Environ(), "HOME="+tmp, "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reserved-names failed: %v\n%s", err, string(out))
	}
	var got reservedAppIDsOutput
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	want := reservedAppIDsArtifact()
	if got.Schema != want.Schema || strings.Join(got.ReservedAppIDs, "\n") != strings.Join(want.ReservedAppIDs, "\n") {
		t.Fatalf("reserved-names output got %#v want %#v", got, want)
	}
}

func cmdMonorepoRootForTest(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func TestTrustedPluginResolutionPrecedenceNetworkFree(t *testing.T) {
	tmp := t.TempDir()
	awHome := filepath.Join(tmp, "aw-home")
	t.Setenv("AW_HOME", awHome)
	pluginsDir := filepath.Join(awHome, "plugins")
	if err := os.MkdirAll(filepath.Join(pluginsDir, "folio"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(pluginsDir, "folio", "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"manifest_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	externalPath := filepath.Join(pluginsDir, "aw-folio")
	if err := os.WriteFile(externalPath, []byte("#!/bin/sh\necho external\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	resolution, err := resolveTrustedPluginCommand("folio")
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Kind != pluginResolutionManifest || resolution.Path != manifestPath {
		t.Fatalf("resolution got %#v, want manifest %s", resolution, manifestPath)
	}

	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}
	resolution, err = resolveTrustedPluginCommand("folio")
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Kind != pluginResolutionExternal || resolution.Path != externalPath {
		t.Fatalf("resolution got %#v, want external %s", resolution, externalPath)
	}

	pathOnlyDir := filepath.Join(tmp, "pathbin")
	if err := os.MkdirAll(pathOnlyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pathOnlyDir, "aw-pathonly"), []byte("#!/bin/sh\necho path\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathOnlyDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	resolution, err = resolveTrustedPluginCommand("pathonly")
	if err != nil {
		t.Fatal(err)
	}
	if resolution.Kind != pluginResolutionNone {
		t.Fatalf("PATH-only plugin resolved from untrusted PATH: %#v", resolution)
	}
}

func TestTeamAuthSignerHeadersNetworkFree(t *testing.T) {
	tmp := t.TempDir()
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, "https://workspace.example", "default:acme.com", "alice", did, priv)
	identity := &localSigningIdentity{
		DIDKey:     did,
		SigningKey: priv,
		WorkingDir: tmp,
		TeamID:     "default:acme.com",
	}
	parsed, err := url.Parse("https://app.example/v1/present?tag=a")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"slug":"pitch"}`)
	headers := make(http.Header)
	if err := signIDRequestHeaders(headers, http.MethodPost, parsed, identity, body, map[string]any{}, true, "2026-06-16T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if headers.Get("Authorization") == "" || headers.Get("X-AWID-Team-Certificate") == "" {
		t.Fatalf("missing signer headers: %#v", headers)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(headers.Get("X-AWEB-Signed-Payload"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	want := map[string]any{
		"aud":         "https://app.example",
		"method":      "POST",
		"path":        "/v1/present?tag=a",
		"team_id":     "default:acme.com",
		"body_sha256": fmt.Sprintf("%x", sum),
		"timestamp":   "2026-06-16T00:00:00Z",
		"v":           float64(2),
	}
	for key, wantValue := range want {
		if got := payload[key]; got != wantValue {
			t.Fatalf("payload[%s]=%#v want %#v in %s", key, got, wantValue, string(payloadBytes))
		}
	}
}

func TestPluginExternalDispatchUsesTrustedDirOnlyAndEnvContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	home := filepath.Join(tmp, "home")
	pluginsDir := filepath.Join(home, ".aw", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	trustedPlugin := filepath.Join(pluginsDir, "aw-hello")
	trustedScript := `#!/bin/sh
printf 'trusted args=%s\n' "$*"
printf 'AW_HELPER=%s\n' "$AW_HELPER"
printf 'AW_HOME=%s\n' "$AW_HOME"
printf 'AW_TEAM=%s\n' "$AW_TEAM"
printf 'AW_SERVER=%s\n' "$AW_SERVER"
printf 'AW_DID=%s\n' "$AW_DID"
`
	if err := os.WriteFile(trustedPlugin, []byte(trustedScript), 0o755); err != nil {
		t.Fatal(err)
	}

	pathDir := filepath.Join(tmp, "pathbin")
	if err := os.MkdirAll(pathDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pathOnlyPlugin := filepath.Join(pathDir, "aw-pathonly")
	if err := os.WriteFile(pathOnlyPlugin, []byte("#!/bin/sh\necho path-plugin-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	runTrusted := exec.CommandContext(ctx, bin, "hello", "one", "two")
	runTrusted.Dir = tmp
	runTrusted.Env = append(os.Environ(), "HOME="+home, "PATH="+pathDir+string(os.PathListSeparator)+os.Getenv("PATH"), "AW_NO_UPDATE_CHECK=1")
	trustedOut, err := runTrusted.CombinedOutput()
	if err != nil {
		t.Fatalf("trusted plugin dispatch failed: %v\n%s", err, string(trustedOut))
	}
	trustedText := string(trustedOut)
	for _, want := range []string{
		"trusted args=one two",
		"AW_HELPER=" + bin,
		"AW_HOME=" + filepath.Join(home, ".aw"),
		"AW_TEAM=",
		"AW_SERVER=",
		"AW_DID=",
	} {
		if !strings.Contains(trustedText, want) {
			t.Fatalf("trusted plugin output missing %q:\n%s", want, trustedText)
		}
	}

	runPathOnly := exec.CommandContext(ctx, bin, "pathonly")
	runPathOnly.Dir = tmp
	runPathOnly.Env = append(os.Environ(), "HOME="+home, "PATH="+pathDir+string(os.PathListSeparator)+os.Getenv("PATH"), "AW_NO_UPDATE_CHECK=1")
	pathOut, err := runPathOnly.CombinedOutput()
	if err == nil {
		t.Fatalf("PATH-only plugin unexpectedly ran:\n%s", string(pathOut))
	}
	if strings.Contains(string(pathOut), "path-plugin-ran") {
		t.Fatalf("external plugin resolved from PATH, want trusted dir only:\n%s", string(pathOut))
	}
	if !strings.Contains(string(pathOut), `unknown command "pathonly" for "aw"`) {
		t.Fatalf("PATH-only plugin should fall through to Cobra unknown command:\n%s", string(pathOut))
	}
}

func TestExternalPluginEnvAllowlistExcludesDotenvSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	home := filepath.Join(tmp, "home")
	pluginsDir := filepath.Join(home, ".aw", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(pluginsDir, "aw-dotenv")
	script := `#!/bin/sh
env | sort
`
	if err := os.WriteFile(plugin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".env"), []byte("SECRET_CANARY=leaked-from-dotenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".env.aweb"), []byte("SECRET_CANARY_AWEB=leaked-from-dotenv-aweb\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "dotenv")
	run.Dir = tmp
	run.Env = envWithout(os.Environ(), "SECRET_CANARY", "SECRET_CANARY_AWEB", "HOME", "AW_NO_UPDATE_CHECK")
	run.Env = append(run.Env,
		"HOME="+home,
		"AW_NO_UPDATE_CHECK=1",
		"SECRET_CANARY=parent-env-secret",
		"SECRET_CANARY_AWEB=parent-env-aweb-secret",
		"UNRELATED_PARENT_SECRET=parent-secret",
	)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("plugin dispatch failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, forbidden := range []string{"SECRET_CANARY=", "SECRET_CANARY_AWEB=", "UNRELATED_PARENT_SECRET="} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("pluginEnv leaked non-allowlisted secret %q:\n%s", forbidden, text)
		}
	}
	for _, want := range []string{
		"AW_DID=",
		"AW_TEAM=",
		"AW_SERVER=",
		"AW_HOME=" + filepath.Join(home, ".aw"),
		"AW_HELPER=" + bin,
		"HOME=" + home,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("plugin env missing allowlisted value %q:\n%s", want, text)
		}
	}
}

func envWithout(env []string, keys ...string) []string {
	blocked := map[string]bool{}
	for _, key := range keys {
		blocked[key] = true
	}
	out := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if !blocked[key] {
			out = append(out, entry)
		}
	}
	return out
}

func TestPluginManagementInstallListRemoveAndRejectBuiltins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	source := filepath.Join(tmp, "aw-foo")
	if err := os.WriteFile(source, []byte("#!/bin/sh\necho foo\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	install := exec.CommandContext(ctx, bin, "plugin", "install", source,
		"--app-id", "app.folio", "--manifest-version", "2026-06-16", "--app-version", "1.2.3", "--origin", "https://folio.example")
	install.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("plugin install failed: %v\n%s", err, string(out))
	}
	installed := filepath.Join(home, ".aw", "plugins", "aw-foo")
	if info, err := os.Stat(installed); err != nil || info.Mode()&0o111 == 0 {
		t.Fatalf("installed plugin missing or not executable: info=%v err=%v", info, err)
	}
	provenancePath := filepath.Join(home, ".aw", "plugins", "aw-foo.provenance.json")
	provenanceData, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	var provenance struct {
		AppName         string `json:"app_name"`
		AppID           string `json:"app_id"`
		ManifestVersion string `json:"manifest_version"`
		AppVersion      string `json:"app_version"`
		Origin          string `json:"origin"`
		Source          string `json:"source"`
		Digest          string `json:"digest"`
	}
	if err := json.Unmarshal(provenanceData, &provenance); err != nil {
		t.Fatalf("decode provenance: %v\n%s", err, string(provenanceData))
	}
	if provenance.AppName != "foo" || provenance.AppID != "app.folio" || provenance.ManifestVersion != "2026-06-16" || provenance.AppVersion != "1.2.3" || provenance.Origin != "https://folio.example" || provenance.Source != source || !strings.HasPrefix(provenance.Digest, "sha256:") {
		t.Fatalf("unexpected provenance: %#v", provenance)
	}

	installAgain := exec.CommandContext(ctx, bin, "plugin", "install", source)
	installAgain.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := installAgain.CombinedOutput(); err == nil || !strings.Contains(string(out), "already installed") {
		t.Fatalf("second install should reject name collision, err=%v out=%s", err, string(out))
	}

	list := exec.CommandContext(ctx, bin, "--json", "plugin", "list")
	list.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	listOut, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("plugin list failed: %v\n%s", err, string(listOut))
	}
	var listed struct {
		Plugins []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			Provenance struct {
				AppID  string `json:"app_id"`
				Origin string `json:"origin"`
			} `json:"provenance"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(extractJSON(t, listOut), &listed); err != nil {
		t.Fatalf("decode plugin list: %v\n%s", err, string(listOut))
	}
	if len(listed.Plugins) != 1 || listed.Plugins[0].Name != "foo" || listed.Plugins[0].Path != installed || listed.Plugins[0].Provenance.AppID != "app.folio" || listed.Plugins[0].Provenance.Origin != "https://folio.example" {
		t.Fatalf("unexpected plugin list: %#v", listed.Plugins)
	}

	remove := exec.CommandContext(ctx, bin, "plugin", "remove", "foo")
	remove.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := remove.CombinedOutput(); err != nil {
		t.Fatalf("plugin remove failed: %v\n%s", err, string(out))
	}
	if _, err := os.Stat(installed); !os.IsNotExist(err) {
		t.Fatalf("plugin still exists after remove: %v", err)
	}

	for _, name := range []string{"aw-id", "aw-introspect"} {
		reservedSource := filepath.Join(tmp, name)
		if err := os.WriteFile(reservedSource, []byte("#!/bin/sh\necho reserved\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, bin, "plugin", "install", reservedSource)
		cmd.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("install of reserved plugin %s unexpectedly succeeded:\n%s", name, string(out))
		}
		if !strings.Contains(string(out), "reserved built-in command or alias") {
			t.Fatalf("reserved plugin error missing reason for %s:\n%s", name, string(out))
		}
	}
}

func TestPluginInstallFetchesWellKnownManifestAndUpdateRefreshes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	version := "1.0.0"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/.well-known/aweb-app.json" {
			t.Fatalf("unexpected manifest request %s %s", r.Method, r.URL.String())
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"manifest_version":1,"app":{"id":"folio","version":"` + version + `","origin":"` + serverOriginForTest(r) + `"},"tools":[{"name":"show","method":"GET","path":"/v1/documents/{slug}","input_schema":{"type":"object","properties":{"slug":{"type":"string"}}},"params":[{"name":"slug","in":"path"}],"body":{"mode":"json"},"mutation":false}]}`))
	}))
	defer server.Close()

	install := exec.CommandContext(ctx, bin, "plugin", "install", server.URL)
	install.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("manifest install failed: %v\n%s", err, string(out))
	}
	manifestPath := filepath.Join(home, ".aw", "plugins", "folio", "manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifest not stored: %v", err)
	}
	provenancePath := filepath.Join(home, ".aw", "plugins", "folio", "provenance.json")
	data, err := os.ReadFile(provenancePath)
	if err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	var provenance struct {
		AppID           string `json:"app_id"`
		ManifestVersion string `json:"manifest_version"`
		AppVersion      string `json:"app_version"`
		Origin          string `json:"origin"`
		ManifestURL     string `json:"manifest_url"`
		Digest          string `json:"digest"`
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatalf("decode provenance: %v\n%s", err, string(data))
	}
	if provenance.AppID != "folio" || provenance.ManifestVersion != "1" || provenance.AppVersion != "1.0.0" || provenance.Origin != server.URL || provenance.ManifestURL != server.URL+"/.well-known/aweb-app.json" || !strings.HasPrefix(provenance.Digest, "sha256:") {
		t.Fatalf("unexpected provenance: %#v", provenance)
	}

	version = "1.0.1"
	update := exec.CommandContext(ctx, bin, "plugin", "update", "folio")
	update.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := update.CombinedOutput(); err != nil {
		t.Fatalf("manifest update failed: %v\n%s", err, string(out))
	}
	data, err = os.ReadFile(provenancePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.AppVersion != "1.0.1" {
		t.Fatalf("update did not refresh app version: %#v", provenance)
	}
}

func serverOriginForTest(r *http.Request) string {
	return "http://" + r.Host
}

func TestInstalledManifestDispatchInvokesTeamAuthRequest(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))

	var sawSignedPayload bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/aweb-app.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"manifest_version":1,"app":{"id":"folio","version":"1.0.0","origin":"` + serverOriginForTest(r) + `"},"tools":[{"name":"present","method":"POST","path":"/v1/present","input_schema":{"type":"object","properties":{"slug":{"type":"string"},"ttl_seconds":{"type":"integer"},"editable":{"type":"boolean"}}},"params":[{"name":"slug","in":"body"},{"name":"ttl_seconds","in":"body"},{"name":"editable","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`))
		case "/v1/present":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Fatalf("Content-Type=%q", got)
			}
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWEB-Signed-Payload") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("missing team-auth headers: %#v", r.Header)
			}
			sawSignedPayload = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["ttl_seconds"] != float64(3600) || body["editable"] != true || body["slug"] != "pitch" {
				t.Fatalf("unexpected body: %#v", body)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, server.URL, "default:acme.com", "alice", did, priv)

	install := exec.CommandContext(ctx, bin, "plugin", "install", server.URL)
	install.Dir = tmp
	install.Env = append(testCommandEnv(tmp), "AW_NO_UPDATE_CHECK=1")
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("plugin install failed: %v\n%s", err, string(out))
	}

	run := exec.CommandContext(ctx, bin, "folio", "present", "--slug", "pitch", "--ttl_seconds", "3600", "--editable", "true")
	run.Dir = tmp
	run.Env = append(testCommandEnv(tmp), "AW_NO_UPDATE_CHECK=1")
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("manifest dispatch failed: %v\n%s", err, string(out))
	}
	if strings.TrimSpace(string(out)) != `{"ok":true}` {
		t.Fatalf("unexpected dispatch output: %s", string(out))
	}
	if !sawSignedPayload {
		t.Fatal("app endpoint was not called with signed payload")
	}
}

func TestPluginInstallRejectsMalformedManifestViaSharedValidation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	cases := []struct {
		name     string
		manifest string
		want     string
	}{
		{
			name:     "param without input_schema property",
			manifest: `{"manifest_version":1,"app":{"id":"bad","version":"1.0.0","origin":"$ORIGIN"},"tools":[{"name":"x","method":"POST","path":"/v1/x","params":[{"name":"slug","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`,
			want:     "not declared in input_schema",
		},
		{
			name:     "path query",
			manifest: `{"manifest_version":1,"app":{"id":"bad","version":"1.0.0","origin":"$ORIGIN"},"tools":[{"name":"x","method":"GET","path":"/v1/x?fixed=1","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false}]}`,
			want:     "query",
		},
		{
			name:     "claimed origin mismatch",
			manifest: `{"manifest_version":1,"app":{"id":"bad","version":"1.0.0","origin":"https://other.example"},"tools":[{"name":"x","method":"GET","path":"/v1/x","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false}]}`,
			want:     "claims origin",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := filepath.Join(tmp, "home-"+strings.NewReplacer(" ", "-", "/", "-").Replace(tc.name))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/aweb-app.json" {
					t.Fatalf("unexpected request path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.ReplaceAll(tc.manifest, "$ORIGIN", serverOriginForTest(r))))
			}))
			defer server.Close()

			install := exec.CommandContext(ctx, bin, "plugin", "install", server.URL)
			install.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
			out, err := install.CombinedOutput()
			if err == nil {
				t.Fatalf("plugin install unexpectedly accepted malformed manifest:\n%s", string(out))
			}
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("install error %q does not contain %q", string(out), tc.want)
			}
		})
	}
}

func TestPluginInstallRejectsCrossOriginManifestRedirect(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	var source *httptest.Server
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/aweb-app.json" {
			t.Fatalf("unexpected target path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"manifest_version":1,"app":{"id":"bad","version":"1.0.0","origin":"` + source.URL + `"},"tools":[{"name":"x","method":"GET","path":"/v1/x","input_schema":{"type":"object","properties":{}},"params":[],"body":{"mode":"json"},"mutation":false}]}`))
	}))
	defer target.Close()
	source = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/aweb-app.json" {
			t.Fatalf("unexpected source path %s", r.URL.Path)
		}
		http.Redirect(w, r, target.URL+"/.well-known/aweb-app.json", http.StatusFound)
	}))
	defer source.Close()

	install := exec.CommandContext(ctx, bin, "plugin", "install", source.URL)
	install.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	out, err := install.CombinedOutput()
	if err == nil {
		t.Fatalf("plugin install unexpectedly followed cross-origin manifest redirect:\n%s", string(out))
	}
	if !strings.Contains(string(out), "cross-origin redirect") {
		t.Fatalf("install error %q does not mention cross-origin redirect", string(out))
	}
}

func TestPluginBuiltInCommandWinsOverTrustedPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")
	pluginsDir := filepath.Join(home, ".aw", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginsDir, "aw-version"), []byte("#!/bin/sh\necho plugin-version-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw version failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "plugin-version-ran") {
		t.Fatalf("built-in version command was shadowed by plugin:\n%s", text)
	}
	if !strings.Contains(text, "aw dev") {
		t.Fatalf("expected built-in version output:\n%s", text)
	}
}
