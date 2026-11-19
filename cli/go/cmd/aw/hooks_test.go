package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/appmanifest"
)

const hookTestOrigin = "https://hooks.example.test"

// hookTestManifest is the shared v2 base manifest with a hooks slot on the
// real catalog, listing scopes and reads out of code-point order.
func hookTestManifest(t *testing.T) *appmanifest.Resolved {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../test-vectors/app-manifests/app-manifest-v2-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		BaseManifests map[string]map[string]any `json:"base_manifests"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	doc := vectors.BaseManifests["v2"]
	doc["app"].(map[string]any)["origin"] = hookTestOrigin
	catalog := map[string]any{"id": "aweb.hooks", "version": 1}
	doc["hooks"] = map[string]any{
		"registration_version": 1,
		"registrations": []any{map[string]any{
			"catalog": catalog, "hook": "post-command-hook", "tool": "audit-ingest",
			"scopes": []any{"fixture:write", "fixture:append"},
		}},
		"productions": []any{map[string]any{
			"catalog": catalog, "hook": "post-manifest-command-hook",
			"reads": []any{"workspace-read", "workspace-list"},
		}},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := appmanifest.Load(data, nil)
	if err != nil {
		t.Fatalf("load hook test manifest: %v", err)
	}
	return resolved
}

func hookTestRegistration() hookBinding {
	return hookBinding{
		BindingID: "0b8f7c1e-3d2a-4f5b-9c6d-7e8f9a0b1c2d", Kind: "registration", TeamID: "demo:example.com",
		InstallationID: "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b", Generation: 3, AppID: "fixture",
		Origin: hookTestOrigin, Digest: "sha256:" + string(make64('a')),
		CatalogID: "aweb.hooks", CatalogVersion: 1, Hook: "post-command-hook",
		Tool: "audit-ingest", Method: "POST", Path: "/v1/audit-ingest",
		Scopes: []string{"fixture:append", "fixture:write"}, Reads: []string{}, State: "pending",
	}
}

func hookTestProduction() hookBinding {
	b := hookTestRegistration()
	b.BindingID = "5d6e7f80-1a2b-4c3d-8e9f-a0b1c2d3e4f5"
	b.Kind, b.Hook = "production", "post-manifest-command-hook"
	b.Tool, b.Method, b.Path, b.Scopes = "", "", "", []string{}
	b.Reads = []string{"workspace-list", "workspace-read"}
	return b
}

func make64(c byte) []byte {
	out := make([]byte, 64)
	for i := range out {
		out[i] = c
	}
	return out
}

// signableAct is an owner act around subject, so a test can ask the owner-act
// authority whether a verifier would accept the subject's form.
func signableAct(t *testing.T, act string, subject map[string]any) (map[string]any, ed25519.PrivateKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Now().UTC().Truncate(time.Second)
	return map[string]any{
		"v": 1, "type": "aweb.owner-act", "act": act, "team_id": "demo:example.com",
		"aud": "https://aweb.example.test", "team_key_did": awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)),
		"subject": subject, "issued_at": issued.Format(time.RFC3339), "expires_at": issued.Add(5 * time.Minute).Format(time.RFC3339),
		"nonce": "0123456789abcdef0123456789abcdef",
	}, key
}

func TestHookRegistrationSubjectComesFromThePinnedManifestNormalized(t *testing.T) {
	subject, err := hookBindingSubject(hookTestRegistration(), hookTestManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"binding_id": "0b8f7c1e-3d2a-4f5b-9c6d-7e8f9a0b1c2d", "installation_id": "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b",
		"generation": int64(3), "app_id": "fixture", "origin": hookTestOrigin, "digest": "sha256:" + string(make64('a')),
		"kind": "registration", "catalog_id": "aweb.hooks", "catalog_version": int64(1), "hook": "post-command-hook",
		"tool": "audit-ingest", "method": "POST", "path": "/v1/audit-ingest",
		"scopes": []any{"fixture:append", "fixture:write"},
	}
	if !reflect.DeepEqual(subject, want) {
		t.Fatalf("subject:\n got %#v\nwant %#v", subject, want)
	}
	act, key := signableAct(t, "hook-binding.activate", subject)
	if _, _, err := awid.SignOwnerAct(key, act); err != nil {
		t.Fatalf("the owner-act authority refuses the normalized subject: %v", err)
	}
}

func TestHookProductionSubjectCarriesSortedReads(t *testing.T) {
	subject, err := hookBindingSubject(hookTestProduction(), hookTestManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := subject["reads"]; !reflect.DeepEqual(got, []any{"workspace-list", "workspace-read"}) {
		t.Fatalf("reads = %#v", got)
	}
	for _, absent := range []string{"tool", "method", "path", "scopes"} {
		if _, present := subject[absent]; present {
			t.Fatalf("a production subject carries %s", absent)
		}
	}
	act, key := signableAct(t, "hook-binding.revoke", subject)
	if _, _, err := awid.SignOwnerAct(key, act); err != nil {
		t.Fatalf("the owner-act authority refuses the production subject: %v", err)
	}
}

func TestHookSubjectRefusesARowThatDisagreesWithItsPinnedManifest(t *testing.T) {
	resolved := hookTestManifest(t)
	cases := map[string]func(*hookBinding){
		"path":       func(b *hookBinding) { b.Path = "/v1/other" },
		"method":     func(b *hookBinding) { b.Method = "PUT" },
		"scopes":     func(b *hookBinding) { b.Scopes = []string{"fixture:append", "fixture:admin"} },
		"tool":       func(b *hookBinding) { b.Tool = "human-input" },
		"undeclared": func(b *hookBinding) { b.Hook = "post-mutation-hook" },
		"app":        func(b *hookBinding) { b.AppID = "other" },
		"origin":     func(b *hookBinding) { b.Origin = "https://other.example.test" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := hookTestRegistration()
			change(&b)
			if _, err := hookBindingSubject(b, resolved); errorCodeOf(err) != "binding_manifest_mismatch" {
				t.Fatalf("err = %v (code %q)", err, errorCodeOf(err))
			}
		})
	}
	t.Run("reads", func(t *testing.T) {
		b := hookTestProduction()
		b.Reads = []string{"workspace-list"}
		if _, err := hookBindingSubject(b, resolved); errorCodeOf(err) != "binding_manifest_mismatch" {
			t.Fatalf("err = %v (code %q)", err, errorCodeOf(err))
		}
	})
}

func TestHookRevocationSubjectComesFromTheServerRowAlone(t *testing.T) {
	registration := hookTestRegistration()
	registration.Scopes = []string{"fixture:write", "fixture:append", "fixture:write"}
	subject, err := hookBindingRowSubject(registration)
	if err != nil {
		t.Fatal(err)
	}
	if got := subject["scopes"]; !reflect.DeepEqual(got, []any{"fixture:append", "fixture:write"}) {
		t.Fatalf("scopes = %#v", got)
	}
	if subject["digest"] != registration.Digest || subject["path"] != registration.Path {
		t.Fatalf("subject does not name the row's pinned digest and target: %#v", subject)
	}
	act, key := signableAct(t, "hook-binding.revoke", subject)
	if _, _, err := awid.SignOwnerAct(key, act); err != nil {
		t.Fatalf("the owner-act authority refuses the row subject: %v", err)
	}

	// The same binding activated from its manifest names the same subject.
	fromManifest, err := hookBindingSubject(hookTestRegistration(), hookTestManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(subject, fromManifest) {
		t.Fatalf("row subject %#v differs from manifest subject %#v", subject, fromManifest)
	}

	production := hookTestProduction()
	production.Reads = []string{"workspace-read", "workspace-list"}
	subject, err = hookBindingRowSubject(production)
	if err != nil {
		t.Fatal(err)
	}
	if got := subject["reads"]; !reflect.DeepEqual(got, []any{"workspace-list", "workspace-read"}) {
		t.Fatalf("reads = %#v", got)
	}
}

func TestHookSubjectNeedsTheInstallationIdentity(t *testing.T) {
	b := hookTestRegistration()
	b.InstallationID, b.Generation = "", 0
	if _, err := hookBindingSubject(b, hookTestManifest(t)); errorCodeOf(err) != "installation_identity_required" {
		t.Fatalf("err = %v (code %q)", err, errorCodeOf(err))
	}
}

func TestOwnerActAudienceIsTheConfiguredServersHTTPSOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://app.aweb.ai":            "https://app.aweb.ai",
		"https://app.aweb.ai/api/":       "https://app.aweb.ai",
		"https://Aweb.Example.test:8443": "https://aweb.example.test:8443",
		"https://app.aweb.ai:443/api":    "https://app.aweb.ai",
		"https://127.0.0.1:9443/":        "https://127.0.0.1:9443",
	} {
		got, err := ownerActAudience(raw)
		if err != nil || got != want {
			t.Fatalf("ownerActAudience(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"http://localhost:8000", "http://127.0.0.1:18000/api"} {
		if _, err := ownerActAudience(raw); errorCodeOf(err) != "owner_act_requires_https" {
			t.Fatalf("ownerActAudience(%q) err = %v (code %q)", raw, err, errorCodeOf(err))
		}
	}
}
