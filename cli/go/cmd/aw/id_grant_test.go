package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

func resetGrantCommandGlobals(t *testing.T) {
	t.Helper()
	reset := func() {
		grantMintScopes = nil
		grantMintTTL = 8 * time.Hour
		grantMintLabel = ""
		grantMintOut = ""
		jsonFlag = false
	}
	reset()
	t.Cleanup(reset)
}

func setGrantTestEnv(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWEB_URL", "")
	t.Setenv(awconfig.IdentityHomeEnv, "")
}

func writeGrantHomeForTest(t *testing.T, root, awebURL string) (ed25519.PublicKey, *awconfig.GrantHome) {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKeyExclusive(awconfig.GrantHomeSigningKeyPath(root), priv); err != nil {
		t.Fatal(err)
	}
	state := &awconfig.GrantHome{
		Version: awconfig.GrantHomeSchemaVersion,
		GrantID: "grant-777",
		TeamID:  "backend:acme.com",
		Subject: awconfig.GrantSubject{
			DIDAW:   "did:aw:alice",
			DIDKey:  "did:key:zRootAlice",
			Address: "acme.com/alice",
			Alias:   "alice",
		},
		Scopes:    []string{"mail.read", "mail.send"},
		ExpiresAt: "2099-01-01T00:00:00Z",
		AwebURL:   awebURL,
		MintedAt:  "2026-08-12T00:00:00Z",
	}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(root), state); err != nil {
		t.Fatal(err)
	}
	return pub, state
}

func TestRunGrantMintWritesGrantHome(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)

	var gotBody map[string]any
	var gotAuthorization, gotTeamCert string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/identity-grants" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		gotAuthorization = r.Header.Get("Authorization")
		gotTeamCert = r.Header.Get("X-AWID-Team-Certificate")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode mint body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"grant_id":       "grant-9",
			"team_id":        "backend:demo",
			"subject_alias":  "alice",
			"subject_did_aw": "did:aw:alice",
			"grant_did_key":  gotBody["grant_did_key"],
			"scopes":         gotBody["scopes"],
			"issued_at":      "2026-08-12T00:00:00Z",
			"expires_at":     "2026-08-12T08:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)
	outDir := filepath.Join(tmp, "worker-grant")
	grantMintScopes = []string{"mail.read,mail.send", "chat.read"}
	grantMintLabel = "worker"
	grantMintOut = outDir

	var runErr error
	stdout := captureIDCommandStdout(t, func() {
		runErr = runGrantMint(&cobra.Command{}, nil)
	})
	if runErr != nil {
		t.Fatalf("runGrantMint: %v", runErr)
	}

	if !strings.HasPrefix(gotAuthorization, "DIDKey ") || gotTeamCert == "" {
		t.Fatalf("mint must use ordinary team-certificate auth, got Authorization=%q cert present=%v", gotAuthorization, gotTeamCert != "")
	}
	scopes, _ := gotBody["scopes"].([]any)
	if len(scopes) != 3 || scopes[0] != "mail.read" || scopes[1] != "mail.send" || scopes[2] != "chat.read" {
		t.Fatalf("scopes=%v", gotBody["scopes"])
	}
	if ttl, ok := gotBody["ttl_seconds"].(float64); !ok || int(ttl) != 28800 {
		t.Fatalf("ttl_seconds=%v", gotBody["ttl_seconds"])
	}
	if gotBody["label"] != "worker" {
		t.Fatalf("label=%v", gotBody["label"])
	}

	if !awconfig.IsGrantHome(outDir) {
		t.Fatalf("mint did not produce a detectable grant home at %s", outDir)
	}
	grant, err := awconfig.LoadGrantHome(outDir)
	if err != nil {
		t.Fatalf("load minted grant home: %v", err)
	}
	if grant.Version != 1 || grant.GrantID != "grant-9" || grant.TeamID != "backend:demo" {
		t.Fatalf("grant home state=%+v", grant)
	}
	if grant.ExpiresAt != "2026-08-12T08:00:00Z" || grant.MintedAt != "2026-08-12T00:00:00Z" {
		t.Fatalf("grant home timestamps=%+v", grant)
	}
	if grant.AwebURL != server.URL {
		t.Fatalf("grant home aweb_url=%q want %q", grant.AwebURL, server.URL)
	}
	if grant.Subject.Alias != "alice" || grant.Subject.DIDAW != "did:aw:alice" {
		t.Fatalf("grant subject=%+v", grant.Subject)
	}

	keyPath := awconfig.GrantHomeSigningKeyPath(outDir)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat grant session key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("grant session key mode=%v want 0600", info.Mode().Perm())
	}
	sessionKey, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		t.Fatalf("load grant session key: %v", err)
	}
	if did := awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey)); did != gotBody["grant_did_key"] {
		t.Fatalf("stored session key did=%q, registered=%v", did, gotBody["grant_did_key"])
	}

	// The subject's root keys stay out of the grant home, and the private key
	// never reaches stdout.
	for _, forbidden := range []string{"signing.key", "identity.yaml", "workspace.yaml"} {
		if _, err := os.Stat(filepath.Join(outDir, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("grant home must not contain %s", forbidden)
		}
	}
	if strings.Contains(stdout, "PRIVATE KEY") {
		t.Fatalf("stdout leaked private key material:\n%s", stdout)
	}
	if !strings.Contains(stdout, "grant-9") || !strings.Contains(stdout, outDir) {
		t.Fatalf("stdout missing grant id or out dir:\n%s", stdout)
	}
}

func TestRunGrantMintRefusesNonEmptyOut(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)

	outDir := filepath.Join(tmp, "occupied")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "identity.yaml"), []byte("did: did:key:z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	grantMintScopes = []string{"mail.read"}
	grantMintOut = outDir

	err := runGrantMint(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("error=%v, want non-empty --out refusal", err)
	}
}

func TestGrantHomeResolvesToGrantClient(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)

	var gotHeader http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/agents" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		gotHeader = r.Header.Clone()
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": []any{}})
	}))
	t.Cleanup(server.Close)

	sessionPub, grant := writeGrantHomeForTest(t, filepath.Join(tmp, ".aw"), server.URL)

	client, sel, err := resolveClientSelectionForDir(tmp)
	if err != nil {
		t.Fatalf("resolveClientSelectionForDir: %v", err)
	}
	if client.GrantID() != grant.GrantID {
		t.Fatalf("client grant id=%q want %q", client.GrantID(), grant.GrantID)
	}
	if sel.TeamID != grant.TeamID || sel.Alias != "alice" || sel.Address != "acme.com/alice" || sel.StableID != "did:aw:alice" {
		t.Fatalf("selection=%+v", sel)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Client.ListAgents(ctx); err != nil {
		t.Fatalf("ListAgents through grant client: %v", err)
	}
	authorization := gotHeader.Get("Authorization")
	parts := strings.Fields(authorization)
	if len(parts) != 4 || parts[0] != "AWEB-Grant" || parts[1] != "DIDKey" || parts[2] != awid.ComputeDIDKey(sessionPub) {
		t.Fatalf("authorization=%q", authorization)
	}
	if gotHeader.Get("X-AWEB-Grant-ID") != grant.GrantID {
		t.Fatalf("grant id header=%q", gotHeader.Get("X-AWEB-Grant-ID"))
	}
	if gotHeader.Get("X-AWEB-Timestamp") == "" || gotHeader.Get("X-AWEB-Signed-Payload") == "" {
		t.Fatalf("missing grant credential headers: %v", gotHeader)
	}
}

func TestRootAuthorityCommandsRefuseGrantHome(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)
	writeGrantHomeForTest(t, filepath.Join(tmp, ".aw"), "https://app.aweb.ai")

	grantMintScopes = []string{"mail.read"}
	grantMintOut = filepath.Join(tmp, "another-grant")
	if err := runGrantMint(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "this is a grant home; run from the identity's own .aw home") {
		t.Fatalf("mint error=%v, want grant-home refusal", err)
	}
	if err := runGrantRevoke(&cobra.Command{}, []string{"grant-777"}); err == nil || !strings.Contains(err.Error(), "this is a grant home") {
		t.Fatalf("revoke error=%v, want grant-home refusal", err)
	}
	// Selection resolution is the shared seam for other root-authority command
	// families (aw id team ..., aw id request ...): it must refuse too.
	if _, err := resolveSelectionForDir(tmp); err == nil || !strings.Contains(err.Error(), "this is a grant home") {
		t.Fatalf("selection error=%v, want grant-home refusal", err)
	}
}
