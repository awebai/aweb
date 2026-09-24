package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
		grantMintBundles = nil
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

func TestParseGrantScopesExpandsNormalAgentBundle(t *testing.T) {
	scopes, err := parseGrantScopesWithBundles([]string{"mail.read", "contacts.read"}, []string{"normal-agent"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mail.read", "mail.send", "chat.read", "chat.send", "events.read", "coord.read", "coord.write", "presence.write", "contacts.read", "contacts.write"}
	if len(scopes) != len(want) {
		t.Fatalf("scopes=%v, want %v", scopes, want)
	}
	for i := range want {
		if scopes[i] != want[i] {
			t.Fatalf("scopes=%v, want %v", scopes, want)
		}
	}
	if _, err := parseGrantScopesWithBundles(nil, []string{"unknown"}); err == nil || !strings.Contains(err.Error(), "unknown grant scope bundle") {
		t.Fatalf("unknown bundle err=%v", err)
	}
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

func TestGrantHomeCustodySocketSignsPlainMail(t *testing.T) {
	resetGrantCommandGlobals(t)
	tmp := t.TempDir()
	t.Chdir(tmp)
	setGrantTestEnv(t, tmp)

	_, residentKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	residentDID := awid.ComputeDIDKey(residentKey.Public().(ed25519.PublicKey))
	var got map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"message_id": got["message_id"], "status": "delivered", "delivered_at": "2026-09-24T00:00:00Z"})
	}))
	t.Cleanup(server.Close)

	grantHome := filepath.Join(tmp, ".aw")
	_, grant := writeGrantHomeForTest(t, grantHome, server.URL)
	grant.Subject.DIDKey = residentDID
	socketID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	custodyRunDir := filepath.Join("/tmp", "aw-custody-"+socketID[:8])
	_ = os.RemoveAll(custodyRunDir)
	t.Cleanup(func() { _ = os.RemoveAll(custodyRunDir) })
	grant.Custody.SocketPath = filepath.Join(custodyRunDir, "custody.sock")
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(grantHome), grant); err != nil {
		t.Fatal(err)
	}
	sessionKey, err := awid.LoadSigningKey(awconfig.GrantHomeSigningKeyPath(grantHome))
	if err != nil {
		t.Fatal(err)
	}
	sessionDID := awid.ComputeDIDKey(sessionKey.Public().(ed25519.PublicKey))
	svc := &custodyService{
		socketPath: grant.Custody.SocketPath,
		identity:   &awconfig.ResolvedIdentity{DID: residentDID, StableID: grant.Subject.DIDAW, Address: grant.Subject.Address, Handle: grant.Subject.Alias},
		signingKey: residentKey,
		now:        time.Now,
		replay:     map[string]string{},
		replayAt:   map[string]time.Time{},
		results:    map[string]any{},
		grantStatus: func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
			return custodyGrantStatus{Active: true, Status: "active", EffectiveStatus: "active", TeamID: grant.TeamID, GrantDIDKey: sessionDID, Scopes: grant.Scopes, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- svc.serve(ctx) }()
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(grant.Custody.SocketPath); err == nil {
			break
		}
		select {
		case err := <-errc:
			t.Fatalf("custody service exited before creating socket: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}

	client, _, err := resolveClientSelectionForDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SendMessage(context.Background(), &awid.SendMessageRequest{ToAlias: "bob", Subject: "hi", Body: "body"}); err != nil {
		t.Fatal(err)
	}
	if got["from_did"] != residentDID {
		t.Fatalf("from_did=%v want resident %s", got["from_did"], residentDID)
	}
	if got["signature"] == "" || got["signed_payload"] == "" {
		t.Fatalf("message not signed through custody: %#v", got)
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

func TestGrantCommandsUseExternalIdentityHomeWithRealBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	shadowDID := awid.ComputeDIDKey(shadowPub)

	var requestMu sync.Mutex
	var signedRequests []messagingSignedRequest
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if r.Header.Get("Authorization") != "" {
			requestMu.Lock()
			signedRequests = append(signedRequests, messagingSignedRequest{
				authorization: r.Header.Get("Authorization"),
				timestamp:     r.Header.Get("X-AWEB-Timestamp"),
				method:        r.Method,
				path:          r.URL.Path,
				body:          body,
			})
			requestMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/identity-grants":
			_ = json.NewEncoder(w).Encode(map[string]any{"grants": []any{map[string]any{
				"grant_id": "grant-9", "team_id": "runtime:aweb.test", "subject_alias": "principal",
				"subject_did_aw": "did:aw:principal", "grant_did_key": "did:key:zGrant", "scopes": []string{"mail.read"},
				"status": "active", "issued_at": "2026-08-12T00:00:00Z", "expires_at": "2026-08-12T01:00:00Z",
			}}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/identity-grants":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id": "grant-9", "team_id": "runtime:aweb.test", "subject_alias": "principal",
				"subject_did_aw": "did:aw:principal", "grant_did_key": "did:key:zGrant", "scopes": []string{"mail.read"},
				"issued_at": "2026-08-12T00:00:00Z", "expires_at": "2026-08-12T01:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/identity-grants/grant-9/revoke":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected grant request %s %s", r.Method, r.URL.Path)
		}
	}))
	var shadowRequests atomic.Int32
	shadowServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowRequests.Add(1)
		http.Error(w, "shadow instance identity must not receive grant command traffic", http.StatusInternalServerError)
	}))

	principalRoot := filepath.Join(root, "principal")
	writeMessagingPrincipalForTest(t, principalRoot, server.URL, "principal", principalDID, principalKey)
	identityHome := filepath.Join(principalRoot, ".aw")
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	run := func(t *testing.T, source, dir string, args ...string) string {
		t.Helper()
		env := append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=", "AW_NO_UPDATE_CHECK=1")
		cmdArgs := append([]string(nil), args...)
		if source == "flag" {
			cmdArgs = append([]string{"--identity-home", identityHome}, cmdArgs...)
		} else {
			env = append(env, awconfig.IdentityHomeEnv+"="+identityHome)
		}
		cmd := exec.CommandContext(ctx, bin, cmdArgs...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("aw %s failed: %v\n%s", strings.Join(cmdArgs, " "), err, out)
		}
		return string(out)
	}

	for _, source := range []string{"flag", "environment"} {
		t.Run(source+"/empty-instance-list", func(t *testing.T) {
			instance := filepath.Join(root, "empty", source)
			if err := os.MkdirAll(instance, 0o700); err != nil {
				t.Fatal(err)
			}
			out := run(t, source, instance, "id", "grant", "list", "--json")
			if !strings.Contains(out, "grant-9") {
				t.Fatalf("list output missing grant: %s", out)
			}
			for _, command := range [][]string{
				{"id", "grant", "--team", "runtime:aweb.test", "list", "--json"},
				{"id", "grant", "list", "--team", "runtime:aweb.test", "--json"},
			} {
				out := run(t, source, instance, command...)
				if !strings.Contains(out, "grant-9") {
					t.Fatalf("team-selected grant list output missing grant for %v: %s", command, out)
				}
			}
			if _, err := os.Lstat(filepath.Join(instance, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("grant list touched empty instance identity state: %v", err)
			}
		})
		t.Run(source+"/shadow-instance-all-verbs", func(t *testing.T) {
			instance := filepath.Join(root, "shadow", source)
			writeMessagingPrincipalForTest(t, instance, shadowServer.URL, "shadow", shadowDID, shadowKey)
			outDir := filepath.Join(root, "minted", source)
			for _, command := range [][]string{
				{"id", "grant", "list", "--json"},
				{"id", "grant", "show", "grant-9", "--json"},
				{"id", "grant", "mint", "--scope", "mail.read", "--ttl", "1h", "--out", outDir, "--json"},
				{"id", "grant", "revoke", "grant-9", "--json"},
			} {
				run(t, source, instance, command...)
			}
			if !awconfig.IsGrantHome(outDir) {
				t.Fatalf("mint did not write grant home to explicit --out: %s", outDir)
			}
		})
	}

	if got := shadowRequests.Load(); got != 0 {
		t.Fatalf("shadow instance received %d grant command requests", got)
	}
	requestMu.Lock()
	requests := append([]messagingSignedRequest(nil), signedRequests...)
	requestMu.Unlock()
	verifyMessagingRequestsForTest(t, requests, principalPub, shadowPub, principalDID, shadowDID)
}

func TestGrantHomeConflictingTeamFailsExplicitlyInRealBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	grantHome := filepath.Join(root, "grant-home")
	writeGrantHomeForTest(t, grantHome, "https://app.aweb.ai")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "--identity-home", grantHome, "--team", "ops:acme.com", "mail", "inbox")
	cmd.Dir = instance
	cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=", "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "grant home is bound to team backend:acme.com; --team ops:acme.com conflicts") {
		t.Fatalf("grant-home conflicting --team error=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "https://app.aweb.ai") {
		t.Fatalf("conflicting --team should fail before using grant server URL:\n%s", out)
	}
}

func TestGrantCommandsWithGrantIdentityHomeRefuseRootAuthorityInRealBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	grantHome := filepath.Join(root, "grant-home")
	writeGrantHomeForTest(t, grantHome, "https://app.aweb.ai")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "--identity-home", grantHome, "id", "grant", "list")
	cmd.Dir = instance
	cmd.Env = append(testCommandEnv(filepath.Join(root, "user-home")), awconfig.IdentityHomeEnv+"=", "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "this is a grant home; run from the identity's own .aw home") {
		t.Fatalf("grant-home root authority command error=%v\n%s", err, out)
	}
	if strings.Contains(string(out), "not yet identity-home-aware") {
		t.Fatalf("grant-home command stopped at policy gate instead of root-authority refusal:\n%s", out)
	}
}
