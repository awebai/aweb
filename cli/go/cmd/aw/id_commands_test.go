package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
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
)

func TestAwIDCommandsHappyPath(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "myteam.aweb.ai/alice"
	logEntry := testDidLogEntry(t, stableID, priv, did, "create", nil, nil, 1, strings.Repeat("a", 64))

	var registerCalls atomic.Int32
	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/resolve/myteam.aweb.ai/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":        did,
				"stable_id":  stableID,
				"address":    address,
				"handle":     "alice",
				"server":     serverURL,
				"custody":    "self",
				"lifetime":   "persistent",
				"public_key": base64.RawStdEncoding.EncodeToString(pub),
			})
		case "/v1/did":
			registerCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"server":          serverURL,
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"log_head":        didLogJSON(logEntry),
			})
		case "/v1/did/" + stableID + "/log":
			_ = json.NewEncoder(w).Encode([]map[string]any{didLogJSON(logEntry)})
		case "/v1/namespaces/myteam.aweb.ai":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "myteam.aweb.ai",
				"controller_did":      "did:key:z6MkController",
				"verification_status": "verified",
				"last_verified_at":    "2026-04-04T00:00:00Z",
				"created_at":          "2026-04-04T00:00:00Z",
			})
		case "/v1/namespaces/myteam.aweb.ai/addresses":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"addresses": []map[string]any{{
					"address_id":      "addr-1",
					"domain":          "myteam.aweb.ai",
					"name":            "alice",
					"did_aw":          stableID,
					"current_did_key": did,
					"reachability":    "public",
					"created_at":      "2026-04-04T00:00:00Z",
				}},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	writeSelfCustodyConfig(t, cfgPath, server.URL, address, "myteam.aweb.ai", "alice", did, stableID, priv)

	runJSON := func(args ...string) map[string]any {
		t.Helper()
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = append(os.Environ(),
			"AW_CONFIG_PATH="+cfgPath,
			"AWID_REGISTRY_URL=local",
		)
		run.Dir = tmp
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		var got map[string]any
		if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
			t.Fatalf("invalid json for %s: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		return got
	}

	if got := runJSON("id", "register", "--json"); got["status"] != "registered" {
		t.Fatalf("register status=%v", got["status"])
	}
	if registerCalls.Load() != 1 {
		t.Fatalf("register calls=%d", registerCalls.Load())
	}
	if got := runJSON("id", "show", "--json"); got["registry_status"] != "registered" {
		t.Fatalf("show registry_status=%v", got["registry_status"])
	}
	if got := runJSON("id", "resolve", stableID, "--json"); got["current_did_key"] != did {
		t.Fatalf("resolve current_did_key=%v", got["current_did_key"])
	}
	if got := runJSON("id", "verify", stableID, "--json"); got["status"] != "OK" {
		t.Fatalf("verify status=%v", got["status"])
	}
	if got := runJSON("id", "namespace", "myteam.aweb.ai", "--json"); got["registry_url"] == "" {
		t.Fatalf("namespace registry_url missing: %+v", got)
	}
}

func TestAwIDCreateWritesStandaloneIdentityAndRegisters(t *testing.T) {
	t.Parallel()

	var createdDIDAW string
	var createdDIDKey string
	var namespaceCreated atomic.Bool
	var addressCreated atomic.Bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com":
			switch r.Method {
			case http.MethodGet:
				if !namespaceCreated.Load() {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"namespace_id":        "ns-1",
					"domain":              "acme.com",
					"controller_did":      createdDIDKey,
					"verification_status": "verified",
					"last_verified_at":    "2026-04-04T00:00:00Z",
					"created_at":          "2026-04-04T00:00:00Z",
				})
			default:
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
		case "/v1/namespaces":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["domain"] != "acme.com" {
				t.Fatalf("namespace domain=%v", payload["domain"])
			}
			controllerDID, _ := payload["controller_did"].(string)
			createdDIDKey = controllerDID
			verifyCanonicalRegistryAuth(t, r, map[string]string{
				"domain":    "acme.com",
				"operation": "register",
			})
			namespaceCreated.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      createdDIDKey,
				"verification_status": "verified",
				"last_verified_at":    "2026-04-04T00:00:00Z",
				"created_at":          "2026-04-04T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/addresses/alice":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			if !addressCreated.Load() {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          createdDIDAW,
				"current_did_key": createdDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/addresses":
			if r.Method != http.MethodPost {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			createdDIDAW, _ = payload["did_aw"].(string)
			if payload["name"] != "alice" {
				t.Fatalf("address name=%v", payload["name"])
			}
			if payload["current_did_key"] != createdDIDKey {
				t.Fatalf("current_did_key=%v want %v", payload["current_did_key"], createdDIDKey)
			}
			if payload["reachability"] != "public" {
				t.Fatalf("reachability=%v", payload["reachability"])
			}
			verifyCanonicalRegistryAuth(t, r, map[string]string{
				"domain":    "acme.com",
				"name":      "alice",
				"operation": "register_address",
			})
			addressCreated.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          createdDIDAW,
				"current_did_key": createdDIDKey,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			createdDIDAW, _ = payload["did_aw"].(string)
			createdDIDKey, _ = payload["did_key"].(string)
			if payload["server"] != "" {
				t.Fatalf("server=%v want empty string", payload["server"])
			}
			if payload["address"] != "acme.com/alice" {
				t.Fatalf("address=%v want acme.com/alice", payload["address"])
			}
			if payload["handle"] != "alice" {
				t.Fatalf("handle=%v want alice", payload["handle"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + createdDIDAW + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          createdDIDAW,
				"current_did_key": createdDIDKey,
				"server":          "",
				"address":         "acme.com/alice",
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "id", "create", "--name", "Alice", "--domain", "Acme.com", "--registry", server.URL, "--skip-dns-verify", "--json")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id create failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Create this DNS TXT record before continuing:") {
		t.Fatalf("expected DNS instructions in output:\n%s", string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "created" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["registry_status"] != "registered" {
		t.Fatalf("registry_status=%v", got["registry_status"])
	}
	if got["address"] != "acme.com/alice" {
		t.Fatalf("address=%v", got["address"])
	}
	if got["registry_url"] != server.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], server.URL)
	}

	identityPath := filepath.Join(tmp, ".aw", "identity.yaml")
	signingKeyPath := filepath.Join(tmp, ".aw", "signing.key")
	if _, err := os.Stat(identityPath); err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if _, err := os.Stat(signingKeyPath); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); !os.IsNotExist(err) {
		t.Fatalf("workspace.yaml should not exist, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.pub")); !os.IsNotExist(err) {
		t.Fatalf("signing.pub should not exist, err=%v", err)
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.DID != got["did_key"] {
		t.Fatalf("identity did=%q want %q", identity.DID, got["did_key"])
	}
	if identity.StableID != got["did_aw"] {
		t.Fatalf("identity stable_id=%q want %q", identity.StableID, got["did_aw"])
	}
	if identity.Address != "acme.com/alice" {
		t.Fatalf("identity address=%q", identity.Address)
	}
	if identity.Custody != awid.CustodySelf {
		t.Fatalf("identity custody=%q", identity.Custody)
	}
	if identity.Lifetime != awid.LifetimePersistent {
		t.Fatalf("identity lifetime=%q", identity.Lifetime)
	}
	if identity.RegistryURL != server.URL {
		t.Fatalf("identity registry_url=%q want %q", identity.RegistryURL, server.URL)
	}
	if identity.RegistryStatus != "registered" {
		t.Fatalf("identity registry_status=%q", identity.RegistryStatus)
	}

	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != identity.DID {
		t.Fatalf("stored signing key did=%q want %q", did, identity.DID)
	}
}

func TestAwIDCreateFailsIfIdentityExists(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       "did:key:z6MkkExisting",
		StableID:  "did:aw:existing",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "create", "--name", "Alice", "--domain", "acme.com")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected id create to fail when identity exists:\n%s", string(out))
	}
	if !strings.Contains(string(out), "standalone identity already exists") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwIDCreateWarnsAndContinuesWhenRegistryUnavailable(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("response writer does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}))
	registryURL := server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "id", "create", "--name", "Alice", "--domain", "acme.com", "--registry", registryURL, "--skip-dns-verify", "--json")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id create failed unexpectedly: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Warning: could not finish identity registration at") {
		t.Fatalf("expected warning in output:\n%s", string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["registry_status"] != "pending" {
		t.Fatalf("registry_status=%v", got["registry_status"])
	}
	if got["registry_error"] == "" {
		t.Fatalf("expected registry_error in output: %+v", got)
	}
	if got["address"] != "acme.com/alice" {
		t.Fatalf("address=%v", got["address"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if identity.RegistryStatus != "pending" {
		t.Fatalf("identity registry_status=%q", identity.RegistryStatus)
	}
	if identity.Address != "acme.com/alice" {
		t.Fatalf("identity address=%q", identity.Address)
	}
}

func TestVerifyIDCreateDomainAuthorityMatchesControllerAndRegistry(t *testing.T) {
	t.Parallel()

	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	err := verifyIDCreateDomainAuthority(
		context.Background(),
		staticTXTResolver{
			"_awid.acme.com": {idCreateDNSRecordValue(did, "https://registry.example.com")},
		},
		"acme.com",
		did,
		"https://registry.example.com",
	)
	if err != nil {
		t.Fatalf("verifyIDCreateDomainAuthority: %v", err)
	}
}

func TestVerifyIDCreateDomainAuthorityFailsWrongController(t *testing.T) {
	t.Parallel()

	wrongPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongDID := awid.ComputeDIDKey(wrongPub)

	err = verifyIDCreateDomainAuthority(
		context.Background(),
		staticTXTResolver{
			"_awid.acme.com": {idCreateDNSRecordValue(wrongDID, "https://registry.example.com")},
		},
		"acme.com",
		"did:key:z6MkExpectedController",
		"https://registry.example.com",
	)
	if err == nil {
		t.Fatal("expected controller mismatch")
	}
	if !strings.Contains(err.Error(), "TXT controller "+wrongDID+" does not match did:key:z6MkExpectedController") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyIDCreateDomainAuthorityFailsWrongRegistry(t *testing.T) {
	t.Parallel()

	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	err := verifyIDCreateDomainAuthority(
		context.Background(),
		staticTXTResolver{
			"_awid.acme.com": {idCreateDNSRecordValue(did, "https://other-registry.example.com")},
		},
		"acme.com",
		did,
		"https://registry.example.com",
	)
	if err == nil {
		t.Fatal("expected registry mismatch")
	}
	if !strings.Contains(err.Error(), "TXT registry https://other-registry.example.com does not match https://registry.example.com") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyIDCreateDomainAuthorityFailsWhenTXTRecordMissing(t *testing.T) {
	t.Parallel()

	err := verifyIDCreateDomainAuthority(
		context.Background(),
		staticTXTResolver{},
		"acme.com",
		"did:key:z6MkExpectedController",
		"https://registry.example.com",
	)
	if err == nil {
		t.Fatal("expected missing TXT record error")
	}
	if !strings.Contains(err.Error(), "lookup _awid.acme.com") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAwIDRotateKeyRotatesRegistryAndUpdatesLocalConfig(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	address := "myteam.aweb.ai/alice"

	currentRegistryDID := oldDID
	createEntry := testDidLogEntry(t, stableID, oldPriv, oldDID, "create", nil, nil, 1, strings.Repeat("a", 64))
	currentHead := createEntry
	var registryRotateCalls atomic.Int32
	var serverURL string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/resolve/myteam.aweb.ai/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":        currentRegistryDID,
				"stable_id":  stableID,
				"address":    address,
				"handle":     "alice",
				"server":     serverURL,
				"custody":    "self",
				"lifetime":   "persistent",
				"public_key": base64.RawStdEncoding.EncodeToString(extractPublicKeyForTest(t, currentRegistryDID)),
			})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentRegistryDID,
				"server":          serverURL,
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentRegistryDID,
				"log_head":        didLogJSON(currentHead),
			})
		case "/v1/did/" + stableID:
			registryRotateCalls.Add(1)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			currentRegistryDID = payload["new_did_key"].(string)
			currentHead = testDidLogEntry(t, stableID, oldPriv, currentRegistryDID, "rotate_key", &oldDID, &createEntry.EntryHash, 2, strings.Repeat("b", 64))
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	writeSelfCustodyConfig(t, cfgPath, server.URL, address, "myteam.aweb.ai", "alice", oldDID, stableID, oldPriv)

	runJSON := func(args ...string) map[string]any {
		t.Helper()
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = append(os.Environ(),
			"AW_CONFIG_PATH="+cfgPath,
			"AWID_REGISTRY_URL=local",
		)
		run.Dir = tmp
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		var got map[string]any
		if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
			t.Fatalf("invalid json for %s: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		return got
	}

	first := runJSON("id", "rotate-key", "--json")
	if first["status"] != "rotated" {
		t.Fatalf("first status=%v", first["status"])
	}
	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil || pending != nil {
		t.Fatalf("pending rotation not cleaned up: %v %#v", err, pending)
	}
	identity := loadIdentityForTest(t, tmp)
	if identity.DID != currentRegistryDID {
		t.Fatalf("identity DID=%s want %s", identity.DID, currentRegistryDID)
	}
	if registryRotateCalls.Load() != 1 {
		t.Fatalf("registry rotate calls=%d", registryRotateCalls.Load())
	}
	rotatedKeyPath := filepath.Join(rotationDir, "rotated", strings.ReplaceAll(oldDID, ":", "-")+".key")
	if _, err := os.Stat(rotatedKeyPath); err != nil {
		t.Fatalf("rotated key missing: %v", err)
	}
}

func TestAwIDRotateKeyPreservesPendingStateOnRegistryNetworkError(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	address := "myteam.aweb.ai/alice"
	createEntry := testDidLogEntry(t, stableID, oldPriv, oldDID, "create", nil, nil, 1, strings.Repeat("a", 64))

	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/resolve/myteam.aweb.ai/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":        oldDID,
				"stable_id":  stableID,
				"address":    address,
				"handle":     "alice",
				"server":     serverURL,
				"custody":    "self",
				"lifetime":   "persistent",
				"public_key": base64.RawStdEncoding.EncodeToString(oldPub),
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": oldDID,
				"log_head":        didLogJSON(createEntry),
			})
		case "/v1/did/" + stableID + "/full":
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("response writer does not support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	writeSelfCustodyConfig(t, cfgPath, server.URL, address, "myteam.aweb.ai", "alice", oldDID, stableID, oldPriv)

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected rotate-key to fail on registry network error:\n%s", string(out))
	}
	if !strings.Contains(string(out), "EOF") && !strings.Contains(string(out), "connection reset") && !strings.Contains(string(out), "broken pipe") {
		t.Fatalf("expected network error output, got:\n%s", string(out))
	}

	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	pending, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("pending rotation state missing after registry failure")
	}
	if pending.OldDID != oldDID {
		t.Fatalf("pending old_did=%s want %s", pending.OldDID, oldDID)
	}
	if pending.NewDID == "" {
		t.Fatal("pending new_did missing after registry failure")
	}
	if pending.PendingKey == "" {
		t.Fatal("pending key path missing after registry failure")
	}
	if _, err := os.Stat(pending.PendingKey); err != nil {
		t.Fatalf("pending signing key missing: %v", err)
	}
	if _, err := os.Stat(awid.PublicKeyPath(pending.PendingKey)); err != nil {
		t.Fatalf("pending public key missing: %v", err)
	}

	identity := loadIdentityForTest(t, tmp)
	if identity.DID != oldDID {
		t.Fatalf("identity DID changed on registry failure: %s", identity.DID)
	}
}

func TestAwIDRotateKeyRecoversLocalPromotionAfterRegistryRotate(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	address := "myteam.aweb.ai/alice"
	createEntry := testDidLogEntry(t, stableID, oldPriv, oldDID, "create", nil, nil, 1, strings.Repeat("a", 64))

	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newDID := awid.ComputeDIDKey(newPub)
	rotateEntry := testDidLogEntry(t, stableID, oldPriv, newDID, "rotate_key", &oldDID, &createEntry.EntryHash, 2, strings.Repeat("b", 64))
	currentRegistryDID := newDID
	var registryRotateCalls atomic.Int32
	var serverURL string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/resolve/myteam.aweb.ai/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":        currentRegistryDID,
				"stable_id":  stableID,
				"address":    address,
				"handle":     "alice",
				"server":     serverURL,
				"custody":    "self",
				"lifetime":   "persistent",
				"public_key": base64.RawStdEncoding.EncodeToString(extractPublicKeyForTest(t, currentRegistryDID)),
			})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentRegistryDID,
				"server":          serverURL,
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentRegistryDID,
				"log_head":        didLogJSON(rotateEntry),
			})
		case "/v1/did/" + stableID:
			registryRotateCalls.Add(1)
			t.Fatalf("unexpected registry re-rotation")
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)
	writeSelfCustodyConfig(t, cfgPath, server.URL, address, "myteam.aweb.ai", "alice", oldDID, stableID, oldPriv)

	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	pendingKeyPath, err := savePendingRotationKeypair(rotationDir, newDID, newPub, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePendingRotationState(rotationDir, &pendingRotationState{
		StableID:   stableID,
		OldDID:     oldDID,
		NewDID:     newDID,
		PendingKey: pendingKeyPath,
	}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWID_REGISTRY_URL=local",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("rotate-key failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "rotated" {
		t.Fatalf("status=%v", got["status"])
	}
	if registryRotateCalls.Load() != 0 {
		t.Fatalf("registry rotate calls=%d", registryRotateCalls.Load())
	}
	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil || pending != nil {
		t.Fatalf("pending rotation not cleaned up: %v %#v", err, pending)
	}
	identity := loadIdentityForTest(t, tmp)
	if identity.DID != newDID {
		t.Fatalf("identity DID=%s want %s", identity.DID, newDID)
	}
	activeKeyPath := awconfig.WorktreeSigningKeyPath(tmp)
	gotPriv, err := awid.LoadSigningKey(activeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotDID := awid.ComputeDIDKey(gotPriv.Public().(ed25519.PublicKey)); gotDID != newDID {
		t.Fatalf("active did:key=%s want %s", gotDID, newDID)
	}
}

func TestPromotePendingRotationKeypairRecoversInterruptedPromotion(t *testing.T) {
	t.Parallel()

	rotationDir := t.TempDir()
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newDID := awid.ComputeDIDKey(newPub)
	pendingKeyPath, err := savePendingRotationKeypair(rotationDir, newDID, newPub, newPriv)
	if err != nil {
		t.Fatal(err)
	}

	activeKeyPath := filepath.Join(rotationDir, "active.signing.key")
	if err := os.Rename(pendingKeyPath, activeKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(awid.PublicKeyPath(activeKeyPath)); !os.IsNotExist(err) {
		t.Fatalf("expected missing active public key before recovery, got %v", err)
	}

	gotKeyPath, err := promotePendingRotationKeypair(activeKeyPath, pendingKeyPath, newDID)
	if err != nil {
		t.Fatal(err)
	}
	if gotKeyPath != activeKeyPath {
		t.Fatalf("active key path=%q want %q", gotKeyPath, activeKeyPath)
	}

	gotPriv, err := awid.LoadSigningKey(activeKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotDID := awid.ComputeDIDKey(gotPriv.Public().(ed25519.PublicKey)); gotDID != newDID {
		t.Fatalf("active did:key=%s want %s", gotDID, newDID)
	}
	gotPub, err := awid.LoadPublicKey(awid.PublicKeyPath(activeKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPub) != string(newPub) {
		t.Fatalf("active public key did not recover from private key")
	}
}

func TestAwIDRotateKeySelfCustodyUsesWorktreeSigningKey(t *testing.T) {
	t.Parallel()

	var newDID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/me/rotate":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			didValue, _ := req["new_did"].(string)
			if strings.TrimSpace(didValue) == "" {
				t.Fatal("new_did missing")
			}
			newDID = didValue
			_ = json.NewEncoder(w).Encode(map[string]any{
				"old_did": "did:key:z6MkOldCustodial",
				"new_did": didValue,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	cfg := strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: myteam.aweb.ai
    custody: custodial
    lifetime: persistent
default_account: acct
`) + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(awDir, "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		ProjectSlug:    "myteam",
		NamespaceSlug:  "myteam.aweb.ai",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		Custody:        "custodial",
		Lifetime:       "persistent",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(awDir, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       "did:key:z6MkOldCustodial",
		StableID:  "did:aw:test-custodial",
		Custody:   "custodial",
		Lifetime:  "persistent",
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--self-custody", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("rotate-key --self-custody failed: %v\n%s", err, string(out))
	}
	if strings.TrimSpace(newDID) == "" {
		t.Fatal("server did not receive new did:key")
	}

	signingKeyPath := filepath.Join(tmp, ".aw", "signing.key")
	if resolvedSigningKeyPath, err := filepath.EvalSymlinks(signingKeyPath); err == nil {
		signingKeyPath = resolvedSigningKeyPath
	}
	if _, err := os.Stat(signingKeyPath); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "keys")); !os.IsNotExist(err) {
		t.Fatalf("unexpected global keys dir, err=%v", err)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(awDir, "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if workspace.SigningKey != "" {
		t.Fatalf("workspace signing_key=%q want empty", workspace.SigningKey)
	}
	if workspace.DID != "" {
		t.Fatalf("workspace did=%q want empty", workspace.DID)
	}
	if workspace.Custody != "" {
		t.Fatalf("workspace custody=%q want empty", workspace.Custody)
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(awDir, "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != newDID {
		t.Fatalf("identity did=%q want %q", identity.DID, newDID)
	}
	if identity.Custody != awid.CustodySelf {
		t.Fatalf("identity custody=%q want %q", identity.Custody, awid.CustodySelf)
	}
}

func TestUpdateAccountIdentityDoesNotRewriteWorkspaceWhenIdentityExists(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	writeSelfCustodyConfig(t, cfgPath, "https://app.aweb.ai", "acme.com/alice", "acme.com", "alice", did, stableID, priv)

	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	workspacePath := filepath.Join(awDir, "workspace.yaml")
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, &awconfig.WorktreeWorkspace{
		ServerURL:      "https://app.aweb.ai",
		APIKey:         "aw_sk_test",
		IdentityHandle: "alice",
		NamespaceSlug:  "acme.com",
		WorkspaceID:    "ws-1",
		ProjectSlug:    "acme",
	}); err != nil {
		t.Fatal(err)
	}
	identityPath := filepath.Join(awDir, "identity.yaml")
	if err := awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	beforeData, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(workspacePath)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("AW_CONFIG_PATH", cfgPath)
	t.Setenv("AWEB_URL", "")
	t.Setenv("AWEB_API_KEY", "")
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = os.Chdir(originalWD)
	}()

	time.Sleep(20 * time.Millisecond)
	if err := updateAccountIdentity("did:key:z6MkUpdated", awid.CustodySelf, awconfig.WorktreeSigningKeyPath(tmp)); err != nil {
		t.Fatalf("updateAccountIdentity: %v", err)
	}

	afterData, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterData) != string(beforeData) {
		t.Fatalf("workspace.yaml changed unexpectedly:\nbefore:\n%s\nafter:\n%s", string(beforeData), string(afterData))
	}
	if !os.SameFile(beforeInfo, afterInfo) {
		t.Fatal("workspace.yaml was rewritten even though identity.yaml exists")
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != "did:key:z6MkUpdated" {
		t.Fatalf("identity did=%q want %q", identity.DID, "did:key:z6MkUpdated")
	}
	if identity.Custody != awid.CustodySelf {
		t.Fatalf("identity custody=%q want %q", identity.Custody, awid.CustodySelf)
	}
}

func writeSelfCustodyConfig(t *testing.T, cfgPath, serverURL, address, namespaceSlug, handle, did, stableID string, signingKey ed25519.PrivateKey) {
	t.Helper()
	pub := signingKey.Public().(ed25519.PublicKey)
	workingDir := filepath.Dir(cfgPath)
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveKeypairAt(signingKeyPath, awid.PublicKeyPath(signingKeyPath), pub, signingKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(workingDir, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:      serverURL,
		APIKey:         "aw_sk_test",
		ProjectSlug:    "myteam",
		NamespaceSlug:  namespaceSlug,
		IdentityID:     "agent-1",
		IdentityHandle: handle,
		DID:            did,
		StableID:       stableID,
		SigningKey:     signingKeyPath,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
	}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Address:   address,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

func loadIdentityForTest(t *testing.T, workingDir string) *awconfig.WorktreeIdentity {
	t.Helper()
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(workingDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testDidLogEntry(t *testing.T, didAW string, signingKey ed25519.PrivateKey, newDID, operation string, previousDID, prevHash *string, seq int, stateHash string) awid.DidKeyEvidence {
	t.Helper()
	entry := awid.DidKeyEvidence{
		Seq:            seq,
		Operation:      operation,
		PreviousDIDKey: previousDID,
		NewDIDKey:      newDID,
		PrevEntryHash:  prevHash,
		StateHash:      stateHash,
		AuthorizedBy:   awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)),
		Timestamp:      "2026-04-04T00:00:00Z",
	}
	payload := awid.CanonicalDidLogPayload(didAW, &entry)
	sum := sha256.Sum256([]byte(payload))
	entry.EntryHash = hex.EncodeToString(sum[:])
	entry.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(payload)))
	return entry
}

func didLogJSON(entry awid.DidKeyEvidence) map[string]any {
	return map[string]any{
		"seq":              entry.Seq,
		"operation":        entry.Operation,
		"previous_did_key": entry.PreviousDIDKey,
		"new_did_key":      entry.NewDIDKey,
		"prev_entry_hash":  entry.PrevEntryHash,
		"entry_hash":       entry.EntryHash,
		"state_hash":       entry.StateHash,
		"authorized_by":    entry.AuthorizedBy,
		"signature":        entry.Signature,
		"timestamp":        entry.Timestamp,
	}
}

func extractPublicKeyForTest(t *testing.T, did string) ed25519.PublicKey {
	t.Helper()
	pub, err := awid.ExtractPublicKey(did)
	if err != nil {
		t.Fatalf("extract public key for %s: %v", did, err)
	}
	return pub
}

func verifyCanonicalRegistryAuth(t *testing.T, r *http.Request, fields map[string]string) {
	t.Helper()
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
	if auth == "" {
		t.Fatal("missing Authorization header")
	}
	if timestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp header")
	}
	parts := strings.Split(auth, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("unexpected Authorization header %q", auth)
	}
	fields = cloneStringMap(fields)
	fields["timestamp"] = timestamp
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(extractPublicKeyForTest(t, parts[1]), payload, sig) {
		t.Fatalf("invalid signature for payload %s", string(payload))
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

type staticTXTResolver map[string][]string

func (r staticTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := r[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: name}
}

func TestStaticTXTResolverNotFoundErrorShape(t *testing.T) {
	t.Parallel()

	_, err := staticTXTResolver{}.LookupTXT(context.Background(), "_awid.example.com")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
		t.Fatalf("expected not-found DNSError, got %v", err)
	}
}
