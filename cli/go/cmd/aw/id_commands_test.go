package main

import (
	"bufio"
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
	"gopkg.in/yaml.v3"
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
	buildAwBinary(t, ctx, bin)
	writeSelfCustodyConfig(t, tmp, server.URL, address, "myteam.aweb.ai", "alice", did, stableID, priv)

	runJSON := func(args ...string) map[string]any {
		t.Helper()
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = testCommandEnv(tmp)
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
	var controllerDID string
	var namespaceAuthDID string
	var addressAuthDID string
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
					"controller_did":      controllerDID,
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
			namespaceAuthDID = didFromRegistryAuthHeader(t, r)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["domain"] != "acme.com" {
				t.Fatalf("namespace domain=%v", payload["domain"])
			}
			controllerDID, _ = payload["controller_did"].(string)
			verifyCanonicalRegistryAuth(t, r, map[string]string{
				"domain":    "acme.com",
				"operation": "register",
			})
			namespaceCreated.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
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
			addressAuthDID = didFromRegistryAuthHeader(t, r)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			createdDIDAW, _ = payload["did_aw"].(string)
			createdDIDKey, _ = payload["current_did_key"].(string)
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
			if payload["did_key"] != createdDIDKey {
				t.Fatalf("did_key=%v want %v", payload["did_key"], createdDIDKey)
			}
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
	run.Env = idCreateCommandEnv(tmp)
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
	if namespaceAuthDID == "" || addressAuthDID == "" {
		t.Fatalf("missing controller auth DID: namespace=%q address=%q", namespaceAuthDID, addressAuthDID)
	}
	if namespaceAuthDID != addressAuthDID {
		t.Fatalf("namespace auth DID=%q address auth DID=%q", namespaceAuthDID, addressAuthDID)
	}
	if namespaceAuthDID == createdDIDKey {
		t.Fatalf("controller DID should differ from identity DID %q", createdDIDKey)
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
	controllerKeyPath := filepath.Join(tmp, ".config", "aw", "controllers", "acme.com.key")
	if _, err := os.Stat(controllerKeyPath); err != nil {
		t.Fatalf("controller key missing: %v", err)
	}
	metaData, err := os.ReadFile(filepath.Join(tmp, ".config", "aw", "controllers", "acme.com.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var meta awconfig.ControllerMeta
	if err := yaml.Unmarshal(metaData, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.ControllerDID != namespaceAuthDID {
		t.Fatalf("controller_did=%q want %q", meta.ControllerDID, namespaceAuthDID)
	}
}

func idCreateCommandEnv(home string) []string {
	return append(os.Environ(), "HOME="+home, "AW_CONFIG_PATH=")
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
	run.Env = idCreateCommandEnv(tmp)
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
	run.Env = idCreateCommandEnv(tmp)
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

func TestAwIDCreateAllowsMultipleIdentitiesOnSameDomain(t *testing.T) {
	t.Parallel()

	type didMapping struct {
		didKey  string
		address string
		handle  string
	}

	var namespaceControllerDID string
	namespacePosts := 0
	addressPosts := 0
	didMappings := map[string]didMapping{}

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/namespaces/acme.com" && r.Method == http.MethodGet:
			if namespaceControllerDID == "" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      namespaceControllerDID,
				"verification_status": "verified",
				"last_verified_at":    "2026-04-05T00:00:00Z",
				"created_at":          "2026-04-05T00:00:00Z",
			})
		case r.URL.Path == "/v1/namespaces" && r.Method == http.MethodPost:
			namespacePosts++
			namespaceControllerDID = didFromRegistryAuthHeader(t, r)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["controller_did"] != namespaceControllerDID {
				t.Fatalf("controller_did=%v want %s", payload["controller_did"], namespaceControllerDID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      namespaceControllerDID,
				"verification_status": "verified",
				"last_verified_at":    "2026-04-05T00:00:00Z",
				"created_at":          "2026-04-05T00:00:00Z",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/namespaces/acme.com/addresses/") && r.Method == http.MethodGet:
			name := strings.TrimPrefix(r.URL.Path, "/v1/namespaces/acme.com/addresses/")
			for stableID, mapping := range didMappings {
				if mapping.handle != name {
					continue
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"address_id":      "addr-" + name,
					"domain":          "acme.com",
					"name":            name,
					"did_aw":          stableID,
					"current_did_key": mapping.didKey,
					"reachability":    "public",
					"created_at":      "2026-04-05T00:00:00Z",
				})
				return
			}
			http.NotFound(w, r)
		case r.URL.Path == "/v1/namespaces/acme.com/addresses" && r.Method == http.MethodPost:
			addressPosts++
			authDID := didFromRegistryAuthHeader(t, r)
			if authDID != namespaceControllerDID {
				t.Fatalf("address auth DID=%s want namespace controller %s", authDID, namespaceControllerDID)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			stableID, _ := payload["did_aw"].(string)
			didKey, _ := payload["current_did_key"].(string)
			name, _ := payload["name"].(string)
			didMappings[stableID] = didMapping{didKey: didKey, address: "acme.com/" + name, handle: name}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-" + name,
				"domain":          "acme.com",
				"name":            name,
				"did_aw":          stableID,
				"current_did_key": didKey,
				"reachability":    "public",
				"created_at":      "2026-04-05T00:00:00Z",
			})
		case r.URL.Path == "/v1/did" && r.Method == http.MethodPost:
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			stableID, _ := payload["did_aw"].(string)
			didKey, _ := payload["did_key"].(string)
			address, _ := payload["address"].(string)
			handle, _ := payload["handle"].(string)
			didMappings[stableID] = didMapping{didKey: didKey, address: address, handle: handle}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full") && r.Method == http.MethodGet:
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			mapping, ok := didMappings[stableID]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": mapping.didKey,
				"server":          "",
				"address":         mapping.address,
				"handle":          mapping.handle,
				"created_at":      "2026-04-05T00:00:00Z",
				"updated_at":      "2026-04-05T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root := t.TempDir()
	home := filepath.Join(root, "home")
	aliceDir := filepath.Join(root, "alice")
	bobDir := filepath.Join(root, "bob")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(aliceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(bobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	runCreate := func(dir, name string) string {
		t.Helper()
		run := exec.CommandContext(ctx, bin, "id", "create", "--name", name, "--domain", "acme.com", "--registry", server.URL, "--skip-dns-verify", "--json")
		run.Env = idCreateCommandEnv(home)
		run.Dir = dir
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("%s create failed: %v\n%s", name, err, string(out))
		}
		return string(out)
	}

	firstOut := runCreate(aliceDir, "alice")
	secondOut := runCreate(bobDir, "bob")

	if !strings.Contains(firstOut, "Create this DNS TXT record before continuing:") {
		t.Fatalf("expected DNS instructions on first create:\n%s", firstOut)
	}
	if strings.Contains(secondOut, "Create this DNS TXT record before continuing:") {
		t.Fatalf("did not expect DNS instructions on second create:\n%s", secondOut)
	}
	if namespacePosts != 1 {
		t.Fatalf("namespace posts=%d want 1", namespacePosts)
	}
	if addressPosts != 2 {
		t.Fatalf("address posts=%d want 2", addressPosts)
	}
	if namespaceControllerDID == "" {
		t.Fatal("namespace controller DID missing")
	}
	aliceIdentity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(aliceDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	bobIdentity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(bobDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if aliceIdentity.Address != "acme.com/alice" {
		t.Fatalf("alice address=%q", aliceIdentity.Address)
	}
	if bobIdentity.Address != "acme.com/bob" {
		t.Fatalf("bob address=%q", bobIdentity.Address)
	}
	if aliceIdentity.DID == bobIdentity.DID {
		t.Fatal("identities should have distinct signing keys")
	}
	controllerMetaData, err := os.ReadFile(filepath.Join(home, ".config", "aw", "controllers", "acme.com.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var controllerMeta awconfig.ControllerMeta
	if err := yaml.Unmarshal(controllerMetaData, &controllerMeta); err != nil {
		t.Fatal(err)
	}
	if controllerMeta.ControllerDID != namespaceControllerDID {
		t.Fatalf("controller meta did=%q want %q", controllerMeta.ControllerDID, namespaceControllerDID)
	}
}

func TestAwIDRotateKeyRotatesStandaloneIdentityAndUpdatesLocalState(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	address := "acme.com/alice"
	registryURL := ""
	logHead := testDidLogEntry(t, stableID, oldPriv, oldDID, "create", nil, nil, 1, strings.Repeat("b", 64))

	var rotated atomic.Bool
	var seenPut atomic.Bool
	var newDID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/key":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": oldDID,
				"log_head":        didLogJSON(logHead),
			})
		case "/v1/did/" + stableID + "/full":
			if r.Method != http.MethodGet {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			authDID := didFromRegistryAuthHeader(t, r)
			currentDID := oldDID
			if rotated.Load() {
				currentDID = newDID
				if authDID != newDID {
					t.Fatalf("post-rotation auth did=%q want %q", authDID, newDID)
				}
			} else if authDID != oldDID {
				t.Fatalf("pre-rotation auth did=%q want %q", authDID, oldDID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentDID,
				"server":          "",
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-05T00:00:00Z",
				"updated_at":      "2026-04-05T00:00:00Z",
			})
		case "/v1/did/" + stableID:
			if r.Method != http.MethodPut {
				t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["operation"] != "rotate_key" {
				t.Fatalf("operation=%v", payload["operation"])
			}
			if payload["authorized_by"] != oldDID {
				t.Fatalf("authorized_by=%v", payload["authorized_by"])
			}
			if int(payload["seq"].(float64)) != 2 {
				t.Fatalf("seq=%v", payload["seq"])
			}
			if payload["prev_entry_hash"] != logHead.EntryHash {
				t.Fatalf("prev_entry_hash=%v want %s", payload["prev_entry_hash"], logHead.EntryHash)
			}
			newDID, _ = payload["new_did_key"].(string)
			if strings.TrimSpace(newDID) == "" || newDID == oldDID {
				t.Fatalf("new_did_key=%q", newDID)
			}
			entry := &awid.DidKeyEvidence{
				Seq:            2,
				Operation:      "rotate_key",
				PreviousDIDKey: stringPtr(oldDID),
				NewDIDKey:      newDID,
				PrevEntryHash:  stringPtr(logHead.EntryHash),
				StateHash:      payload["state_hash"].(string),
				AuthorizedBy:   oldDID,
				Timestamp:      payload["timestamp"].(string),
			}
			sig, err := base64.RawStdEncoding.DecodeString(payload["signature"].(string))
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if !ed25519.Verify(oldPub, []byte(awid.CanonicalDidLogPayload(stableID, entry)), sig) {
				t.Fatal("invalid rotation signature")
			}
			rotated.Store(true)
			seenPut.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]any{"updated": true})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	registryURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, address, oldDID, stableID, registryURL, oldPriv)

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id rotate-key failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "rotated" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["old_did"] != oldDID {
		t.Fatalf("old_did=%v want %s", got["old_did"], oldDID)
	}
	if got["new_did"] != newDID {
		t.Fatalf("new_did=%v want %s", got["new_did"], newDID)
	}
	if !seenPut.Load() {
		t.Fatal("rotation PUT was not sent")
	}

	identity := loadIdentityForTest(t, tmp)
	if identity.DID != newDID {
		t.Fatalf("identity did=%q want %q", identity.DID, newDID)
	}
	if identity.RegistryStatus != "registered" {
		t.Fatalf("identity registry_status=%q", identity.RegistryStatus)
	}
	activeKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(activeKey.Public().(ed25519.PublicKey)); got != newDID {
		t.Fatalf("active signing key did=%q want %q", got, newDID)
	}
	archivedKey := filepath.Join(tmp, ".aw", "rotated", pendingFileBase(oldDID)+".key")
	if _, err := os.Stat(archivedKey); err != nil {
		t.Fatalf("archived key missing: %v", err)
	}
	if pending, err := loadPendingRotationState(filepath.Join(tmp, ".aw", "rotation"), stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Fatalf("pending rotation state still present: %+v", pending)
	}
}

func TestAwIDRotateKeyRefusesWhenPendingRotationExists(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	registryURL := "https://registry.example"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, registryURL, priv)

	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	if err := os.MkdirAll(filepath.Join(rotationDir, "pending"), 0o700); err != nil {
		t.Fatal(err)
	}
	pendingPub, pendingPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pendingDID := awid.ComputeDIDKey(pendingPub)
	pendingKeyPath, err := savePendingRotationKeypair(rotationDir, pendingDID, pendingPub, pendingPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePendingRotationState(rotationDir, &pendingRotationState{
		StableID:    stableID,
		OldDID:      did,
		NewDID:      pendingDID,
		RegistryURL: registryURL,
		PendingKey:  pendingKeyPath,
	}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected rotate-key to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "pending rotation exists") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwIDShowWorksWithStandaloneIdentity(t *testing.T) {
	t.Parallel()

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/key") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          "did:aw:TestStableID",
				"current_did_key": "did:key:z6MkTestKey",
			})
			return
		}
		http.NotFound(w, r)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Write only identity.yaml and signing.key — no workspace.yaml.
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(awDir, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            did,
		StableID:       stableID,
		Address:        "acme.com/alice",
		Custody:        "self",
		Lifetime:       "persistent",
		RegistryURL:    registryServer.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-05T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(awDir, "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "show", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id show failed: %v\n%s", err, string(out))
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["did_key"] != did {
		t.Fatalf("did_key=%v want %v", got["did_key"], did)
	}
	if got["did_aw"] != stableID {
		t.Fatalf("did_aw=%v want %v", got["did_aw"], stableID)
	}
	if got["address"] != "acme.com/alice" {
		t.Fatalf("address=%v", got["address"])
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["registry_status"] != "registered" {
		t.Fatalf("registry_status=%v", got["registry_status"])
	}
}

func TestAwIDResolveUsesAWIDRegistryURLEnvWithoutWorkspace(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	var registryHits atomic.Int32
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/key":
			registryHits.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
	}))
	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("AWEB_URL should not be used for awid lookup: %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, "", priv)

	run := exec.CommandContext(ctx, bin, "id", "resolve", stableID, "--json")
	run.Env = append(testCommandEnv(tmp),
		"AWID_REGISTRY_URL="+registryServer.URL,
		"AWEB_URL="+awebServer.URL,
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id resolve failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["registry_url"] != registryServer.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], registryServer.URL)
	}
	if got["current_did_key"] != did {
		t.Fatalf("current_did_key=%v want %v", got["current_did_key"], did)
	}
	if registryHits.Load() != 1 {
		t.Fatalf("registry hits=%d want 1", registryHits.Load())
	}
}

func TestAwIDVerifyUsesIdentityRegistryURLWithoutWorkspace(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	logEntry := testDidLogEntry(t, stableID, priv, did, "create", nil, nil, 1, strings.Repeat("b", 64))

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/log":
			_ = json.NewEncoder(w).Encode([]map[string]any{didLogJSON(logEntry)})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, registryServer.URL, priv)

	run := exec.CommandContext(ctx, bin, "id", "verify", stableID, "--json")
	run.Env = append(testCommandEnv(tmp), "AWEB_URL=https://should-not-be-used.example")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id verify failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "OK" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["registry_url"] != registryServer.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], registryServer.URL)
	}
}

func TestAwIDVerifyAWIDRegistryURLEnvOverridesIdentityRegistryURL(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	logEntry := testDidLogEntry(t, stableID, priv, did, "create", nil, nil, 1, strings.Repeat("c", 64))

	var envHits atomic.Int32
	envServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/log":
			envHits.Add(1)
			_ = json.NewEncoder(w).Encode([]map[string]any{didLogJSON(logEntry)})
		default:
			t.Fatalf("unexpected env registry request %s %s", r.Method, r.URL.Path)
		}
	}))
	identityServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("identity registry should not be used when AWID_REGISTRY_URL is set: %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, identityServer.URL, priv)

	run := exec.CommandContext(ctx, bin, "id", "verify", stableID, "--json")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+envServer.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id verify failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["registry_url"] != envServer.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], envServer.URL)
	}
	if envHits.Load() != 1 {
		t.Fatalf("env registry hits=%d want 1", envHits.Load())
	}
}

func TestAwIDResolveWorksWithoutSigningKeyWhenIdentityRegistryURLPresent(t *testing.T) {
	t.Parallel()

	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
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

	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(awDir, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     "acme.com/alice",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: registryServer.URL,
		CreatedAt:   "2026-04-14T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "resolve", stableID, "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id resolve failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["current_did_key"] != did {
		t.Fatalf("current_did_key=%v want %v", got["current_did_key"], did)
	}
	if got["registry_url"] != registryServer.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], registryServer.URL)
	}
}

func TestResolveRegistryClientForLookupDefaultsWithoutIdentityOrEnv(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	registry, identity, err := resolveRegistryClientForLookup(tmp)
	if err != nil {
		t.Fatalf("resolveRegistryClientForLookup: %v", err)
	}
	if identity != nil {
		t.Fatalf("identity=%+v want nil", identity)
	}
	if registry.DefaultRegistryURL != awid.DefaultAWIDRegistryURL {
		t.Fatalf("default registry=%q want %q", registry.DefaultRegistryURL, awid.DefaultAWIDRegistryURL)
	}
}

func TestResolveRegistryClientForLookupRejectsAWIDRegistryURLLocal(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "local")

	tmp := t.TempDir()
	_, _, err := resolveRegistryClientForLookup(tmp)
	if err == nil {
		t.Fatal("expected AWID_REGISTRY_URL=local to fail")
	}
	if !strings.Contains(err.Error(), "AWID_REGISTRY_URL=local is not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAwIDShowWorksWithoutIdentityFileForEphemeralWorkspace(t *testing.T) {
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
	didKey := writeEphemeralIdentityWorkspaceForIDTest(t, tmp, "https://app.aweb.ai", "default:alice.aweb.ai", "alice-laptop", priv)

	run := exec.CommandContext(ctx, bin, "id", "show", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id show failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["did_key"] != didKey {
		t.Fatalf("did_key=%v want %v", got["did_key"], didKey)
	}
	if got["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("lifetime=%v", got["lifetime"])
	}
	if got["custody"] != awid.CustodySelf {
		t.Fatalf("custody=%v", got["custody"])
	}
	if got["registry_status"] != "not_applicable" {
		t.Fatalf("registry_status=%v", got["registry_status"])
	}
	if _, ok := got["did_aw"]; ok {
		t.Fatalf("did_aw should be absent for ephemeral identity, got %v", got["did_aw"])
	}
	if _, ok := got["address"]; ok {
		t.Fatalf("address should be absent for ephemeral identity, got %v", got["address"])
	}
}

func TestAwIDVerifyWorksWithoutIdentityFileForEphemeralWorkspace(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	logEntry := testDidLogEntry(t, stableID, priv, did, "create", nil, nil, 1, strings.Repeat("a", 64))

	var serverURL string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/log":
			_ = json.NewEncoder(w).Encode([]map[string]any{didLogJSON(logEntry)})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	serverURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	_, ephemeralKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeEphemeralIdentityWorkspaceForIDTest(t, tmp, serverURL, "default:alice.aweb.ai", "alice-laptop", ephemeralKey)

	run := exec.CommandContext(ctx, bin, "id", "verify", stableID, "--json")
	run.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+serverURL)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id verify failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "OK" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["current_did_key"] != did {
		t.Fatalf("current_did_key=%v want %v", got["current_did_key"], did)
	}
}

func TestAwIDRotateKeyFailsClearlyWithoutIdentityFileForEphemeralWorkspace(t *testing.T) {
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
	networkServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected network call during ephemeral rotate-key failure: %s %s", r.Method, r.URL.Path)
	}))
	writeEphemeralIdentityWorkspaceForIDTest(t, tmp, networkServer.URL, "default:alice.aweb.ai", "alice-laptop", priv)

	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected rotate-key to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "this command requires a persistent identity") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwIDRegisterFailsClearlyWithoutIdentityFileForEphemeralWorkspace(t *testing.T) {
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
	networkServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected network call during ephemeral register failure: %s %s", r.Method, r.URL.Path)
	}))
	writeEphemeralIdentityWorkspaceForIDTest(t, tmp, networkServer.URL, "default:alice.aweb.ai", "alice-laptop", priv)

	run := exec.CommandContext(ctx, bin, "id", "register", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected register to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "this command requires a persistent identity") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwIDShowFailsForEmptyIdentityFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "identity.yaml"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(awDir, "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "show", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected id show to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "current identity is invalid: .aw/identity.yaml is missing did") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
	if did := awid.ComputeDIDKey(pub); strings.Contains(string(out), did) {
		t.Fatalf("unexpected silent fallback to signing key in output:\n%s", string(out))
	}
}

func TestAwIDShowFailsForIdentityDIDMismatch(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(awDir, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       awid.ComputeDIDKey(wrongPub),
		StableID:  awid.ComputeStableID(pub),
		Address:   "alice.aweb.ai/alice-laptop",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-13T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(awDir, "signing.key"), priv); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "show", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected id show to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "current identity is invalid: .aw/identity.yaml did") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwIDShowFailsWhenEphemeralCertMissingMemberDIDKey(t *testing.T) {
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
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(awDir, "signing.key"), priv); err != nil {
		t.Fatal(err)
	}
	workspace := workspaceBinding("https://app.aweb.ai", "default:alice.aweb.ai", "alice-laptop", "workspace-1")
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(awDir, "workspace.yaml"), &workspace); err != nil {
		t.Fatal(err)
	}
	cert := &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-1",
		Team:          "default:alice.aweb.ai",
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  "",
		Alias:         "alice-laptop",
		Lifetime:      awid.LifetimeEphemeral,
		IssuedAt:      "2026-04-13T00:00:00Z",
		Signature:     "invalid",
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, cert.Team, cert); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "id", "show", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected id show to fail\n%s", string(out))
	}
	if !strings.Contains(string(out), "active team certificate is missing member_did_key") {
		t.Fatalf("unexpected error output:\n%s", string(out))
	}
}

func TestAwIDRegisterWorksWithStandaloneIdentity(t *testing.T) {
	t.Parallel()

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "acme.com/alice"

	var registerCalls atomic.Int32
	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did":
			registerCalls.Add(1)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["did_aw"] != stableID {
				t.Fatalf("did_aw=%v want %v", payload["did_aw"], stableID)
			}
			if payload["did_key"] != did {
				t.Fatalf("did_key=%v want %v", payload["did_key"], did)
			}
			if payload["server"] != "" {
				t.Fatalf("server=%v want empty string", payload["server"])
			}
			if payload["address"] != address {
				t.Fatalf("address=%v want %v", payload["address"], address)
			}
			if payload["handle"] != "alice" {
				t.Fatalf("handle=%v want alice", payload["handle"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case "/v1/did/" + stableID + "/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"server":          "",
				"address":         address,
				"handle":          "alice",
				"created_at":      "2026-04-05T00:00:00Z",
				"updated_at":      "2026-04-05T00:00:00Z",
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
	writeStandaloneSelfCustodyIdentity(t, tmp, address, did, stableID, registryServer.URL, priv)

	run := exec.CommandContext(ctx, bin, "id", "register", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("id register failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "registered" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["registry_url"] != registryServer.URL {
		t.Fatalf("registry_url=%v want %v", got["registry_url"], registryServer.URL)
	}
	if got["did_aw"] != stableID {
		t.Fatalf("did_aw=%v want %v", got["did_aw"], stableID)
	}
	if got["did_key"] != did {
		t.Fatalf("did_key=%v want %v", got["did_key"], did)
	}
	if registerCalls.Load() != 1 {
		t.Fatalf("register calls=%d want 1", registerCalls.Load())
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

func TestConfirmAndVerifyIDCreateDNSRetriesOnFailure(t *testing.T) {
	t.Parallel()

	did := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	var calls int
	resolver := &countingTXTResolver{
		failUntil: 1,
		records: map[string][]string{
			"_awid.acme.com": {idCreateDNSRecordValue(did, "https://api.awid.ai")},
		},
	}

	// Simulate user answering "y" twice (first attempt fails, second succeeds).
	// Wrap in bufio.Reader so the buffer is reused across prompt calls.
	input := bufio.NewReader(strings.NewReader("y\ny\n"))
	var output strings.Builder

	plan := &idCreatePlan{
		NeedsDNSSetup:  true,
		Domain:         "acme.com",
		ControllerDID:  did,
		RegistryURL:    "https://api.awid.ai",
		DNSRecordName:  "_awid.acme.com",
		DNSRecordValue: idCreateDNSRecordValue(did, "https://api.awid.ai"),
	}
	err := confirmAndVerifyIDCreateDNS(plan, idCreateOptions{
		SkipDNSVerify: false,
		PromptIn:      input,
		PromptOut:     &output,
		TXTResolver:   resolver,
	})
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	calls = resolver.calls
	if calls != 2 {
		t.Fatalf("expected 2 DNS lookups, got %d", calls)
	}
	if !strings.Contains(output.String(), "lookup _awid.acme.com") {
		t.Fatalf("expected error message in output, got: %s", output.String())
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

func writeSelfCustodyConfig(t *testing.T, workingDir, serverURL, address, namespaceSlug, handle, did, stableID string, signingKey ed25519.PrivateKey) {
	t.Helper()
	pub := signingKey.Public().(ed25519.PublicKey)
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveKeypairAt(signingKeyPath, awid.PublicKeyPath(signingKeyPath), pub, signingKey); err != nil {
		t.Fatal(err)
	}
	state := workspaceBinding(serverURL, "backend:myteam", handle, "agent-1")
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(workingDir, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     address,
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: serverURL,
		CreatedAt:   "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

func writeStandaloneSelfCustodyIdentity(t *testing.T, workingDir, address, did, stableID, registryURL string, signingKey ed25519.PrivateKey) {
	t.Helper()
	pub := signingKey.Public().(ed25519.PublicKey)
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveKeypairAt(signingKeyPath, awid.PublicKeyPath(signingKeyPath), pub, signingKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            did,
		StableID:       stableID,
		Address:        address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    registryURL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-05T00:00:00Z",
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

func didFromRegistryAuthHeader(t *testing.T, r *http.Request) string {
	t.Helper()
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		t.Fatal("missing Authorization header")
	}
	parts := strings.Split(auth, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("unexpected Authorization header %q", auth)
	}
	return parts[1]
}

func cloneStringMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func writeEphemeralIdentityWorkspaceForIDTest(t *testing.T, workingDir, serverURL, teamID, alias string, signingKey ed25519.PrivateKey) string {
	t.Helper()
	workspace := workspaceBinding(serverURL, teamID, alias, "workspace-1")
	if err := awid.SaveSigningKey(filepath.Join(workingDir, ".aw", "signing.key"), signingKey); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	writeTeamCertificateWorkspaceForTest(t, workingDir, workspace, &testSelectionFixture{
		SigningKey: signingKey,
		Lifetime:   awid.LifetimeEphemeral,
		CreatedAt:  "2026-04-13T00:00:00Z",
	})
	writeWorkspaceBindingForTest(t, workingDir, workspace)
	if _, err := os.Stat(filepath.Join(workingDir, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should be absent for ephemeral workspace, err=%v", err)
	}
	return awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
}

type staticTXTResolver map[string][]string

func (r staticTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if records, ok := r[name]; ok {
		return records, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: name}
}

type countingTXTResolver struct {
	failUntil int
	calls     int
	records   map[string][]string
}

func (r *countingTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.calls++
	if r.calls <= r.failUntil {
		return nil, &net.DNSError{IsNotFound: true, Err: "no such host", Name: name}
	}
	if records, ok := r.records[name]; ok {
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
