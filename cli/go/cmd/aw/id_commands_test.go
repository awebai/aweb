package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

func TestAwIDRotateKeyPersistsPendingRetryAndRecovers(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	address := "myteam.aweb.ai/alice"

	currentRegistryDID := oldDID
	currentServerDID := oldDID
	createEntry := testDidLogEntry(t, stableID, oldPriv, oldDID, "create", nil, nil, 1, strings.Repeat("a", 64))
	currentHead := createEntry
	var registryRotateCalls atomic.Int32
	var serverRotateCalls atomic.Int32
	serverShouldFail := atomic.Bool{}
	serverShouldFail.Store(true)
	var serverURL string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/resolve/myteam.aweb.ai/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did":        currentServerDID,
				"stable_id":  stableID,
				"address":    address,
				"handle":     "alice",
				"server":     serverURL,
				"custody":    "self",
				"lifetime":   "persistent",
				"public_key": base64.RawStdEncoding.EncodeToString(extractPublicKeyForTest(t, currentServerDID)),
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
		case "/v1/agents/me/rotate":
			serverRotateCalls.Add(1)
			if serverShouldFail.Load() {
				http.Error(w, "server update failed", http.StatusInternalServerError)
				return
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			currentServerDID = payload["new_did"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "rotated",
				"old_did":        oldDID,
				"new_did":        currentServerDID,
				"new_public_key": payload["new_public_key"],
				"custody":        "self",
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
	if first["status"] != "pending_server_update" {
		t.Fatalf("first status=%v", first["status"])
	}
	keysDir := awconfig.KeysDir(cfgPath)
	if pending, err := loadPendingRotationState(keysDir, stableID); err != nil || pending == nil {
		t.Fatalf("pending rotation missing: %v", err)
	}
	cfg := loadConfigForTest(t, cfgPath)
	if cfg.Accounts["acct"].DID != oldDID {
		t.Fatalf("config DID changed too early: %s", cfg.Accounts["acct"].DID)
	}
	if registryRotateCalls.Load() != 1 {
		t.Fatalf("registry rotate calls=%d", registryRotateCalls.Load())
	}

	serverShouldFail.Store(false)
	second := runJSON("id", "rotate-key", "--json")
	if second["status"] != "rotated" {
		t.Fatalf("second status=%v", second["status"])
	}
	if registryRotateCalls.Load() != 1 {
		t.Fatalf("registry rotate retried unexpectedly: %d", registryRotateCalls.Load())
	}
	if serverRotateCalls.Load() != 2 {
		t.Fatalf("server rotate calls=%d", serverRotateCalls.Load())
	}
	if pending, err := loadPendingRotationState(keysDir, stableID); err != nil || pending != nil {
		t.Fatalf("pending rotation not cleaned up: %v %#v", err, pending)
	}
	cfg = loadConfigForTest(t, cfgPath)
	if cfg.Accounts["acct"].DID != currentServerDID {
		t.Fatalf("config DID=%s want %s", cfg.Accounts["acct"].DID, currentServerDID)
	}
	rotatedKeyPath := filepath.Join(keysDir, "rotated", strings.ReplaceAll(oldDID, ":", "-")+".key")
	if _, err := os.Stat(rotatedKeyPath); err != nil {
		t.Fatalf("rotated key missing: %v", err)
	}
}

func TestPromotePendingRotationKeypairRecoversInterruptedPromotion(t *testing.T) {
	t.Parallel()

	keysDir := t.TempDir()
	address := "myteam.aweb.ai/alice"
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newDID := awid.ComputeDIDKey(newPub)
	pendingKeyPath, err := savePendingRotationKeypair(keysDir, newDID, newPub, newPriv)
	if err != nil {
		t.Fatal(err)
	}

	activeKeyPath := awid.SigningKeyPath(keysDir, address)
	if err := os.Rename(pendingKeyPath, activeKeyPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(awid.PublicKeyPath(activeKeyPath)); !os.IsNotExist(err) {
		t.Fatalf("expected missing active public key before recovery, got %v", err)
	}

	gotKeyPath, err := promotePendingRotationKeypair(keysDir, address, pendingKeyPath)
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

func writeSelfCustodyConfig(t *testing.T, cfgPath, serverURL, address, namespaceSlug, handle, did, stableID string, signingKey ed25519.PrivateKey) {
	t.Helper()
	keysDir := awconfig.KeysDir(cfgPath)
	pub := signingKey.Public().(ed25519.PublicKey)
	if err := awid.SaveKeypair(keysDir, address, pub, signingKey); err != nil {
		t.Fatal(err)
	}
	cfg := &awconfig.GlobalConfig{
		Servers: map[string]awconfig.Server{
			"local": {URL: serverURL},
		},
		Accounts: map[string]awconfig.Account{
			"acct": {
				Account: awid.Account{
					Server:         "local",
					APIKey:         "aw_sk_test",
					IdentityHandle: handle,
					NamespaceSlug:  namespaceSlug,
					DID:            did,
					StableID:       stableID,
					SigningKey:     awid.SigningKeyPath(keysDir, address),
					Custody:        "self",
					Lifetime:       "persistent",
				},
				DefaultProject: "myteam",
			},
		},
		DefaultAccount: "acct",
	}
	if err := cfg.SaveGlobalTo(cfgPath); err != nil {
		t.Fatal(err)
	}
}

func loadConfigForTest(t *testing.T, cfgPath string) *awconfig.GlobalConfig {
	t.Helper()
	cfg, err := awconfig.LoadGlobalFrom(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
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
