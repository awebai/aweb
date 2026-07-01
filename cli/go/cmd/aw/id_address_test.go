package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func writeGlobalIdentityForAddressClaimTest(t *testing.T, workingDir, registryURL, address string) (ed25519.PrivateKey, string, string) {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	didAW := awid.ComputeStableID(pub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:            didKey,
		StableID:       didAW,
		Address:        address,
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryURL:    registryURL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-06-30T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), key); err != nil {
		t.Fatal(err)
	}
	return key, didKey, didAW
}

func writeControllerForAddressClaimTest(t *testing.T, domain, registryURL string) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(pub)
	if err := awconfig.SaveControllerKey(domain, key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerMeta(domain, &awconfig.ControllerMeta{
		Domain:        domain,
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
		CreatedAt:     "2026-06-30T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	return key, controllerDID
}

func TestIDAddressClaimUsesAtomicPrimitiveForExistingGlobalIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()

	var sawClaim bool
	var sawDIDAW string
	var sawDIDKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/other.com/addresses/claims":
			sawClaim = true
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["operation"] != awid.AtomicAddressClaimOperation {
				t.Fatalf("operation=%v", payload["operation"])
			}
			if payload["address_name"] != "bob" {
				t.Fatalf("address_name=%v", payload["address_name"])
			}
			if payload["identity_custody"] != string(awid.AddressClaimCustodySelf) || payload["namespace_custody"] != string(awid.AddressClaimCustodySelf) {
				t.Fatalf("custody=%v/%v", payload["identity_custody"], payload["namespace_custody"])
			}
			if strings.TrimSpace(payloadString(payload, "identity_signature")) == "" || strings.TrimSpace(payloadString(payload, "namespace_signature")) == "" {
				t.Fatalf("missing signatures: %+v", payload)
			}
			if _, ok := payload["did_log_proof"].(map[string]any); !ok {
				t.Fatalf("missing did_log_proof: %+v", payload)
			}
			sawDIDAW = payloadString(payload, "did_aw")
			sawDIDKey = payloadString(payload, "current_did_key")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":            "claimed",
				"dry_run":           false,
				"domain":            "other.com",
				"name":              "bob",
				"did_aw":            sawDIDAW,
				"current_did_key":   sawDIDKey,
				"identity_custody":  "self",
				"namespace_custody": "self",
				"did_status":        "existing",
				"address_status":    "created",
				"address": map[string]any{
					"address_id":         "addr-bob",
					"domain":             "other.com",
					"name":               "bob",
					"did_aw":             sawDIDAW,
					"current_did_key":    sawDIDKey,
					"reachability":       "public",
					"visible_to_team_id": nil,
					"created_at":         "2026-06-30T00:00:00Z",
				},
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	_, didKey, didAW := writeGlobalIdentityForAddressClaimTest(t, workingDir, server.URL, "acme.com/alice")
	_, controllerDID := writeControllerForAddressClaimTest(t, "other.com", server.URL)

	out, err := executeIDAddressClaim(context.Background(), workingDir, idAddressClaimOptions{Address: "other.com/bob"})
	if err != nil {
		t.Fatalf("executeIDAddressClaim: %v", err)
	}
	if !sawClaim {
		t.Fatal("atomic claim endpoint was not called")
	}
	if out.Status != "claimed" || out.Address != "other.com/bob" || out.DIDAW != didAW || out.DIDKey != didKey || out.ControllerDID != controllerDID {
		t.Fatalf("output=%+v", out)
	}
	identityRaw, err := os.ReadFile(filepath.Join(workingDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(identityRaw), "other.com/bob") {
		t.Fatalf("additional address claim must not rewrite identity.yaml primary address: %s", string(identityRaw))
	}
}

func TestIDAddressClaimFailsClosedWithoutNamespaceAuthority(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()
	serverCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		t.Fatalf("unexpected registry mutation without namespace authority: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	writeGlobalIdentityForAddressClaimTest(t, workingDir, server.URL, "acme.com/alice")
	before, err := os.ReadFile(filepath.Join(workingDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = executeIDAddressClaim(context.Background(), workingDir, idAddressClaimOptions{Address: "other.com/bob", RegistryURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "namespace authority is required") {
		t.Fatalf("expected namespace authority error, got %v", err)
	}
	if serverCalls != 0 {
		t.Fatalf("registry called %d times", serverCalls)
	}
	after, err := os.ReadFile(filepath.Join(workingDir, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("identity.yaml changed on failed claim\nbefore:\n%s\nafter:\n%s", string(before), string(after))
	}
}

func TestIDAddressClaimHostedNamespaceFailsClosedWithJoinGuidanceEvenWithLocalControllerKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()
	serverCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls++
		t.Fatalf("unexpected registry mutation for hosted standalone claim: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()

	writeGlobalIdentityForAddressClaimTest(t, workingDir, server.URL, "acme.com/alice")
	writeControllerForAddressClaimTest(t, "team.aweb.ai", server.URL)
	_, err := executeIDAddressClaim(context.Background(), workingDir, idAddressClaimOptions{Address: "team.aweb.ai/bob", RegistryURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "standalone hosted address claims are not supported") || !strings.Contains(err.Error(), "aw team join") {
		t.Fatalf("expected hosted join guidance, got %v", err)
	}
	if serverCalls != 0 {
		t.Fatalf("registry called %d times", serverCalls)
	}
}

func TestIDAddressesDefaultsToCurrentGlobalIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workingDir := t.TempDir()

	var didAW string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/did/"+didAW+"/addresses" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{
			{"address_id": "addr-1", "domain": "acme.com", "name": "alice", "did_aw": didAW, "current_did_key": "did:key:zCurrent", "reachability": "public", "created_at": "2026-06-30T00:00:00Z"},
			{"address_id": "addr-2", "domain": "other.com", "name": "bob", "did_aw": didAW, "current_did_key": "did:key:zCurrent", "reachability": "public", "created_at": "2026-06-30T00:00:00Z"},
		}})
	}))
	defer server.Close()

	_, _, stableID := writeGlobalIdentityForAddressClaimTest(t, workingDir, server.URL, "acme.com/alice")
	didAW = stableID
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	oldJSON := jsonFlag
	jsonFlag = false
	defer func() { jsonFlag = oldJSON }()
	out := captureIDAddressStdout(t, func() {
		if err := runIDAddresses(nil, nil); err != nil {
			t.Fatalf("runIDAddresses: %v", err)
		}
	})
	if !strings.Contains(out, "acme.com/alice") || !strings.Contains(out, "other.com/bob") {
		t.Fatalf("addresses output missing claimed addresses:\n%s", out)
	}
}

func payloadString(payload map[string]any, key string) string {
	value, _ := payload[key].(string)
	return value
}

func captureIDAddressStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	fn()
	_ = w.Close()
	os.Stdout = oldStdout
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
