package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAwIDRegistryReadCommandsUseSupportContractEnvelope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	if err := awid.SaveKeypairAt(awconfig.WorktreeSigningKeyPath(tmp), awid.PublicKeyPath(awconfig.WorktreeSigningKeyPath(tmp)), pub, priv); err != nil {
		t.Fatal(err)
	}

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	t.Setenv("HOME", tmp)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seenAuth := map[string][]string{}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get("X-Request-ID")) == "" {
			t.Fatalf("missing X-Request-ID for %s %s", r.Method, r.URL.Path)
		}
		mu.Lock()
		seenAuth[r.URL.Path] = append(seenAuth[r.URL.Path], strings.TrimSpace(r.Header.Get("Authorization")))
		mu.Unlock()
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"log_head": map[string]any{
					"seq":           1,
					"operation":     "create",
					"new_did_key":   did,
					"entry_hash":    strings.Repeat("a", 64),
					"state_hash":    strings.Repeat("b", 64),
					"authorized_by": did,
					"signature":     "secret-signature-value",
					"timestamp":     "2026-04-04T00:00:00Z",
				},
			})
		case "/v1/did/" + stableID + "/addresses":
			_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{registryAddressJSON(stableID, did)}})
		case "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-04T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/addresses":
			_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{registryAddressJSON(stableID, did)}})
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(registryAddressJSON(stableID, did))
		default:
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
	}))

	run := func(args ...string) registryReadEnvelope {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
		cmd.Dir = tmp
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		var got registryReadEnvelope
		if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
			t.Fatalf("invalid json for %s: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		assertRegistryReadEnvelope(t, got, server.URL)
		if strings.Contains(string(out), "DIDKey ") || strings.Contains(string(out), "secret-signature-value") || strings.Contains(string(out), "PRIVATE KEY") {
			t.Fatalf("output leaked auth/private material:\n%s", string(out))
		}
		return got
	}

	resolved := run("id", "resolve", stableID, "--json")
	if resolved.Payload.Schema != registryReadSchema || resolved.Payload.Operation != "resolve-key" {
		t.Fatalf("resolve payload schema/op=%s/%s", resolved.Payload.Schema, resolved.Payload.Operation)
	}
	if resolved.Payload.DIDKey == nil || resolved.Payload.DIDKey.CurrentDIDKey != did {
		t.Fatalf("resolve did_key=%+v", resolved.Payload.DIDKey)
	}
	if resolved.Payload.DIDKey.LogHead == nil || resolved.Payload.DIDKey.LogHead.AuthorizedBy != did {
		t.Fatalf("resolve log_head metadata=%+v", resolved.Payload.DIDKey.LogHead)
	}
	if !registryReadHasRedaction(resolved, "payload.did_key.log_head.signature") {
		t.Fatalf("resolve redactions=%v", resolved.Redactions)
	}

	didAddresses := run("id", "addresses", stableID, "--json")
	if didAddresses.Payload.Operation != "list-did-addresses" || len(didAddresses.Payload.Addresses) != 1 {
		t.Fatalf("did addresses payload=%+v", didAddresses.Payload)
	}

	namespace := run("id", "namespace", "acme.com", "--json")
	if namespace.Payload.Operation != "namespace-state" || namespace.Payload.Namespace == nil {
		t.Fatalf("namespace payload=%+v", namespace.Payload)
	}
	if len(namespace.Payload.Addresses) != 0 {
		t.Fatalf("namespace-state should not include address listing: %+v", namespace.Payload.Addresses)
	}

	publicList := run("id", "namespace", "addresses", "acme.com", "--authority", "anonymous", "--json")
	if publicList.AuthorityMode != registryReadAuthorityAnonymous || publicList.AuthoritySubject != "" {
		t.Fatalf("anonymous authority=%s subject=%s", publicList.AuthorityMode, publicList.AuthoritySubject)
	}
	if publicList.Payload.OwnershipProof {
		t.Fatal("anonymous listing must not be ownership proof")
	}

	didList := run("id", "namespace", "addresses", "acme.com", "--authority", "did", "--json")
	if didList.AuthorityMode != registryReadAuthorityDIDKey || didList.AuthoritySubject != did {
		t.Fatalf("did authority=%s subject=%s want %s", didList.AuthorityMode, didList.AuthoritySubject, did)
	}
	if didList.Payload.OwnershipProof {
		t.Fatal("did-key listing must not be reported as namespace ownership proof")
	}

	controllerAddress := run("id", "namespace", "resolve", "acme.com/alice", "--authority", "namespace-controller", "--json")
	if controllerAddress.AuthorityMode != registryReadAuthorityNamespaceController || controllerAddress.AuthoritySubject != controllerDID {
		t.Fatalf("controller authority=%s subject=%s want %s", controllerAddress.AuthorityMode, controllerAddress.AuthoritySubject, controllerDID)
	}
	if controllerAddress.Payload.Address == nil || controllerAddress.Payload.Address.DIDAW != stableID {
		t.Fatalf("address payload=%+v", controllerAddress.Payload.Address)
	}

	mu.Lock()
	defer mu.Unlock()
	if auths := seenAuth["/v1/namespaces/acme.com/addresses"]; len(auths) < 2 || auths[0] != "" {
		t.Fatalf("anonymous namespace address auth headers=%q", auths)
	}
	if auths := seenAuth["/v1/namespaces/acme.com/addresses"]; len(auths) < 2 || !strings.Contains(auths[1], did) {
		t.Fatalf("did namespace address auth headers=%q want %s", auths, did)
	}
	if auths := seenAuth["/v1/namespaces/acme.com/addresses/alice"]; len(auths) != 1 || !strings.Contains(auths[0], controllerDID) {
		t.Fatalf("controller resolve auth headers=%q want %s", auths, controllerDID)
	}
}

func TestAwIDRegistryReadStructuredFailures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	stableID := awid.ComputeStableID(pub)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did/" + stableID + "/key":
			http.NotFound(w, r)
		case "/v1/did/" + stableID + "/addresses":
			http.Error(w, "registry secret body must not leak", http.StatusInternalServerError)
		case "/v1/namespaces/acme.com/addresses":
			http.Error(w, "forbidden secret body must not leak", http.StatusForbidden)
		default:
			t.Fatalf("unexpected registry request %s %s", r.Method, r.URL.Path)
		}
	}))

	run := func(args ...string) registryReadEnvelope {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
		cmd.Dir = tmp
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s should emit structured output with zero exit: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		if strings.Contains(string(out), "secret body") {
			t.Fatalf("output leaked registry body:\n%s", string(out))
		}
		var got registryReadEnvelope
		if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
			t.Fatalf("invalid json: %v\n%s", err, string(out))
		}
		return got
	}

	notFound := run("id", "resolve", stableID, "--json")
	assertRegistryReadError(t, notFound, registryReadStatusFail, true, "target.not_found")

	unavailable := run("id", "addresses", stableID, "--json")
	assertRegistryReadError(t, unavailable, registryReadStatusUnknown, false, "registry.unavailable")

	blocked := run("id", "namespace", "addresses", "acme.com", "--authority", "anonymous", "--json")
	assertRegistryReadError(t, blocked, registryReadStatusBlocked, true, "auth.authority_insufficient")
}

func TestAwIDRegistryReadSignedPreconditionDoesNotContactRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	var hits int
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "should not be contacted", http.StatusTeapot)
	}))

	cmd := exec.CommandContext(ctx, bin, "id", "namespace", "addresses", "acme.com", "--authority", "did", "--json")
	cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing signing key to fail\n%s", string(out))
	}
	if hits != 0 {
		t.Fatalf("registry contacted %d times", hits)
	}

	cmd = exec.CommandContext(ctx, bin, "id", "namespace", "resolve", "acme.com/alice", "--authority", "namespace-controller", "--json")
	cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
	cmd.Dir = tmp
	out, err = cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected missing controller key to fail\n%s", string(out))
	}
	if hits != 0 {
		t.Fatalf("registry contacted %d times", hits)
	}
}

func TestRegistryReadLookupDoesNotUseIdentityRegistryForUnrelatedTargets(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")

	tmp := t.TempDir()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	identityRegistryURL := "https://identity-registry.example"
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", did, stableID, identityRegistryURL, priv)

	registry, identity, err := resolveRegistryClientForLookup(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if registry.DefaultRegistryURL == identityRegistryURL {
		t.Fatalf("lookup client installed identity registry as generic fallback")
	}

	ctx := context.Background()
	localURL, err := registryLookupURL(ctx, registry, identity, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if localURL != identityRegistryURL {
		t.Fatalf("local identity did lookup url=%s want %s", localURL, identityRegistryURL)
	}

	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherStableID := awid.ComputeStableID(otherPub)
	unrelatedURL, err := registryLookupURL(ctx, registry, identity, otherStableID)
	if err != nil {
		t.Fatal(err)
	}
	if unrelatedURL == identityRegistryURL {
		t.Fatalf("unrelated did lookup used identity registry_url")
	}
}

func registryAddressJSON(stableID, did string) map[string]any {
	return map[string]any{
		"address_id":      "addr-1",
		"domain":          "acme.com",
		"name":            "alice",
		"did_aw":          stableID,
		"current_did_key": did,
		"reachability":    "public",
		"created_at":      "2026-04-04T00:00:00Z",
	}
}

func assertRegistryReadEnvelope(t *testing.T, got registryReadEnvelope, registryURL string) {
	t.Helper()
	if got.Version != supportContractVersion {
		t.Fatalf("version=%s", got.Version)
	}
	if got.Source != registryReadSourceAwid {
		t.Fatalf("source=%s", got.Source)
	}
	if got.Payload.Schema != registryReadSchema {
		t.Fatalf("payload schema=%s", got.Payload.Schema)
	}
	if got.Payload.RegistryURL != registryURL {
		t.Fatalf("registry_url=%s want %s", got.Payload.RegistryURL, registryURL)
	}
	if got.Payload.Status != registryReadStatusOK || got.Status != registryReadStatusOK {
		t.Fatalf("status top=%s payload=%s", got.Status, got.Payload.Status)
	}
	if !got.Authoritative {
		t.Fatal("successful registry read should be authoritative")
	}
	if got.RequestID == "" {
		t.Fatal("request_id missing")
	}
	if got.Redactions == nil {
		t.Fatal("redactions must be an empty array, not null")
	}
	if got.Target.Identifier == "" || got.Payload.Target.Identifier == "" {
		t.Fatalf("target missing: top=%+v payload=%+v", got.Target, got.Payload.Target)
	}
}

func assertRegistryReadError(t *testing.T, got registryReadEnvelope, status string, authoritative bool, code string) {
	t.Helper()
	if got.Status != status || got.Payload.Status != status {
		t.Fatalf("status top=%s payload=%s want %s", got.Status, got.Payload.Status, status)
	}
	if got.Authoritative != authoritative {
		t.Fatalf("authoritative=%v want %v", got.Authoritative, authoritative)
	}
	if got.Payload.Error == nil {
		t.Fatal("missing payload.error")
	}
	if got.Payload.Error.Code != code {
		t.Fatalf("error code=%s want %s", got.Payload.Error.Code, code)
	}
}

func registryReadHasRedaction(got registryReadEnvelope, field string) bool {
	for _, redaction := range got.Redactions {
		if redaction == field {
			return true
		}
	}
	return false
}
