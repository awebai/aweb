package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/a2a"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestA2ACardReportsUnsignedInteropWithoutAWIDClaim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	card := testA2ACard("")
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a2a/agents/r_support/agent-card.json" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(card)
	}))

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", server.URL+"/a2a/agents/r_support/agent-card.json")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a card failed: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationUnsigned || got.Verification.Tier != a2a.VerificationTier0 {
		t.Fatalf("verification=%#v", got.Verification)
	}
	if strings.Contains(string(out), "AWID-backed") || strings.Contains(string(out), "verified") {
		t.Fatalf("unsigned output made a verified/AWID-backed claim:\n%s", string(out))
	}
}

func TestA2ACardDoesNotClaimSignatureVerificationWithoutAWID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	card := testA2ACard("")
	card.Signatures = []a2a.Signature{{Protected: "unused", Signature: "unused"}}
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/a2a/agents/r_support/agent-card.json" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(card)
	}))

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", server.URL+"/a2a/agents/r_support/agent-card.json")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a card failed: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationUnsigned || got.Verification.Tier != a2a.VerificationTier0 {
		t.Fatalf("verification=%#v", got.Verification)
	}
	if strings.Contains(string(out), "signature_ok") || strings.Contains(string(out), "verified") {
		t.Fatalf("signature-present output claimed verification:\n%s", string(out))
	}
}

func TestA2ACardVerifiesAWIDPublicationDigest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	var cardURL string
	var server *httptest.Server
	card := testA2ACard("")
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			_ = json.NewEncoder(w).Encode(card)
		case "/v1/namespaces/acme.com/addresses/help/a2a":
			digest, err := a2a.CardDigest(card)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": "acme.com/help",
				"did_aw":  "did:aw:test",
				"a2a": map[string]any{
					"status":                   "active",
					"card_url":                 cardURL,
					"rpc_url":                  server.URL + "/a2a/agents/r_support/rpc",
					"route_id":                 "r_support",
					"gateway_identity":         "did:aw:gateway",
					"card_digest_alg":          "sha256",
					"card_digest":              digest.Value,
					"card_revision":            "1",
					"publication_assertion_id": "pub-1",
					"published_at":             "2026-06-07T00:00:00Z",
					"expires_at":               "2026-07-07T00:00:00Z",
					"verification":             "awid_publication_available",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	cardURL = server.URL + "/a2a/agents/r_support/agent-card.json"

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", cardURL, "--address", "acme.com/help", "--registry-url", server.URL)
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a card --address failed: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationAWIDVerified || got.Verification.Code != "awid_publication_verified" {
		t.Fatalf("verification=%#v", got.Verification)
	}
}

func TestA2ACardReportsDelegatedAWIDPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	var cardURL string
	var server *httptest.Server
	card := testA2ACard("")
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			_ = json.NewEncoder(w).Encode(card)
		case "/v1/namespaces/acme.com/addresses/help/a2a":
			digest, err := a2a.CardDigest(card)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": "acme.com/help",
				"did_aw":  "did:aw:test",
				"a2a": map[string]any{
					"status":                   "active",
					"card_url":                 cardURL,
					"rpc_url":                  server.URL + "/a2a/agents/r_support/rpc",
					"route_id":                 "r_support",
					"gateway_identity":         "did:aw:gateway",
					"card_digest_alg":          "sha256",
					"card_digest":              digest.Value,
					"card_revision":            "1",
					"publication_assertion_id": "pub-1",
					"delegation_id":            "deleg-1",
					"delegation_digest":        "sha256:deleg",
					"published_at":             "2026-06-07T00:00:00Z",
					"expires_at":               "2026-07-07T00:00:00Z",
					"verification":             "awid_publication_available",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	cardURL = server.URL + "/a2a/agents/r_support/agent-card.json"

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", cardURL, "--address", "acme.com/help", "--registry-url", server.URL)
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a card delegated failed: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationAWIDVerified {
		t.Fatalf("verification=%#v", got.Verification)
	}
}

func TestA2ACardRejectsAWIDDigestMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	cardURL := ""
	card := testA2ACard("")
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			_ = json.NewEncoder(w).Encode(card)
		case "/v1/namespaces/acme.com/addresses/help/a2a":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": "acme.com/help",
				"did_aw":  "did:aw:test",
				"a2a": map[string]any{
					"status":                   "active",
					"card_url":                 cardURL,
					"route_id":                 "r_support",
					"gateway_identity":         "did:aw:gateway",
					"card_digest_alg":          "sha256",
					"card_digest":              "sha256:deadbeef",
					"card_revision":            "1",
					"publication_assertion_id": "pub-1",
					"published_at":             "2026-06-07T00:00:00Z",
					"expires_at":               "2026-07-07T00:00:00Z",
					"verification":             "awid_publication_available",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	cardURL = server.URL + "/a2a/agents/r_support/agent-card.json"

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", cardURL, "--address", "acme.com/help", "--registry-url", server.URL)
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("digest mismatch should be reported, not be a transport error: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationFailed || got.Verification.Code != "a2a_card_digest_mismatch" {
		t.Fatalf("verification=%#v", got.Verification)
	}
}

func TestA2ACardReportsRevokedPublicationWithoutCallingItVerified(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	card := testA2ACard("")
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			_ = json.NewEncoder(w).Encode(card)
		case "/v1/namespaces/acme.com/addresses/help/a2a":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": "acme.com/help",
				"did_aw":  "did:aw:test",
				"a2a":     nil,
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "card", server.URL+"/a2a/agents/r_support/agent-card.json", "--address", "acme.com/help", "--registry-url", server.URL)
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("revoked publication should be reported in output, not be a transport error: %v\n%s", err, string(out))
	}
	var got a2aCardOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("decode output: %v\n%s", err, string(out))
	}
	if got.Verification.Status != a2a.VerificationFailed || got.Verification.Code != "a2a_publication_missing" {
		t.Fatalf("verification=%#v", got.Verification)
	}
	if strings.Contains(string(out), "awid_verified") {
		t.Fatalf("revoked output claimed AWID verification:\n%s", string(out))
	}
}

func TestA2ACardRejectsInvalidCardAndDoesNotFetchJWKULink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			card := testA2ACard("")
			card.Version = ""
			card.Signatures = []a2a.Signature{{Protected: "unused", Signature: "unused", Header: map[string]any{"jku": "https://evil.example/jwks.json"}}}
			_ = json.NewEncoder(w).Encode(card)
		default:
			t.Fatalf("unexpected request, possible blind jku fetch: %s %s", r.Method, r.URL.Path)
		}
	}))

	run := exec.CommandContext(ctx, bin, "a2a", "card", server.URL+"/a2a/agents/r_support/agent-card.json")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("invalid card should fail\n%s", string(out))
	}
}

func TestA2APublishPostsDelegationThenPublicationAndVerifies(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)
	resetA2APublishFlagsForTest(t)
	oldHTTPClient := a2aHTTPClient
	t.Cleanup(func() { a2aHTTPClient = oldHTTPClient })

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	address := "acme.com/research"
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), priv); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       did,
		StableID:  stableID,
		Address:   address,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-06-07T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	gatewayIdentity := "did:aw:zQmGatewayForA2APublishTest1111111111111111111111"
	var cardURL string
	var delegationDigest string
	var sawDelegation bool
	var sawPublication bool
	card := testA2ACard("")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_research/agent-card.json":
			card.SupportedInterfaces[0].URL = "https://" + r.Host + "/a2a/agents/r_research/rpc"
			_ = json.NewEncoder(w).Encode(card)
		case "/v1/a2a/delegations":
			if r.Method != http.MethodPost {
				t.Fatalf("delegation method=%s", r.Method)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			sawDelegation = true
			if body["authority_source"] != awid.A2AAuthoritySelfDelegation {
				t.Fatalf("delegation authority_source=%v", body["authority_source"])
			}
			if body["signer_did"] != did || body["delegator_did_aw"] != stableID || body["delegated_gateway_identity"] != gatewayIdentity {
				t.Fatalf("bad delegation body: %#v", body)
			}
			canonical, err := awid.A2ADelegationCanonical(awid.A2ADelegationFields{
				Operation:                stringFieldForA2ATest(body, "operation"),
				DelegationID:             stringFieldForA2ATest(body, "delegation_id"),
				DelegatorDIDAW:           stringFieldForA2ATest(body, "delegator_did_aw"),
				DelegatorCurrentDIDKey:   stringFieldForA2ATest(body, "delegator_current_did_key"),
				DelegatedGatewayIdentity: stringFieldForA2ATest(body, "delegated_gateway_identity"),
				Address:                  stringFieldForA2ATest(body, "address"),
				RouteID:                  stringFieldForA2ATest(body, "route_id"),
				CardURL:                  stringFieldForA2ATest(body, "card_url"),
				RPCURL:                   stringFieldForA2ATest(body, "rpc_url"),
				AllowedOperations:        []string{"send_task", "receive_reply", "cancel_task", "serve_card"},
				CardDigestAlg:            stringFieldForA2ATest(body, "card_digest_alg"),
				CardDigest:               stringFieldForA2ATest(body, "card_digest"),
				CustodyMode:              stringFieldForA2ATest(body, "custody_mode"),
				AuthoritySource:          stringFieldForA2ATest(body, "authority_source"),
				SignerDID:                stringFieldForA2ATest(body, "signer_did"),
				SignerKID:                stringFieldForA2ATest(body, "signer_kid"),
				IssuedAt:                 stringFieldForA2ATest(body, "issued_at"),
				ExpiresAt:                stringFieldForA2ATest(body, "expires_at"),
				Status:                   stringFieldForA2ATest(body, "status"),
				RegistryURL:              stringFieldForA2ATest(body, "registry_url"),
			})
			if err != nil {
				t.Fatal(err)
			}
			delegationDigest, err = awid.A2ASignedAssertionDigest(canonical, stringFieldForA2ATest(body, "signature"))
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "applied",
				"delegation_id":    stringFieldForA2ATest(body, "delegation_id"),
				"assertion_digest": delegationDigest,
				"address":          address,
				"route_id":         "r_research",
			})
		case "/v1/a2a/publications":
			if !sawDelegation {
				t.Fatal("publication arrived before delegation")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			sawPublication = true
			if body["authority_source"] != awid.A2AAuthoritySelfIdentityKey {
				t.Fatalf("publication authority_source=%v", body["authority_source"])
			}
			if body["delegation_digest"] != delegationDigest || body["gateway_identity"] != gatewayIdentity {
				t.Fatalf("bad publication body: %#v delegationDigest=%s", body, delegationDigest)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":           "applied",
				"assertion_id":     stringFieldForA2ATest(body, "assertion_id"),
				"assertion_digest": "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"address":          address,
				"route_id":         "r_research",
			})
		case "/v1/namespaces/acme.com/addresses/research/a2a":
			digest, err := a2a.CardDigest(card)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address": address,
				"did_aw":  stableID,
				"a2a": map[string]any{
					"status":                   "active",
					"card_url":                 cardURL,
					"rpc_url":                  "https://" + r.Host + "/a2a/agents/r_research/rpc",
					"route_id":                 "r_research",
					"gateway_identity":         gatewayIdentity,
					"card_digest_alg":          "sha256",
					"card_digest":              digest.Value,
					"card_revision":            "1.0.0",
					"publication_assertion_id": "pub-1",
					"delegation_id":            "del-1",
					"delegation_digest":        delegationDigest,
					"published_at":             "2026-06-07T00:00:00Z",
					"expires_at":               "2026-07-07T00:00:00Z",
					"verification":             "awid_publication_available",
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	a2aHTTPClient = server.Client
	cardURL = server.URL + "/a2a/agents/r_research/agent-card.json"
	a2aPublishRegistry = server.URL
	a2aPublishGatewayIdentity = gatewayIdentity

	out, err := runA2APublish(context.Background(), cardURL)
	if err != nil {
		t.Fatalf("runA2APublish: %v", err)
	}
	if !sawDelegation || !sawPublication {
		t.Fatalf("sawDelegation=%v sawPublication=%v", sawDelegation, sawPublication)
	}
	if out.Verification.Status != a2a.VerificationAWIDVerified {
		t.Fatalf("verification=%#v", out.Verification)
	}
	if out.Delegation == nil || out.Publication == nil {
		t.Fatalf("missing write responses: %#v", out)
	}
}

func TestA2ASendNoWaitUsesCredentialFileAndReturnImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	var sawReturnImmediately bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			card := testA2ACard("http://" + r.Host + "/a2a/agents/r_support/rpc")
			_ = json.NewEncoder(w).Encode(card)
		case "/a2a/agents/r_support/rpc":
			if got := r.Header.Get("X-A2A-API-Key"); got != "secret-key" {
				t.Fatalf("X-A2A-API-Key=%q", got)
			}
			if got := r.Header.Get("X-A2A-Caller-ID"); got != "ci" {
				t.Fatalf("X-A2A-Caller-ID=%q", got)
			}
			var req struct {
				ID     string `json:"id"`
				Method string `json:"method"`
				Params struct {
					Configuration struct {
						ReturnImmediately bool `json:"returnImmediately"`
					} `json:"configuration"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.Method != "SendMessage" {
				t.Fatalf("method=%s", req.Method)
			}
			sawReturnImmediately = req.Params.Configuration.ReturnImmediately
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{"task": map[string]any{
					"id":        "task-1",
					"contextId": "ctx-1",
					"status":    map[string]any{"state": "TASK_STATE_WORKING", "timestamp": "2026-06-07T00:00:00Z"},
					"metadata":  map[string]any{"task_bearer_token": "token-1"},
				}},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	writeA2ACredentialsForTest(t, tmp, server.URL, "secret-key", "ci", "")

	run := exec.CommandContext(ctx, bin, "--json", "a2a", "send", server.URL+"/a2a/agents/r_support/agent-card.json", "hello")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a send failed: %v\n%s", err, string(out))
	}
	if !sawReturnImmediately {
		t.Fatal("send did not set configuration.returnImmediately for default no-wait mode")
	}
	var task a2a.Task
	if err := json.Unmarshal(extractJSON(t, out), &task); err != nil {
		t.Fatalf("decode task: %v\n%s", err, string(out))
	}
	if task.ID != "task-1" || task.Status.State != "TASK_STATE_WORKING" {
		t.Fatalf("task=%#v", task)
	}
}

func resetA2APublishFlagsForTest(t *testing.T) {
	t.Helper()
	oldAddress := a2aPublishAddress
	oldRegistry := a2aPublishRegistry
	oldGateway := a2aPublishGatewayIdentity
	oldRouteID := a2aPublishRouteID
	oldRPCURL := a2aPublishRPCURL
	oldRevision := a2aPublishCardRevision
	oldAssertionID := a2aPublishAssertionID
	oldDelegationID := a2aPublishDelegationID
	oldExpiresDays := a2aPublishExpiresDays
	oldDefault := a2aPublishDefaultForHost
	a2aPublishAddress = ""
	a2aPublishRegistry = ""
	a2aPublishGatewayIdentity = ""
	a2aPublishRouteID = ""
	a2aPublishRPCURL = ""
	a2aPublishCardRevision = ""
	a2aPublishAssertionID = ""
	a2aPublishDelegationID = ""
	a2aPublishExpiresDays = 30
	a2aPublishDefaultForHost = false
	t.Cleanup(func() {
		a2aPublishAddress = oldAddress
		a2aPublishRegistry = oldRegistry
		a2aPublishGatewayIdentity = oldGateway
		a2aPublishRouteID = oldRouteID
		a2aPublishRPCURL = oldRPCURL
		a2aPublishCardRevision = oldRevision
		a2aPublishAssertionID = oldAssertionID
		a2aPublishDelegationID = oldDelegationID
		a2aPublishExpiresDays = oldExpiresDays
		a2aPublishDefaultForHost = oldDefault
	})
}

func stringFieldForA2ATest(value map[string]any, key string) string {
	got, _ := value[key].(string)
	return got
}

func TestA2ASendWaitReturnsFailedTaskAsExitOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			card := testA2ACard("http://" + r.Host + "/a2a/agents/r_support/rpc")
			_ = json.NewEncoder(w).Encode(card)
		case "/a2a/agents/r_support/rpc":
			var req struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{"task": map[string]any{
					"id":     "task-1",
					"status": map[string]any{"state": "TASK_STATE_FAILED", "timestamp": "2026-06-07T00:00:00Z"},
				}},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))

	run := exec.CommandContext(ctx, bin, "a2a", "send", server.URL+"/a2a/agents/r_support/agent-card.json", "hello", "--wait")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("failed task should exit non-zero\n%s", string(out))
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
		t.Fatalf("exit=%v out=%s", err, string(out))
	}
}

func TestA2AStatusAndCancelUseTaskTokenCredential(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			card := testA2ACard("http://" + r.Host + "/a2a/agents/r_support/rpc")
			_ = json.NewEncoder(w).Encode(card)
		case "/a2a/agents/r_support/rpc":
			if got := r.Header.Get("X-A2A-Task-Token"); got != "task-token" {
				t.Fatalf("X-A2A-Task-Token=%q", got)
			}
			var req struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			state := "TASK_STATE_COMPLETED"
			if req.Method == "CancelTask" {
				state = "TASK_STATE_CANCELED"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"id":     "task-1",
					"status": map[string]any{"state": state, "timestamp": "2026-06-07T00:00:00Z"},
				},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	writeA2ACredentialsForTest(t, tmp, server.URL, "", "", "task-token")

	status := exec.CommandContext(ctx, bin, "--json", "a2a", "status", server.URL+"/a2a/agents/r_support/agent-card.json", "task-1")
	status.Dir = tmp
	status.Env = testCommandEnv(tmp)
	out, err := status.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a status failed: %v\n%s", err, string(out))
	}

	cancelCmd := exec.CommandContext(ctx, bin, "--json", "a2a", "cancel", server.URL+"/a2a/agents/r_support/agent-card.json", "task-1")
	cancelCmd.Dir = tmp
	cancelCmd.Env = testCommandEnv(tmp)
	out, err = cancelCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw a2a cancel failed: %v\n%s", err, string(out))
	}
}

func TestA2ASendInputRequiredExitCode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a2a/agents/r_support/agent-card.json":
			card := testA2ACard("http://" + r.Host + "/a2a/agents/r_support/rpc")
			_ = json.NewEncoder(w).Encode(card)
		case "/a2a/agents/r_support/rpc":
			var req struct {
				ID string `json:"id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{"task": map[string]any{
					"id":     "task-1",
					"status": map[string]any{"state": "TASK_STATE_INPUT_REQUIRED", "timestamp": "2026-06-07T00:00:00Z"},
				}},
			})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))

	run := exec.CommandContext(ctx, bin, "a2a", "send", server.URL+"/a2a/agents/r_support/agent-card.json", "hello", "--wait")
	run.Dir = tmp
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("input-required should exit non-zero\n%s", string(out))
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 3 {
		t.Fatalf("exit=%v out=%s", err, string(out))
	}
}

func testA2ACard(rpcURL string) a2a.Card {
	if rpcURL == "" {
		rpcURL = "https://acme.com/a2a/agents/r_support/rpc"
	}
	return a2a.Card{
		Name:        "Acme Support",
		Description: "Support agent.",
		Provider:    &a2a.Provider{Organization: "Acme", URL: "https://acme.com"},
		Version:     "1.0.0",
		Capabilities: &a2a.Capabilities{
			Streaming:         a2a.Bool(false),
			PushNotifications: a2a.Bool(false),
			Extensions:        []a2a.Extension{a2a.AWIDPublicationExtension()},
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		SupportedInterfaces: []a2a.Interface{{
			URL:             rpcURL,
			ProtocolBinding: a2a.ProtocolBindingJSONRPC,
			ProtocolVersion: a2a.ProtocolVersion10,
		}},
		Skills: []a2a.Skill{{ID: "support", Name: "Support", Description: "Answers support questions.", Tags: []string{"support"}}},
	}
}

func writeA2ACredentialsForTest(t *testing.T, dir, hostURL, apiKey, callerID, taskToken string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".aw"), 0o700); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	host := strings.TrimPrefix(hostURL, "http://")
	host = strings.TrimPrefix(host, "https://")
	data := "credentials:\n  - host: " + host + "\n"
	if apiKey != "" {
		data += "    api_key: " + apiKey + "\n"
	}
	if callerID != "" {
		data += "    caller_id: " + callerID + "\n"
	}
	if taskToken != "" {
		data += "    task_token: " + taskToken + "\n"
	}
	if err := os.WriteFile(filepath.Join(dir, ".aw", "a2a-credentials.yaml"), []byte(data), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
}
