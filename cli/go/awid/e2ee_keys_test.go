package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testEncryptionAssertion(t *testing.T, priv ed25519.PrivateKey, did, stableID string) *EncryptionKeyAssertion {
	t.Helper()
	raw := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}
	keyID, err := ComputeEncryptionKeyID(raw)
	if err != nil {
		t.Fatal(err)
	}
	assertion := &EncryptionKeyAssertion{
		Operation:           "publish_encryption_key",
		Version:             EncryptionKeyAssertionVersion,
		IdentityDID:         did,
		EncryptionKeyID:     keyID,
		EncryptionPublicKey: base64.RawStdEncoding.EncodeToString(raw),
		Algorithm:           EncryptionKeyAlgorithmX25519,
		CreatedAt:           "2026-05-26T00:00:00Z",
		NotBefore:           "2026-05-26T00:00:00Z",
		ExpiresAt:           "2030-05-27T00:00:00Z",
	}
	if strings.TrimSpace(stableID) != "" {
		assertion.IdentityStableID = &stableID
	}
	payload, err := encryptionAssertionSignedPayload(assertion)
	if err != nil {
		t.Fatal(err)
	}
	assertion.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	return assertion
}

func TestVerifyEncryptionKeyAssertion(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)

	if err := VerifyEncryptionKeyAssertion(assertion, did, stableID, time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestBuildEncryptionKeyAssertionIncludesSignedSelfCustody(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	rawPub := []byte{
		1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24,
		25, 26, 27, 28, 29, 30, 31, 32,
	}

	assertion, err := BuildEncryptionKeyAssertion(priv, did, stableID, rawPub, "", time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if assertion.Custody != EncryptionKeyCustodySelf {
		t.Fatalf("custody=%q want self", assertion.Custody)
	}
	if err := VerifyEncryptionKeyAssertion(assertion, did, stableID, time.Date(2026, 5, 26, 12, 1, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEncryptionKeyAssertionRejectsUnsignedCustodyMutation(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)
	assertion.Custody = EncryptionKeyCustodySelf

	err = VerifyEncryptionKeyAssertion(assertion, did, stableID, time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "invalid encryption key assertion signature") {
		t.Fatalf("err=%v, want custody mutation to break signature", err)
	}
}

func TestVerifyEncryptionKeyAssertionRejectsInvalidCustody(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)
	assertion.Custody = "server"

	err = VerifyEncryptionKeyAssertion(assertion, did, stableID, time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "unsupported encryption key custody") {
		t.Fatalf("err=%v, want invalid custody rejection", err)
	}
}

func TestVerifyEncryptionKeyAssertionRejectsSubstitution(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)
	err = VerifyEncryptionKeyAssertion(assertion, ComputeDIDKey(otherPub), stableID, time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "identity_did") {
		t.Fatalf("err=%v, want identity_did mismatch", err)
	}
}

func TestVerifyEncryptionKeyAssertionRejectsLocalEmptyStableIDField(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	assertion := testEncryptionAssertion(t, priv, did, "")
	empty := ""
	assertion.IdentityStableID = &empty
	payload, err := encryptionAssertionSignedPayload(assertion)
	if err != nil {
		t.Fatal(err)
	}
	assertion.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, []byte(payload)))

	err = VerifyEncryptionKeyAssertion(assertion, did, "", time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "omit identity_stable_id") {
		t.Fatalf("err=%v, want local stable-id omission rejection", err)
	}
}

func TestRegistryResolverReturnsVerifiedEncryptionKey(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"created_at":      "2026-05-26T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"encryption_key":  assertion,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.Now = func() time.Time { return time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC) }
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC),
	}

	identity, err := resolver.Resolve(context.Background(), "acme.com/alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.EncryptionKey == nil {
		t.Fatal("missing encryption key")
	}
	if identity.EncryptionKey.EncryptionKeyID != assertion.EncryptionKeyID {
		t.Fatalf("key id=%q want %q", identity.EncryptionKey.EncryptionKeyID, assertion.EncryptionKeyID)
	}
}

func TestRegistryResolverRejectsInvalidEncryptionKeyAssertion(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion := testEncryptionAssertion(t, priv, did, stableID)
	assertion.Signature = "invalid"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"created_at":      "2026-05-26T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"encryption_key":  assertion,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.Now = func() time.Time { return time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC) }
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Date(2026, 5, 26, 13, 0, 0, 0, time.UTC),
	}

	_, err = resolver.Resolve(context.Background(), "acme.com/alice")
	if err == nil || !strings.Contains(err.Error(), "invalid encryption key assertion") {
		t.Fatalf("err=%v, want invalid encryption key assertion", err)
	}
}

func TestListAgentsReturnsVerifiedLocalEncryptionKey(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	assertion := testEncryptionAssertion(t, priv, did, "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(ListAgentsResponse{
			TeamID: "backend:acme.com",
			Agents: []AgentView{{
				AgentID:       "agent-1",
				Alias:         "alice",
				DIDKey:        did,
				IdentityScope: "local",
				EncryptionKey: assertion,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.ListAgents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Agents) != 1 || resp.Agents[0].EncryptionKey == nil {
		t.Fatalf("missing encryption key in response: %#v", resp)
	}
}

func TestListAgentsRejectsInvalidLocalEncryptionKeyAssertion(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	assertion := testEncryptionAssertion(t, priv, did, "did:aw:2wrong")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(ListAgentsResponse{
			TeamID: "backend:acme.com",
			Agents: []AgentView{{
				AgentID:       "agent-1",
				Alias:         "alice",
				DIDKey:        did,
				IdentityScope: "local",
				EncryptionKey: assertion,
			}},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.ListAgents(context.Background())
	if err == nil || !strings.Contains(err.Error(), "omit identity_stable_id") {
		t.Fatalf("err=%v, want local stable-id rejection", err)
	}
}

func TestAgentViewRequireEncryptionKeyRejectsMissing(t *testing.T) {
	t.Parallel()

	agent := AgentView{Alias: "alice", DIDKey: "did:key:z6Mkalice"}
	_, err := agent.RequireEncryptionKey(time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "no E2E encryption key") {
		t.Fatalf("err=%v, want missing encryption key error", err)
	}
}

func TestAgentViewRequireEncryptionKeyRejectsStale(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	assertion := testEncryptionAssertion(t, priv, did, "")
	agent := AgentView{Alias: "alice", DIDKey: did, EncryptionKey: assertion}
	_, err = agent.RequireEncryptionKey(time.Date(2030, 5, 28, 12, 0, 0, 0, time.UTC))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err=%v, want stale encryption key error", err)
	}
}

func TestPublishMyEncryptionKey(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	assertion := testEncryptionAssertion(t, priv, did, "")
	var got *EncryptionKeyAssertion

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/v1/agents/me/encryption-key" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(PublishAgentEncryptionKeyResponse{
			AgentID:       "agent-1",
			TeamID:        "backend:acme.com",
			Alias:         "alice",
			EncryptionKey: got,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.PublishMyEncryptionKey(context.Background(), assertion)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.EncryptionKeyID != assertion.EncryptionKeyID {
		t.Fatalf("request assertion=%#v, want %#v", got, assertion)
	}
	if resp.EncryptionKey == nil || resp.EncryptionKey.EncryptionKeyID != assertion.EncryptionKeyID {
		t.Fatalf("response=%#v, want published assertion", resp)
	}
}
