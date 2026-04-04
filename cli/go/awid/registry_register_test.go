package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterSelfCustodialDIDPostsCreateEntry(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	var got didRegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/did" {
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"registered":true}`))
	}))
	t.Cleanup(server.Close)

	if err := RegisterSelfCustodialDID(
		context.Background(),
		server.URL,
		"https://app.example.com",
		"acme.com/alice",
		"alice",
		did,
		stableID,
		priv,
	); err != nil {
		t.Fatal(err)
	}

	if got.DIDAW != stableID {
		t.Fatalf("did_aw=%q", got.DIDAW)
	}
	if got.DIDKey != did {
		t.Fatalf("did_key=%q", got.DIDKey)
	}
	if got.Server != "https://app.example.com" {
		t.Fatalf("server=%q", got.Server)
	}
	if got.Address != "acme.com/alice" {
		t.Fatalf("address=%q", got.Address)
	}
	if got.Handle == nil || *got.Handle != "alice" {
		t.Fatalf("handle=%v", got.Handle)
	}
	if got.Seq != 1 || got.PrevEntryHash != nil {
		t.Fatalf("seq=%d prev=%v", got.Seq, got.PrevEntryHash)
	}
	if got.StateHash != stableIdentityStateHash(stableID, did, "https://app.example.com", "acme.com/alice", "alice") {
		t.Fatalf("state_hash=%q", got.StateHash)
	}
	if got.AuthorizedBy != did {
		t.Fatalf("authorized_by=%q", got.AuthorizedBy)
	}
	if got.Proof == "" {
		t.Fatal("proof should not be empty")
	}
}

func TestRegisterSelfCustodialDIDTreatsSameKeyConflictAsSuccess(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			posts++
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"did_aw already registered"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	if err := RegisterSelfCustodialDID(
		context.Background(),
		server.URL,
		"https://app.example.com",
		"acme.com/alice",
		"alice",
		did,
		stableID,
		priv,
	); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("posts=%d", posts)
	}
}

func TestRegisterSelfCustodialDIDRejectsInvalidStableID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	err = RegisterSelfCustodialDID(
		context.Background(),
		"https://registry.example.com",
		"https://app.example.com",
		"acme.com/alice",
		"alice",
		did,
		"stable-project-key",
		priv,
	)
	if err == nil || !strings.Contains(err.Error(), "did:aw:") {
		t.Fatalf("err=%v, want did:aw validation failure", err)
	}
}
