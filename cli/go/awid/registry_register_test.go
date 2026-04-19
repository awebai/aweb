package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type identityVectorFile struct {
	KeySeeds map[string]string `json:"key_seeds"`
	Mapping  struct {
		DIDAW         string `json:"did_aw"`
		InitialDIDKey string `json:"initial_did_key"`
		RotatedDIDKey string `json:"rotated_did_key"`
	} `json:"mapping"`
	Entries []identityEntryVector `json:"entries"`
}

type identityEntryVector struct {
	Name                  string         `json:"name"`
	EntryPayload          map[string]any `json:"entry_payload"`
	CanonicalEntryPayload string         `json:"canonical_entry_payload"`
	SignatureB64          string         `json:"signature_b64"`
}

func loadIdentityVector(t *testing.T) identityVectorFile {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", "identity-log-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out identityVectorFile
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func identityVectorEntry(t *testing.T, vectors identityVectorFile, name string) identityEntryVector {
	t.Helper()
	for _, entry := range vectors.Entries {
		if entry.Name == name {
			return entry
		}
	}
	t.Fatalf("missing identity vector entry %q", name)
	return identityEntryVector{}
}

func TestRegisterIdentityMatchesRegisterVector(t *testing.T) {
	vectors := loadIdentityVector(t)
	entry := identityVectorEntry(t, vectors, "register_did")
	seed, err := hex.DecodeString(vectors.KeySeeds["initial_seed_hex"])
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	timestamp, err := time.Parse(time.RFC3339, entry.EntryPayload["timestamp"].(string))
	if err != nil {
		t.Fatal(err)
	}
	oldNow := registryNow
	registryNow = func() time.Time { return timestamp.UTC() }
	t.Cleanup(func() { registryNow = oldNow })

	var got didRegisterRequest
	var gotRaw map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			if err := json.NewDecoder(r.Body).Decode(&gotRaw); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(gotRaw)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{"registered":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+vectors.Mapping.DIDAW+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          vectors.Mapping.DIDAW,
				"current_did_key": vectors.Mapping.InitialDIDKey,
				"server":          "",
				"address":         "",
				"handle":          nil,
				"created_at":      "2026-04-18T12:00:00Z",
				"updated_at":      "2026-04-18T12:00:00Z",
			})
		default:
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	if _, err := client.RegisterIdentity(
		context.Background(),
		server.URL,
		vectors.Mapping.InitialDIDKey,
		vectors.Mapping.DIDAW,
		priv,
	); err != nil {
		t.Fatal(err)
	}

	for _, field := range []string{"address", "server", "handle", "did_key"} {
		if _, ok := gotRaw[field]; ok {
			t.Fatalf("register_did payload unexpectedly carried %q", field)
		}
	}
	payload := CanonicalDidLogPayload(got.DIDAW, &DidKeyEvidence{
		Seq:            got.Seq,
		Operation:      got.Operation,
		PreviousDIDKey: got.PreviousDIDKey,
		NewDIDKey:      got.NewDIDKey,
		PrevEntryHash:  got.PrevEntryHash,
		StateHash:      got.StateHash,
		AuthorizedBy:   got.AuthorizedBy,
		Timestamp:      got.Timestamp,
	})
	if payload != entry.CanonicalEntryPayload {
		t.Fatalf("canonical payload:\n got:  %s\n want: %s", payload, entry.CanonicalEntryPayload)
	}
	if got.Proof != entry.SignatureB64 {
		t.Fatalf("signature:\n got:  %s\n want: %s", got.Proof, entry.SignatureB64)
	}
}

func TestRegisterIdentityPostsCreateEntry(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	var got didRegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte(`{"registered":true}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
				"created_at":      "2026-04-04T00:00:00Z",
				"updated_at":      "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("method=%s path=%s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	if err := RegisterIdentity(
		context.Background(),
		server.URL,
		did,
		stableID,
		priv,
	); err != nil {
		t.Fatal(err)
	}

	if got.DIDAW != stableID {
		t.Fatalf("did_aw=%q", got.DIDAW)
	}
	if got.Operation != "register_did" {
		t.Fatalf("operation=%q", got.Operation)
	}
	if got.NewDIDKey != did {
		t.Fatalf("new_did_key=%q", got.NewDIDKey)
	}
	if got.PreviousDIDKey != nil {
		t.Fatalf("previous_did_key=%v", got.PreviousDIDKey)
	}
	if got.Seq != 1 || got.PrevEntryHash != nil {
		t.Fatalf("seq=%d prev=%v", got.Seq, got.PrevEntryHash)
	}
	if got.StateHash != stableIdentityStateHash(stableID, did) {
		t.Fatalf("state_hash=%q", got.StateHash)
	}
	if got.AuthorizedBy != did {
		t.Fatalf("authorized_by=%q", got.AuthorizedBy)
	}
	if got.Proof == "" {
		t.Fatal("proof should not be empty")
	}
}

func TestRegisterIdentityTreatsSameKeyConflictAsSuccess(t *testing.T) {
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

	if err := RegisterIdentity(
		context.Background(),
		server.URL,
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

func TestRegisterIdentityReturnsAlreadyRegisteredForDifferentKeyConflict(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherDID := ComputeDIDKey(otherPriv.Public().(ed25519.PublicKey))

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"detail":"did_aw already registered"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did_aw":          stableID,
				"current_did_key": otherDID,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	_, err = client.RegisterIdentity(context.Background(), server.URL, did, stableID, priv)

	var already *AlreadyRegisteredError
	if err == nil {
		t.Fatal("expected conflict")
	}
	if !strings.Contains(err.Error(), "already registered") || !strings.Contains(err.Error(), otherDID) {
		t.Fatalf("err=%v, want already registered error for other key", err)
	}
	if !strings.Contains(err.Error(), stableID) {
		t.Fatalf("err=%v, want did:aw in error", err)
	}
	if !errors.As(err, &already) {
		t.Fatalf("err=%T, want AlreadyRegisteredError", err)
	}
	if already.ExistingDIDKey != otherDID {
		t.Fatalf("existing_did_key=%q", already.ExistingDIDKey)
	}
}

func TestRegisterIdentityRejectsInvalidStableID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	err = RegisterIdentity(
		context.Background(),
		"https://registry.example.com",
		did,
		"stable-project-key",
		priv,
	)
	if err == nil || !strings.Contains(err.Error(), "did:aw:") {
		t.Fatalf("err=%v, want did:aw validation failure", err)
	}
}
