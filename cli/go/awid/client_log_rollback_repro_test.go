package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestTruncatedLogCannotRollPinBackToRetiredKey is the aajc.8 anti-rollback
// repro. Verified log heads live only in a process-memory cache
// (registry_resolver.go headCache), while the pin survives on disk. So after a
// restart a compromised registry can serve a VALID but TRUNCATED prefix of the
// log — genesis alone — and the client, having no persisted memory of the
// higher sequence it already verified, accepts the retired key as current and
// rolls the pin backwards. That defeats rotation revocation exactly when an old
// key plus the registry are compromised, which is the case rotation exists for.
//
// The fix requires an authenticated checkpoint (verified seq + entry hash)
// persisted with the pin, and refusing any served log that does not contain and
// extend it.
func TestTruncatedLogCannotRollPinBackToRetiredKey(t *testing.T) {
	t.Parallel()

	// One identity that legitimately rotates key1 -> key2.
	pub1, priv1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did1 := ComputeDIDKey(pub1)
	stableID := ComputeStableID(pub1)

	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did2 := ComputeDIDKey(pub2)

	genesis := signedDidKeyResolution(t, priv1, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did1,
		LogHead: &DidKeyEvidence{
			Seq: 1, Operation: "register_did", NewDIDKey: did1,
			AuthorizedBy: did1, Timestamp: "2026-02-22T10:00:00Z",
		},
	}).LogHead
	prevHash := genesis.EntryHash
	rotated := signedDidKeyResolution(t, priv1, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: did2,
		LogHead: &DidKeyEvidence{
			Seq: 2, Operation: "rotate_key", PreviousDIDKey: &did1, NewDIDKey: did2,
			PrevEntryHash: &prevHash, AuthorizedBy: did1, Timestamp: "2026-02-22T10:05:00Z",
		},
	}).LogHead

	// truncated flips the registry from honest (full log, seq 2) to malicious
	// (genesis only, seq 1) — a valid prefix, correctly signed.
	truncated := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		head, current := rotated, did2
		entries := []DidKeyEvidence{*genesis, *rotated}
		if truncated {
			head, current = genesis, did1
			entries = []DidKeyEvidence{*genesis}
		}
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-1", "domain": "acme.com", "name": "alice",
				"did_aw": stableID, "current_did_key": current,
				"reachability": "public", "created_at": "2026-02-01T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": stableID, "current_did_key": current, "log_head": head,
			})
		case "/v1/did/" + stableID + "/log":
			_ = json.NewEncoder(w).Encode(entries)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	address := "acme.com/alice"
	// The pin store is the part that persists across a restart.
	pins := NewPinStore()

	// newSession simulates a fresh process: new resolver (empty head cache) and
	// new client, reusing the persisted pin store.
	newSession := func() *Client {
		resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
		resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
			value:     DomainAuthority{RegistryURL: server.URL},
			expiresAt: time.Now().Add(time.Minute),
		}
		c, err := New("http://example")
		if err != nil {
			t.Fatal(err)
		}
		c.SetPinStore(pins, "")
		c.SetResolver(resolver)
		return c
	}

	// Session 1: the honest registry serves the full log; the client verifies
	// the rotation and pins the CURRENT key.
	status, _ := newSession().NormalizeSenderTrust(
		context.Background(), Verified, address, did2, stableID, nil, nil, nil,
	)
	if status != Verified {
		t.Fatalf("legitimate rotation: status=%q, want verified", status)
	}
	if got := pins.Pins[stableID].DIDKey; got != did2 {
		t.Fatalf("after rotation pin did:key=%q, want rotated %q", got, did2)
	}

	// Restart. The registry is now compromised along with the RETIRED key, and
	// serves a valid truncated prefix that ends at genesis.
	truncated = true

	status, _ = newSession().NormalizeSenderTrust(
		context.Background(), Verified, address, did1, stableID, nil, nil, nil,
	)

	if status != IdentityMismatch {
		t.Fatalf("rollback to retired key: status=%q, want IdentityMismatch", status)
	}
	if got := pins.Pins[stableID].DIDKey; got != did2 {
		t.Fatalf("pin rolled back to retired key %q; must stay at rotated %q", got, did2)
	}
}
