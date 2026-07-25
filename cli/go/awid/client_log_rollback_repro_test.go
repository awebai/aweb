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

// didLogRegistry serves one identity that legitimately rotates key1 -> key2.
// Flipping truncated makes it serve a VALID but truncated prefix (genesis only),
// which is the rollback attack.
type didLogRegistry struct {
	stableID  string
	did1      string
	did2      string
	truncated *bool
	pins      *PinStore
	newClient func() *Client
}

func newDidLogRegistry(t *testing.T) *didLogRegistry {
	t.Helper()
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

	// The pin store is the part that persists across a restart.
	pins := NewPinStore()

	// newClient simulates a fresh process: new resolver (empty head cache) and
	// new client, reusing the persisted pin store.
	newClient := func() *Client {
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

	return &didLogRegistry{
		stableID: stableID, did1: did1, did2: did2,
		truncated: &truncated, pins: pins, newClient: newClient,
	}
}

const didLogTestAddress = "acme.com/alice"

// The aajc.8 anti-rollback repro. Verified log heads lived only in a
// process-memory cache while the pin survives on disk, so after a restart a
// compromised registry could serve a VALID but TRUNCATED prefix — genesis alone
// — and the client, with no persisted memory of the higher sequence it had
// already verified, accepted the retired key as current and rolled the pin
// backwards. That defeats rotation revocation exactly when an old key plus the
// registry are compromised, which is the case rotation exists for.
func TestTruncatedLogCannotRollPinBackToRetiredKey(t *testing.T) {
	t.Parallel()

	f := newDidLogRegistry(t)
	address, pins, stableID, did1, did2 := didLogTestAddress, f.pins, f.stableID, f.did1, f.did2

	// Session 1: the honest registry serves the full log; the client verifies
	// the rotation and pins the CURRENT key.
	status, _ := f.newClient().NormalizeSenderTrust(
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
	*f.truncated = true

	status, _ = f.newClient().NormalizeSenderTrust(
		context.Background(), Verified, address, did1, stableID, nil, nil, nil,
	)

	if status != IdentityMismatch {
		t.Fatalf("rollback to retired key: status=%q, want IdentityMismatch", status)
	}
	if got := pins.Pins[stableID].DIDKey; got != did2 {
		t.Fatalf("pin rolled back to retired key %q; must stay at rotated %q", got, did2)
	}
}

// A pin written before checkpoints existed carries no log_seq/log_entry_hash.
// It must still advance safely: verification anchors the head through the full
// log from genesis, the pin follows the rotation, and it acquires a checkpoint
// so it is protected from then on. Migration must not require re-pinning.
func TestLegacyPinWithoutCheckpointMigratesThroughFullLog(t *testing.T) {
	t.Parallel()

	f := newDidLogRegistry(t)

	// A legacy pin: the identity and its current key, but no checkpoint.
	f.pins.StorePin(f.stableID, didLogTestAddress, "", "")
	f.pins.Pins[f.stableID].StableID = f.stableID
	f.pins.Pins[f.stableID].DIDKey = f.did1
	if f.pins.Pins[f.stableID].LogSeq != 0 {
		t.Fatal("fixture must start without a checkpoint")
	}

	status, _ := f.newClient().NormalizeSenderTrust(
		context.Background(), Verified, didLogTestAddress, f.did2, f.stableID, nil, nil, nil,
	)

	if status != Verified {
		t.Fatalf("legacy pin migration: status=%q, want verified", status)
	}
	pin := f.pins.Pins[f.stableID]
	if pin.DIDKey != f.did2 {
		t.Fatalf("legacy pin did:key=%q, want rotated %q", pin.DIDKey, f.did2)
	}
	if pin.LogSeq != 2 || pin.LogEntryHash == "" {
		t.Fatalf("legacy pin did not acquire a checkpoint: seq=%d hash=%q", pin.LogSeq, pin.LogEntryHash)
	}

	// Now protected: a truncated prefix is refused after the restart.
	*f.truncated = true
	status, _ = f.newClient().NormalizeSenderTrust(
		context.Background(), Verified, didLogTestAddress, f.did1, f.stableID, nil, nil, nil,
	)
	if status != IdentityMismatch {
		t.Fatalf("after migration, rollback status=%q, want IdentityMismatch", status)
	}
	if got := f.pins.Pins[f.stableID].DIDKey; got != f.did2 {
		t.Fatalf("pin rolled back to %q, want %q", got, f.did2)
	}
}
