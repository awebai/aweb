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

// TestForgedRotationDoesNotReplaceTOFUPin is the end-to-end adversarial check
// for aajc.3: an attacker serves a full DID log for the victim's did:aw whose
// genesis is the attacker's own key. Because the victim's did:aw does not derive
// from the attacker's genesis key, the full-log verifier returns HARD_ERROR, the
// client reports IdentityMismatch, and the victim's existing TOFU pin is left
// untouched. Before the fix the forged rotation verified as OK_VERIFIED and
// replaced the pin (identity takeover).
func TestForgedRotationDoesNotReplaceTOFUPin(t *testing.T) {
	t.Parallel()

	// Victim identity (the attacker cannot sign with this key).
	victimPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	victimDID := ComputeDIDKey(victimPub)
	victimStableID := ComputeStableID(victimPub)

	// Attacker keys, wholly under attacker control.
	atkPub, atkPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	atkDID := ComputeDIDKey(atkPub)
	atk2Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	atk2DID := ComputeDIDKey(atk2Pub)

	// The attacker forges a full log for the VICTIM's did:aw: a genesis bound to
	// the attacker's own key, then a rotation to a second attacker key.
	forgedGenesis := signedDidKeyResolution(t, atkPriv, &DidKeyResolution{
		DIDAW:         victimStableID,
		CurrentDIDKey: atkDID,
		LogHead: &DidKeyEvidence{
			Seq: 1, Operation: "register_did", NewDIDKey: atkDID,
			AuthorizedBy: atkDID, Timestamp: "2026-02-22T10:00:00Z",
		},
	}).LogHead
	prevHash := forgedGenesis.EntryHash
	forgedRotate := signedDidKeyResolution(t, atkPriv, &DidKeyResolution{
		DIDAW:         victimStableID,
		CurrentDIDKey: atk2DID,
		LogHead: &DidKeyEvidence{
			Seq: 2, Operation: "rotate_key", PreviousDIDKey: &atkDID, NewDIDKey: atk2DID,
			PrevEntryHash: &prevHash, AuthorizedBy: atkDID, Timestamp: "2026-02-22T10:05:00Z",
		},
	}).LogHead

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-1", "domain": "acme.com", "name": "alice",
				"did_aw": victimStableID, "current_did_key": atk2DID,
				"reachability": "public", "created_at": "2026-02-01T00:00:00Z",
			})
		case "/v1/did/" + victimStableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": victimStableID, "current_did_key": atk2DID, "log_head": forgedRotate,
			})
		case "/v1/did/" + victimStableID + "/log":
			_ = json.NewEncoder(w).Encode([]DidKeyEvidence{*forgedGenesis, *forgedRotate})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Now().Add(time.Minute),
	}

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(resolver)

	// The victim was already TOFU-pinned to its genuine key.
	address := "acme.com/alice"
	ps.StorePin(victimStableID, address, "", "")
	ps.Pins[victimStableID].StableID = victimStableID
	ps.Pins[victimStableID].DIDKey = victimDID

	status, _ := c.NormalizeSenderTrust(
		context.Background(), Verified, address, atk2DID, victimStableID, nil, nil, nil,
	)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want IdentityMismatch", status)
	}
	if got := ps.Pins[victimStableID].DIDKey; got != victimDID {
		t.Fatalf("pin DIDKey=%q was overwritten; want victim %q", got, victimDID)
	}
}
