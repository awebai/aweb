package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// addressTakeoverFixture builds the aajc.8 attack: an attacker who legitimately
// owns did:aw:attacker (a perfectly valid, self-consistent, self-signed log that
// passes every aajc.3 genesis/rotation check) and a registry that maps the
// VICTIM's address to it.
//
// This is the distinction the code conflates: a valid self-owned DID log proves
// DID -> KEY. It proves nothing about ADDRESS -> DID. Only the address authority
// (the DNS-anchored namespace controller) can authorize an address changing
// hands.
type addressTakeoverFixture struct {
	client         *Client
	pins           *PinStore
	address        string
	victimStableID string
	victimDID      string
	atkStableID    string
	atkDID         string
	controllerDID  string
	controllerPriv ed25519.PrivateKey
}

func newAddressTakeoverFixture(t *testing.T) *addressTakeoverFixture {
	t.Helper()

	victimPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	victimDID := ComputeDIDKey(victimPub)
	victimStableID := ComputeStableID(victimPub)

	// The attacker's own identity: they hold this key, so the log below is
	// genuinely valid — did:aw derives from its own genesis key.
	atkPub, atkPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	atkDID := ComputeDIDKey(atkPub)
	atkStableID := ComputeStableID(atkPub)

	// The namespace controller for acme.com, anchored in the _awid DNS TXT
	// record. The attacker does NOT hold this key.
	ctrlPub, ctrlPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(ctrlPub)

	atkGenesis := signedDidKeyResolution(t, atkPriv, &DidKeyResolution{
		DIDAW:         atkStableID,
		CurrentDIDKey: atkDID,
		LogHead: &DidKeyEvidence{
			Seq: 1, Operation: "register_did", NewDIDKey: atkDID,
			AuthorizedBy: atkDID, Timestamp: "2026-02-22T10:00:00Z",
		},
	}).LogHead

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		// The compromised/malicious registry points the victim's address at the
		// attacker's stable identity.
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id": "addr-1", "domain": "acme.com", "name": "alice",
				"did_aw": atkStableID, "current_did_key": atkDID,
				"reachability": "public", "created_at": "2026-02-01T00:00:00Z",
			})
		case "/v1/did/" + atkStableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": atkStableID, "current_did_key": atkDID, "log_head": atkGenesis,
			})
		case "/v1/did/" + atkStableID + "/log":
			_ = json.NewEncoder(w).Encode([]DidKeyEvidence{*atkGenesis})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL, ControllerDID: controllerDID},
		expiresAt: time.Now().Add(time.Minute),
	}

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	c.SetPinStore(pins, "")
	c.SetResolver(resolver)

	// The victim already holds the address pin.
	address := "acme.com/alice"
	pins.StorePin(victimStableID, address, "", "")
	pins.Pins[victimStableID].StableID = victimStableID
	pins.Pins[victimStableID].DIDKey = victimDID

	return &addressTakeoverFixture{
		client: c, pins: pins, address: address,
		victimStableID: victimStableID, victimDID: victimDID,
		atkStableID: atkStableID, atkDID: atkDID,
		controllerDID: controllerDID, controllerPriv: ctrlPriv,
	}
}

func (f *addressTakeoverFixture) assertVictimPinIntact(t *testing.T) {
	t.Helper()
	if got := f.pins.Addresses[f.address]; got != f.victimStableID {
		t.Fatalf("address %q now pinned to %q; victim binding %q was taken over",
			f.address, got, f.victimStableID)
	}
	pin, ok := f.pins.Pins[f.victimStableID]
	if !ok {
		t.Fatalf("victim pin %q was deleted", f.victimStableID)
	}
	if pin.DIDKey != f.victimDID {
		t.Fatalf("victim pin did:key=%q, want %q", pin.DIDKey, f.victimDID)
	}
	if _, ok := f.pins.Pins[f.atkStableID]; ok {
		t.Fatalf("attacker stable id %q was persisted to the pin store", f.atkStableID)
	}
}

// A valid attacker-owned DID log must NOT be accepted as authority to take over
// a different identity's pinned address. Without a controller-signed replacement
// announcement the pin stands and the mismatch is reported honestly.
func TestRegistryVerifiedAttackerDIDCannotTakeOverPinnedAddress(t *testing.T) {
	t.Parallel()

	f := newAddressTakeoverFixture(t)

	status, _ := f.client.NormalizeSenderTrust(
		context.Background(), Verified, f.address, f.atkDID, f.atkStableID, nil, nil, nil,
	)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want IdentityMismatch: a self-owned log is not address authority", status)
	}
	f.assertVictimPinIntact(t)
}

// The same takeover attempt carrying a replacement announcement that is NOT
// signed by the DNS-anchored namespace controller must also be refused.
func TestAddressReplacementWithoutControllerSignatureIsRefused(t *testing.T) {
	t.Parallel()

	f := newAddressTakeoverFixture(t)

	// The attacker signs the announcement with their own key instead of the
	// controller's, and names themselves as controller.
	_, forgedCtrlPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := CanonicalReplacementJSON(f.address, f.controllerDID, f.victimStableID, f.atkStableID, timestamp)
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(forgedCtrlPriv, []byte(payload)))
	repl := &ReplacementAnnouncement{
		Address: f.address, OldDID: f.victimStableID, NewDID: f.atkStableID,
		ControllerDID: f.controllerDID, Timestamp: timestamp, ControllerSignature: sig,
	}

	status, _ := f.client.NormalizeSenderTrust(
		context.Background(), Verified, f.address, f.atkDID, f.atkStableID, nil, repl, nil,
	)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want IdentityMismatch: announcement is not controller-signed", status)
	}
	f.assertVictimPinIntact(t)
}

// The fail-closed rule must not break legitimate handover: an address
// replacement genuinely signed by the DNS-anchored namespace controller is
// accepted and the address moves to the new stable identity.
func TestAddressReplacementSignedByControllerIsAccepted(t *testing.T) {
	t.Parallel()

	f := newAddressTakeoverFixture(t)

	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := CanonicalReplacementJSON(f.address, f.controllerDID, f.victimStableID, f.atkDID, timestamp)
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.controllerPriv, []byte(payload)))
	repl := &ReplacementAnnouncement{
		Address: f.address, OldDID: f.victimStableID, NewDID: f.atkDID,
		ControllerDID: f.controllerDID, Timestamp: timestamp, ControllerSignature: sig,
	}

	status, _ := f.client.NormalizeSenderTrust(
		context.Background(), Verified, f.address, f.atkDID, f.atkStableID, nil, repl, nil,
	)

	if status != Verified {
		t.Fatalf("status=%q, want Verified: a controller-signed replacement is authorized", status)
	}
	if got := f.pins.Addresses[f.address]; got != f.atkStableID {
		t.Fatalf("address pin=%q, want the authorized new owner %q", got, f.atkStableID)
	}
	if _, ok := f.pins.Pins[f.victimStableID]; ok {
		t.Fatalf("replaced pin %q should have been removed", f.victimStableID)
	}
}
