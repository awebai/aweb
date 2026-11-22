package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// One anti-rollback checkpoint per (registry, stable ID); the pin keeps only
// the key binding. A move to another registry starts a new checkpoint, and the
// pin's key binding protects across it (Antares 4dbb84a5, 10.15).

type checkpointIdentity struct {
	oldDID, newDID, stableID string
	create, rotate           *DidKeyEvidence
}

func newCheckpointIdentity(t *testing.T) checkpointIdentity {
	t.Helper()
	oldKey, newKey := seededKey(11), seededKey(12)
	id := checkpointIdentity{
		oldDID:   ComputeDIDKey(oldKey.Public().(ed25519.PublicKey)),
		newDID:   ComputeDIDKey(newKey.Public().(ed25519.PublicKey)),
		stableID: ComputeStableID(oldKey.Public().(ed25519.PublicKey)),
	}
	id.create = signedDidKeyResolution(t, oldKey, &DidKeyResolution{
		DIDAW: id.stableID, CurrentDIDKey: id.oldDID,
		LogHead: &DidKeyEvidence{Seq: 1, Operation: "create", NewDIDKey: id.oldDID, AuthorizedBy: id.oldDID, Timestamp: "2026-11-01T00:00:00Z"},
	}).LogHead
	prev := id.create.EntryHash
	id.rotate = signedDidKeyResolution(t, oldKey, &DidKeyResolution{
		DIDAW: id.stableID, CurrentDIDKey: id.newDID,
		LogHead: &DidKeyEvidence{Seq: 2, Operation: "rotate_key", PreviousDIDKey: &id.oldDID, NewDIDKey: id.newDID, PrevEntryHash: &prev, AuthorizedBy: id.oldDID, Timestamp: "2026-11-02T00:00:00Z"},
	}).LogHead
	return id
}

// identityRegistry serves one identity at acme.com/alice with currentDID and
// the log up to head.
func identityRegistry(t *testing.T, id checkpointIdentity, currentDID string, log ...*DidKeyEvidence) *httptest.Server {
	t.Helper()
	head := log[len(log)-1]
	entries := make([]DidKeyEvidence, 0, len(log))
	for _, entry := range log {
		entries = append(entries, *entry)
	}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{"address_id": "addr-alice", "domain": "acme.com", "name": "alice", "did_aw": id.stableID, "current_did_key": currentDID, "created_at": "2026-11-01T00:00:00Z"})
		case "/v1/did/" + id.stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": id.stableID, "current_did_key": currentDID, "log_head": head})
		case "/v1/did/" + id.stableID + "/log":
			_ = json.NewEncoder(w).Encode(entries)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func checkpointClient(t *testing.T, registry *httptest.Server, pins *PinStore) *Client {
	t.Helper()
	resolver := NewRegistryResolver(registry.Client(), staticTXTResolver{})
	routeUntrustedResolverRegistriesToInjectedClient(resolver)
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{value: DomainAuthority{RegistryURL: registry.URL}, expiresAt: time.Now().Add(time.Hour)}
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	c.SetPinStore(pins, "")
	c.SetResolver(resolver)
	return c
}

func checkpointsOf(t *testing.T, pins *PinStore) map[string]map[string]*VerifiedLogHead {
	t.Helper()
	heads := map[string]map[string]*VerifiedLogHead{}
	raw, ok := pins.unknown[receivedHeadsField]
	if !ok {
		return heads
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &heads); err != nil {
		t.Fatal(err)
	}
	return heads
}

func setCheckpoint(t *testing.T, pins *PinStore, registryURL, stableID string, head *DidKeyEvidence, currentDID string) {
	t.Helper()
	heads := checkpointsOf(t, pins)
	if heads[registryURL] == nil {
		heads[registryURL] = map[string]*VerifiedLogHead{}
	}
	heads[registryURL][stableID] = &VerifiedLogHead{Seq: head.Seq, EntryHash: head.EntryHash, CurrentDIDKey: currentDID}
	data, err := json.Marshal(heads)
	if err != nil {
		t.Fatal(err)
	}
	var plain map[string]any
	if err := json.Unmarshal(data, &plain); err != nil {
		t.Fatal(err)
	}
	if pins.unknown == nil {
		pins.unknown = map[string]any{}
	}
	pins.unknown[receivedHeadsField] = plain
}

func pinFor(pins *PinStore, id checkpointIdentity, didKey string) {
	pins.StorePin(id.stableID, "acme.com/alice", "", "")
	pins.Pins[id.stableID].StableID = id.stableID
	pins.Pins[id.stableID].DIDKey = didKey
	pins.Pins[id.stableID].ConfirmedBy = "registry"
}

func TestVerifiedHeadIsCheckpointedUnderItsRegistry(t *testing.T) {
	id := newCheckpointIdentity(t)
	registry := identityRegistry(t, id, id.oldDID, id.create)
	pins := NewPinStore()
	c := checkpointClient(t, registry, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", id.oldDID, id.stableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified", status)
	}
	if head := checkpointsOf(t, pins)[registry.URL][id.stableID]; head == nil || head.Seq != 1 || head.EntryHash != id.create.EntryHash {
		t.Fatalf("checkpoint at %s=%+v, want seq 1 at the create entry", registry.URL, head)
	}
	if pin := pins.Pins[id.stableID]; pin == nil || pin.LogSeq != 0 || pin.LogEntryHash != "" {
		t.Fatalf("pin=%+v: the pin keeps only the key binding", pin)
	}
}

func TestPinAnchorIsCarriedToTheRegistryItVerifiesAt(t *testing.T) {
	id := newCheckpointIdentity(t)
	registry := identityRegistry(t, id, id.newDID, id.create, id.rotate)
	pins := NewPinStore()
	pinFor(pins, id, id.newDID)
	pins.Pins[id.stableID].LogSeq, pins.Pins[id.stableID].LogEntryHash = 2, id.rotate.EntryHash
	c := checkpointClient(t, registry, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", id.newDID, id.stableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified", status)
	}
	if head := checkpointsOf(t, pins)[registry.URL][id.stableID]; head == nil || head.Seq != 2 {
		t.Fatalf("checkpoint=%+v, want the carried seq 2", head)
	}
	if pin := pins.Pins[id.stableID]; pin.LogSeq != 0 || pin.LogEntryHash != "" {
		t.Fatalf("pin=%+v: a carried anchor leaves the pin", pin)
	}
}

func TestPinAnchorRefusesARollbackAndIsKept(t *testing.T) {
	id := newCheckpointIdentity(t)
	registry := identityRegistry(t, id, id.oldDID, id.create)
	pins := NewPinStore()
	pinFor(pins, id, id.newDID)
	pins.Pins[id.stableID].LogSeq, pins.Pins[id.stableID].LogEntryHash = 2, id.rotate.EntryHash
	c := checkpointClient(t, registry, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", id.oldDID, id.stableID, nil, nil, nil)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want identity_mismatch for a log rolled back behind the anchor", status)
	}
	if pin := pins.Pins[id.stableID]; pin.LogSeq != 2 || pin.LogEntryHash != id.rotate.EntryHash {
		t.Fatalf("pin=%+v: an anchor that did not verify is kept", pin)
	}
}

func TestRegistryMoveStartsANewCheckpoint(t *testing.T) {
	id := newCheckpointIdentity(t)
	moved := identityRegistry(t, id, id.newDID, id.create, id.rotate)
	pins := NewPinStore()
	pinFor(pins, id, id.newDID)
	setCheckpoint(t, pins, "https://old-registry.example", id.stableID, id.rotate, id.newDID)
	c := checkpointClient(t, moved, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", id.newDID, id.stableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified", status)
	}
	heads := checkpointsOf(t, pins)
	if head := heads[moved.URL][id.stableID]; head == nil || head.Seq != 2 {
		t.Fatalf("checkpoint at the new registry=%+v, want seq 2", head)
	}
	if head := heads["https://old-registry.example"][id.stableID]; head == nil || head.Seq != 2 || head.EntryHash != id.rotate.EntryHash {
		t.Fatalf("the old registry's checkpoint changed: %+v", head)
	}
}

func TestNewRegistryPresentingAnOlderKeyThanThePinIsAMismatch(t *testing.T) {
	id := newCheckpointIdentity(t)
	moved := identityRegistry(t, id, id.oldDID, id.create)
	pins := NewPinStore()
	pinFor(pins, id, id.newDID)
	setCheckpoint(t, pins, "https://old-registry.example", id.stableID, id.rotate, id.newDID)
	c := checkpointClient(t, moved, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", id.oldDID, id.stableID, nil, nil, nil)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want identity_mismatch: a new registry's key other than the pinned one", status)
	}
	if pins.Pins[id.stableID].DIDKey != id.newDID {
		t.Fatalf("the pin moved back to the older key: %+v", pins.Pins[id.stableID])
	}
}

// checkpointSeq is the sequence an identity's checkpoint holds at whichever
// registry has one (0 when none does).
func checkpointHead(t *testing.T, pins *PinStore, stableID string) VerifiedLogHead {
	t.Helper()
	var latest VerifiedLogHead
	for _, identities := range checkpointsOf(t, pins) {
		if head := identities[stableID]; head != nil && head.Seq > latest.Seq {
			latest = *head
		}
	}
	return latest
}
