package awid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A pin that never reaches disk is not continuity. If a first-contact pin cannot
// be durably committed, the next process sees no pin, treats the sender as first
// contact again, and trusts whoever answers to that address — so the message that
// established the pin must not be reported as verified (default-aajc.9).

// unwritablePinPath returns a path whose parent is a regular file, so every
// attempt to write the store fails deterministically without needing root.
func unwritablePinPath(t *testing.T) string {
	t.Helper()
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(blocker, "known_agents.yaml")
}

func newPinClient(t *testing.T, path string) (*Client, *PinStore) {
	t.Helper()
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, path)
	return c, ps
}

func TestFirstContactPinThatCannotPersistIsNotVerified(t *testing.T) {
	c, ps := newPinClient(t, unwritablePinPath(t))

	const addr = "alice@example.com"
	const did = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

	status := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if status == Verified || status == VerifiedCustodial {
		t.Fatalf("status=%q: a first-contact pin that could not be saved must not be reported verified", status)
	}
	if status != VerificationStale {
		t.Errorf("status=%q, want %q", status, VerificationStale)
	}
	// The in-memory pin is still recorded; only the durability claim failed.
	if _, ok := ps.Pins[did]; !ok {
		t.Error("pin should still be held in memory for this process")
	}
}

func TestFirstContactPinThatPersistsIsVerified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	c, _ := newPinClient(t, path)

	const addr = "alice@example.com"
	const did = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

	status := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q when the pin commits durably", status, Verified)
	}

	// Prove durability against the real file, not the in-memory store.
	reloaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.CheckPin(addr, did, LifetimePersistent) != PinOK {
		t.Error("pin was reported verified but is not on disk")
	}
}

// A save failure that only loses a last_seen refresh is an availability problem,
// not a continuity one: the pin is unchanged and already durable. Downgrading
// here would make every message unverifiable whenever the disk is full.
func TestAlreadyPinnedSenderStaysVerifiedWhenRefreshCannotPersist(t *testing.T) {
	c, ps := newPinClient(t, unwritablePinPath(t))

	const addr = "alice@example.com"
	const did = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"
	ps.StorePin(did, addr, "", "")

	status := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if status != Verified {
		t.Fatalf("status=%q: an unchanged, already-durable pin must stay verified", status)
	}
}

// The anti-rollback checkpoint (default-aajc.8) is security state too. If an
// advanced checkpoint cannot be committed, the next process still holds the
// lower sequence and would accept a log head we have already moved past, so the
// message that advanced it must not be reported verified.
//
// The pin here already matches the incoming key, so no pin record changes and
// the only thing that needs to persist is the checkpoint advance — isolating
// this path from the first-contact and rotation paths above.
func TestAdvancedCheckpointThatCannotPersistIsNotVerified(t *testing.T) {
	f := newDidLogRegistry(t)

	f.pins.StorePin(f.stableID, didLogTestAddress, "", "")
	f.pins.Pins[f.stableID].StableID = f.stableID
	f.pins.Pins[f.stableID].DIDKey = f.did2
	if f.pins.Pins[f.stableID].LogSeq != 0 {
		t.Fatal("fixture must start without a checkpoint")
	}

	c := f.newClient()
	c.SetPinStore(f.pins, unwritablePinPath(t))

	status, _ := c.NormalizeSenderTrust(
		context.Background(), Verified, didLogTestAddress, f.did2, f.stableID, nil, nil, nil,
	)
	if status == Verified || status == VerifiedCustodial {
		t.Fatalf("status=%q: an anti-rollback checkpoint that could not be saved must not be reported verified", status)
	}
}

func TestAdvancedCheckpointThatPersistsIsVerified(t *testing.T) {
	f := newDidLogRegistry(t)

	f.pins.StorePin(f.stableID, didLogTestAddress, "", "")
	f.pins.Pins[f.stableID].StableID = f.stableID
	f.pins.Pins[f.stableID].DIDKey = f.did2

	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	c := f.newClient()
	c.SetPinStore(f.pins, path)

	status, _ := c.NormalizeSenderTrust(
		context.Background(), Verified, didLogTestAddress, f.did2, f.stableID, nil, nil, nil,
	)
	if status != Verified {
		t.Fatalf("status=%q, want %q when the checkpoint commits durably", status, Verified)
	}

	reloaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Pins[f.stableID]; got == nil || got.LogSeq != 2 {
		t.Errorf("checkpoint was reported verified but is not on disk: %+v", got)
	}
}
