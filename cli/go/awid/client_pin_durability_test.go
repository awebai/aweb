package awid

import (
	"context"
	"fmt"
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

func TestClientCASPersisterAdvancesThenRefusesAStaleSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	c, _ := newPinClient(t, path)
	current := NewPinStore()
	c.SetPinStorePersister(func(_ string, expectedYAML, desiredYAML []byte) error {
		expected, err := ParsePinStore(expectedYAML)
		if err != nil {
			return err
		}
		if !current.SemanticallyEqual(expected) {
			return fmt.Errorf("changed since it was read")
		}
		desired, err := ParsePinStore(desiredYAML)
		if err != nil {
			return err
		}
		current = desired
		return nil
	})

	if status := c.CheckTOFUPin(context.Background(), Verified, "alice@example.com", "did:key:zAlice", "", nil, nil); status != Verified {
		t.Fatalf("first status=%q, want verified", status)
	}
	if status := c.CheckTOFUPin(context.Background(), Verified, "carol@example.com", "did:key:zCarol", "", nil, nil); status != Verified {
		t.Fatalf("second status=%q, want verified after advancing the successful baseline", status)
	}
	// A different process commits Bob after this client's baseline was read.
	current.StorePin("did:key:zBob", "bob@example.com", "", "")

	status := c.CheckTOFUPin(context.Background(), Verified, "dave@example.com", "did:key:zDave", "", nil, nil)
	if status != VerificationStale {
		t.Fatalf("stale continuity decision status=%q, want %q", status, VerificationStale)
	}
	if current.CheckPin("bob@example.com", "did:key:zBob", LifetimePersistent) != PinOK {
		t.Fatal("stale writer erased the other process's pin")
	}
	if current.CheckPin("carol@example.com", "did:key:zCarol", LifetimePersistent) != PinOK {
		t.Fatal("second successful mutation was not committed")
	}
	if current.CheckPin("dave@example.com", "did:key:zDave", LifetimePersistent) != PinNew {
		t.Fatal("stale writer's desired mutation reached the durable store")
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

// Reviewer finding (aajc.9a): the first-contact downgrade is not enough on its
// own. After a failed commit the mutated pin is still in memory, so the SECOND
// message from the same sender takes the PinOK path — which treats the pin as
// already durable — and is reported verified while the store does not exist at
// all. The downgrade must persist until the state is actually committed.
func TestSenderStaysUnverifiedWhileTheStoreCannotBeCommitted(t *testing.T) {
	path := unwritablePinPath(t)
	c, _ := newPinClient(t, path)

	const addr = "alice@example.com"
	const did = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

	first := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if first == Verified {
		t.Fatal("first contact with a failed commit must not be verified")
	}

	second := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if second == Verified || second == VerifiedCustodial {
		t.Fatalf("second=%q: the pin is still not on disk, so it is not continuity", second)
	}

	if _, err := os.Stat(path); err == nil {
		t.Fatal("fixture is wrong: the store must not exist")
	}
}

// ...and once the store can be written again, the sender recovers to verified
// without needing a restart.
func TestSenderRecoversOnceTheStoreCanBeCommitted(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := newPinClient(t, filepath.Join(blocked, "known_agents.yaml"))

	const addr = "alice@example.com"
	const did = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

	if status := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil); status == Verified {
		t.Fatal("precondition: the first commit must fail")
	}

	// Clear the obstruction; the same client must be able to commit now.
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	status := c.CheckTOFUPin(context.Background(), Verified, addr, did, "", nil, nil)
	if status != Verified {
		t.Fatalf("status=%q: once the store commits, the sender must verify again", status)
	}
}
