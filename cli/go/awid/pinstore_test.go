package awid

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPinStoreStoreAndCheckRoundtrip(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	ps.StorePin(did, "myco/agent", "@bob", "app.aweb.ai")

	result := ps.CheckPin("myco/agent", did, LifetimePersistent)
	if result != PinOK {
		t.Fatalf("result=%q, want %q", result, PinOK)
	}
}

func TestPinStoreIdentityMismatch(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did1 := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	did2 := "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"

	ps.StorePin(did1, "myco/agent", "@bob", "app.aweb.ai")

	result := ps.CheckPin("myco/agent", did2, LifetimePersistent)
	if result != PinMismatch {
		t.Fatalf("result=%q, want %q", result, PinMismatch)
	}
}

func TestPinStoreEphemeralSkipsPinning(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did1 := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	did2 := "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"

	// Pin under one DID.
	ps.StorePin(did1, "myco/agent", "@bob", "app.aweb.ai")

	// Ephemeral agent with a different DID should not trigger mismatch.
	result := ps.CheckPin("myco/agent", did2, LifetimeEphemeral)
	if result != PinSkipped {
		t.Fatalf("result=%q, want %q", result, PinSkipped)
	}
}

func TestPinStoreUnknownAddressReturnsNew(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	result := ps.CheckPin("myco/agent", did, LifetimePersistent)
	if result != PinNew {
		t.Fatalf("result=%q, want %q", result, PinNew)
	}
}

func TestPinStoreAddressChangeUpdatesReverseIndex(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	ps.StorePin(did, "myco/agent-v1", "@bob", "app.aweb.ai")
	ps.StorePin(did, "myco/agent-v2", "@bob", "app.aweb.ai")

	// New address should resolve to the same DID.
	result := ps.CheckPin("myco/agent-v2", did, LifetimePersistent)
	if result != PinOK {
		t.Fatalf("new address: result=%q, want %q", result, PinOK)
	}

	// Old address should no longer be in the reverse index.
	result = ps.CheckPin("myco/agent-v1", did, LifetimePersistent)
	if result != PinNew {
		t.Fatalf("old address: result=%q, want %q", result, PinNew)
	}
}

func TestPinStoreSaveAndLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "known_agents.yaml")

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	ps.StorePin(did, "myco/agent", "@bob", "app.aweb.ai")

	if err := ps.Save(path); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}

	result := loaded.CheckPin("myco/agent", did, LifetimePersistent)
	if result != PinOK {
		t.Fatalf("result=%q after load, want %q", result, PinOK)
	}

	// Verify reverse index survived.
	result = loaded.CheckPin("myco/agent", "did:key:z6MkDIFFERENT", LifetimePersistent)
	if result != PinMismatch {
		t.Fatalf("result=%q after load, want %q", result, PinMismatch)
	}
}

func TestLoadPinStoreNotFound(t *testing.T) {
	t.Parallel()

	ps, err := LoadPinStore("/nonexistent/path/known_agents.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Should return an empty store, not error.
	if len(ps.Pins) != 0 {
		t.Fatalf("expected empty pins, got %d", len(ps.Pins))
	}
}

func TestPinStoreLastSeenUpdated(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	ps.StorePin(did, "myco/agent", "@bob", "app.aweb.ai")

	// Backdate first_seen so the next StorePin produces a different last_seen.
	ps.Pins[did].FirstSeen = "2020-01-01T00:00:00Z"
	ps.Pins[did].LastSeen = "2020-01-01T00:00:00Z"

	ps.StorePin(did, "myco/agent", "@bob", "app.aweb.ai")
	if ps.Pins[did].FirstSeen != "2020-01-01T00:00:00Z" {
		t.Fatal("first_seen should not change on update")
	}
	if ps.Pins[did].LastSeen == "2020-01-01T00:00:00Z" {
		t.Fatal("last_seen should be updated")
	}
}

func TestPinStoreSaveCreatesParentDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "known_agents.yaml")

	ps := NewPinStore()
	ps.StorePin("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "myco/agent", "@bob", "app.aweb.ai")

	if err := ps.Save(path); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestPinStoreSaveFilePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "known_agents.yaml")

	ps := NewPinStore()
	ps.StorePin("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "myco/agent", "@bob", "app.aweb.ai")

	if err := ps.Save(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Pin store contains identity data — should be owner-only read/write.
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions=%o, want 0600", perm)
	}
}

func TestPinStoreRemoveAddress(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	ps.StorePin(did, "myco/agent", "@bob", "app.aweb.ai")

	if !ps.RemoveAddress("myco/agent") {
		t.Fatal("expected address removal")
	}
	if _, ok := ps.Addresses["myco/agent"]; ok {
		t.Fatal("address index should be removed")
	}
	if _, ok := ps.Pins[did]; ok {
		t.Fatal("pin should be removed")
	}
}
