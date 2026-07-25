package awid

import (
	"os"
	"path/filepath"
	"testing"
)

// Repro for default-aajc.9. These document CURRENT (broken) behaviour so the
// failure is observed before the fix. Delete once the guards land.

func TestReproPresentButEmptyFileAcceptedAsEmptyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadPinStore(path)
	if err != nil {
		t.Logf("FIXED: present-but-empty rejected: %v", err)
		return
	}
	t.Errorf("REPRO: present-but-empty file accepted as empty trust store (pins=%d) — TOFU reopens", len(ps.Pins))
}

func TestReproDanglingAddressIndexAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	// addresses points at a pin key that does not exist in pins.
	content := "pins: {}\naddresses:\n  alice@example.com: did:key:zMissing\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	ps, err := LoadPinStore(path)
	if err != nil {
		t.Logf("FIXED: dangling reverse index rejected: %v", err)
		return
	}
	res := ps.CheckPin("alice@example.com", "did:key:zAttacker", LifetimePersistent)
	t.Errorf("REPRO: dangling reverse index accepted; CheckPin returns %q against an unknown pin", res)
}

func TestReproUnknownFieldsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	content := "pins:\n  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\n    server: s\n    bogus_unknown_field: 1\naddresses:\n  alice@example.com: did:key:zA\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinStore(path); err != nil {
		t.Logf("FIXED: unknown field rejected: %v", err)
		return
	}
	t.Error("REPRO: unknown field accepted by permissive YAML decode")
}

func TestReproTwoWriterLostPin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")

	// A and B both load the (absent) store, then each pin a distinct address.
	a, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a.StorePin("did:key:zAlice", "alice@example.com", "alice", "s")
	b.StorePin("did:key:zBob", "bob@example.com", "bob", "s")

	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := b.Save(path); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, haveAlice := reloaded.Pins["did:key:zAlice"]
	_, haveBob := reloaded.Pins["did:key:zBob"]
	if haveAlice && haveBob {
		t.Logf("FIXED: both pins survived concurrent writers")
		return
	}
	t.Errorf("REPRO: lost pin after two writers — alice=%v bob=%v; the lost identity reopens TOFU", haveAlice, haveBob)
}
