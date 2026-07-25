package awid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The trust database must fail closed: anything other than a genuinely absent
// file has to surface as an error rather than silently becoming an empty store,
// because an empty store reopens first-contact TOFU for every known identity.
// These mirror the checks channel-core's PinStore.fromYAML already enforces, so
// Go and Node agree on the shared ~/.config/aw/known_agents.yaml (default-aajc.9).

func writeStore(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustFailLoad(t *testing.T, content, wantSubstring string) {
	t.Helper()
	ps, err := LoadPinStore(writeStore(t, content))
	if err == nil {
		t.Fatalf("expected load to fail closed, got a usable store with %d pins", len(ps.Pins))
	}
	if wantSubstring != "" && !strings.Contains(err.Error(), wantSubstring) {
		t.Errorf("error %q does not mention %q", err.Error(), wantSubstring)
	}
}

func TestLoadPinStoreRejectsPresentButEmptyDocument(t *testing.T) {
	// An intentional empty store is written as "pins: {}\naddresses: {}".
	// A zero-length or whitespace-only file is truncation or corruption.
	mustFailLoad(t, "", "empty")
	mustFailLoad(t, "   \n   \n", "empty")
	mustFailLoad(t, "# only a comment\n", "empty")
	mustFailLoad(t, "null\n", "empty")
	// A tab is not legal YAML indentation; it must still fail closed, though it
	// is reported as a parse error rather than an empty document.
	mustFailLoad(t, "\t\n", "")
}

func TestLoadPinStoreRejectsNonMappingRoot(t *testing.T) {
	mustFailLoad(t, "- a\n- b\n", "mapping")
	mustFailLoad(t, "just a string\n", "mapping")
}

func TestLoadPinStoreRejectsDanglingReverseIndex(t *testing.T) {
	mustFailLoad(t,
		"pins: {}\naddresses:\n  alice@example.com: did:key:zMissing\n",
		"unknown pin")
}

// Two pins claiming one address is an unresolved identity conflict; resolving it
// by map-iteration order would pick a trust anchor at random.
func TestLoadPinStoreRejectsDuplicateAddressOwnership(t *testing.T) {
	mustFailLoad(t,
		"pins:\n"+
			"  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\n"+
			"  did:key:zB:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\n"+
			"addresses:\n  alice@example.com: did:key:zA\n",
		"claimed by two pins")
}

func TestLoadPinStoreRejectsDuplicateKeys(t *testing.T) {
	mustFailLoad(t,
		"pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n  did:key:zA:\n    address: d@e.f\n    first_seen: t\n    last_seen: t\naddresses: {}\n",
		"")
}

func TestLoadPinStoreRejectsMalformedPins(t *testing.T) {
	base := "addresses: {}\n"
	// pins must be a mapping
	mustFailLoad(t, "pins: [1,2]\n"+base, "mapping")
	// a pin must be a mapping
	mustFailLoad(t, "pins:\n  did:key:zA: notamapping\n"+base, "mapping")
	// required fields must be present and non-empty
	mustFailLoad(t, "pins:\n  did:key:zA:\n    first_seen: t\n    last_seen: t\n"+base, "address")
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: \"\"\n    first_seen: t\n    last_seen: t\n"+base, "address")
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: a@b.c\n    last_seen: t\n"+base, "first_seen")
	// an empty pin key is meaningless
	mustFailLoad(t, "pins:\n  \"\":\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n"+base, "empty pin key")
	// log_seq is an anti-rollback checkpoint; a non-positive or non-integer
	// value must not silently become zero.
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n    log_seq: 0\n"+base, "log_seq")
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n    log_seq: notanumber\n"+base, "log_seq")
}

func TestLoadPinStoreRejectsMalformedAddresses(t *testing.T) {
	pins := "pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n"
	mustFailLoad(t, pins+"addresses: [1,2]\n", "mapping")
	mustFailLoad(t, pins+"addresses:\n  a@b.c: \"\"\n", "non-empty")
	mustFailLoad(t, pins+"addresses:\n  \"\": did:key:zA\n", "empty address key")
}

func TestLoadPinStoreRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	big := make([]byte, maxPinStoreBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinStore(path); err == nil {
		t.Fatal("expected oversized trust store to be refused")
	} else if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error %q does not mention size", err.Error())
	}
}

func TestLoadPinStoreRejectsUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := writeStore(t, "pins: {}\naddresses: {}\n")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := LoadPinStore(path); err == nil {
		t.Fatal("expected an unreadable trust store to fail closed, not read as empty")
	}
}

// The forward-compatibility counterpart to the strictness above: a pin field
// added by a newer client must NOT brick an older one. default-aajc.8 added
// log_seq and log_entry_hash to this very struct; had the loader rejected
// unknown fields, every older binary would have refused to start against a
// store a newer binary had touched. channel-core's validatePin ignores unknown
// fields for the same reason, and the two must agree on a shared file.
func TestLoadPinStoreIgnoresUnknownFields(t *testing.T) {
	path := writeStore(t,
		"pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: t\n    last_seen: t\n    field_from_a_newer_client: 1\naddresses:\n  a@b.c: did:key:zA\nroot_from_a_newer_client: x\n")
	ps, err := LoadPinStore(path)
	if err != nil {
		t.Fatalf("unknown fields must not brick an older client: %v", err)
	}
	if ps.CheckPin("a@b.c", "did:key:zA", LifetimePersistent) != PinOK {
		t.Error("pin did not survive a store containing unknown fields")
	}
}

// Absent is the only case that legitimately yields a fresh empty store.
func TestLoadPinStoreAbsentFileIsFreshStore(t *testing.T) {
	ps, err := LoadPinStore(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("absent store must be a fresh first run: %v", err)
	}
	if len(ps.Pins) != 0 || len(ps.Addresses) != 0 {
		t.Error("absent store should be empty")
	}
}

// Whatever we write must load back; strictness that rejects our own output
// would brick every client on first save.
func TestLoadPinStoreAcceptsOwnOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_agents.yaml")

	empty := NewPinStore()
	if err := empty.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinStore(path); err != nil {
		t.Fatalf("an intentionally empty store must round-trip: %v", err)
	}

	ps := NewPinStore()
	ps.StorePin("did:key:zAlice", "alice@example.com", "alice", "")
	ps.Pins["did:key:zAlice"].StableID = "did:aw:alice"
	ps.Pins["did:key:zAlice"].DIDKey = "did:key:zAlice"
	ps.Pins["did:key:zAlice"].LogSeq = 3
	ps.Pins["did:key:zAlice"].LogEntryHash = "hash"
	if err := ps.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := LoadPinStore(path)
	if err != nil {
		t.Fatalf("a populated store must round-trip: %v", err)
	}
	if back.CheckPin("alice@example.com", "did:key:zAlice", LifetimePersistent) != PinOK {
		t.Error("round-tripped pin did not verify")
	}
	if back.Pins["did:key:zAlice"].LogSeq != 3 {
		t.Error("log_seq anti-rollback checkpoint did not survive the round trip")
	}
}
