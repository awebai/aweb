package awid

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
		"reverse index")
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

// Unknown fields are PRESERVED, not dropped and not refused. Dropping them looks
// like tolerance but is silent data destruction: Save marshals only today's
// schema, so an older binary would erase whatever a newer one stored. For
// something like an anti-rollback anchor that is the aajc.8 failure again, with
// no error anywhere. Refusing outright would instead brick an older binary, and
// with aw, channel-core and pi on independent release trains that is a real cost.
// Preserving keeps both properties.
//
// The round trip goes through the production LoadPinStore and Save, and asserts
// the reparsed values are deep-equal — key order and formatting may differ.
func TestUnknownFieldsSurviveALoadSaveRoundTrip(t *testing.T) {
	original := "pins:\n" +
		"  did:key:zA:\n" +
		"    address: a@b.c\n" +
		"    first_seen: t\n" +
		"    last_seen: t\n" +
		"    future_scalar: deadbeef\n" +
		"    future_mapping:\n      nested: 1\n      deeper:\n        leaf: x\n" +
		"    future_sequence:\n      - one\n      - two\n" +
		"addresses:\n  a@b.c: did:key:zA\n" +
		"future_root_scalar: rootvalue\n" +
		"future_root_mapping:\n  k: v\n" +
		"future_root_sequence:\n  - a\n  - b\n"

	path := writeStore(t, original)
	ps, err := LoadPinStore(path)
	if err != nil {
		t.Fatalf("a store with unknown fields must load: %v", err)
	}
	if err := ps.Save(path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPinStore(path); err != nil {
		t.Fatalf("the saved store must load again: %v", err)
	}

	before := decodeYAML(t, []byte(original))
	after := decodeYAML(t, readFileForTest(t, path))

	for _, key := range []string{"future_root_scalar", "future_root_mapping", "future_root_sequence"} {
		if !reflect.DeepEqual(before[key], after[key]) {
			t.Errorf("root %q was not preserved: before=%#v after=%#v", key, before[key], after[key])
		}
	}
	pinBefore := before["pins"].(map[string]any)["did:key:zA"].(map[string]any)
	pinAfter := after["pins"].(map[string]any)["did:key:zA"].(map[string]any)
	for _, key := range []string{"future_scalar", "future_mapping", "future_sequence"} {
		if !reflect.DeepEqual(pinBefore[key], pinAfter[key]) {
			t.Errorf("pin field %q was not preserved: before=%#v after=%#v", key, pinBefore[key], pinAfter[key])
		}
	}
	// The known schema must still be intact alongside them.
	if pinAfter["address"] != "a@b.c" {
		t.Errorf("known field damaged: %#v", pinAfter["address"])
	}
}

func decodeYAML(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func readFileForTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A merge key would let one mapping pull in another's fields — a schema hole,
// and the shape behind the js-yaml merge-key advisories.
func TestLoadPinStoreRejectsMergeKeys(t *testing.T) {
	mustFailLoad(t,
		"defaults: &d\n  address: a@b.c\npins:\n  did:key:zA:\n    <<: *d\n    first_seen: t\n    last_seen: t\naddresses: {}\n",
		"merge key")
	mustFailLoad(t,
		"defaults: &d\n  x: 1\n<<: *d\npins: {}\naddresses: {}\n",
		"merge key")
}

// yaml.v3 coerces scalars and honours custom tags; channel-core's JSON_SCHEMA
// loader does neither. Validating decoded struct fields would accept all of
// these, so the check has to happen on the raw node.
func TestLoadPinStoreRejectsCoercedTypesAndCustomTags(t *testing.T) {
	tail := "    first_seen: t\n    last_seen: t\naddresses: {}\n"
	// A numeric address must not silently become the string "123".
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: 123\n"+tail, "must be a string")
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: a@b.c\n    handle: 123\n"+tail, "must be a string")
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: true\n"+tail, "must be a string")
	// Custom tags are not part of the format.
	mustFailLoad(t, "pins:\n  did:key:zA:\n    address: !evil x\n"+tail, "must be a string")
	mustFailLoad(t, "pins:\n  did:key:zA: !evil\n    address: a@b.c\n"+tail, "must be a mapping")
	mustFailLoad(t, "pins: !evil\n  did:key:zA:\n    address: a@b.c\n"+tail, "must be a mapping")
}

// An unquoted RFC3339 timestamp resolves to !!timestamp, not !!str, and those
// are the values we write ourselves — so type strictness must not reject them.
func TestLoadPinStoreAcceptsUnquotedTimestamps(t *testing.T) {
	path := writeStore(t,
		"pins:\n  did:key:zA:\n    address: a@b.c\n    first_seen: 2026-04-26T00:00:00Z\n    last_seen: 2026-04-26T00:00:00Z\naddresses:\n  a@b.c: did:key:zA\n")
	ps, err := LoadPinStore(path)
	if err != nil {
		t.Fatalf("unquoted RFC3339 timestamps must load: %v", err)
	}
	if ps.Pins["did:key:zA"].FirstSeen != "2026-04-26T00:00:00Z" {
		t.Errorf("timestamp mangled: %q", ps.Pins["did:key:zA"].FirstSeen)
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

// Reviewer finding (aajc.9a): validating only reverse->pin existence leaves the
// forward direction unchecked. A pin whose address has no reverse entry makes
// CheckPin return "new" for an address we DO hold a pin for — first-contact TOFU
// against a known identity — and a reverse entry pointing at the wrong address is
// equally inconsistent. The index must agree in both directions.
func TestLoadPinStoreRejectsMissingReverseEntry(t *testing.T) {
	mustFailLoad(t,
		"pins:\n  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\naddresses: {}\n",
		"reverse")
}

func TestLoadPinStoreRejectsWrongReverseAddress(t *testing.T) {
	mustFailLoad(t,
		"pins:\n  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\n"+
			"addresses:\n  mallory@example.com: did:key:zA\n",
		"reverse")
}

// Reviewer finding (aajc.9a): decoding one document and ignoring the rest lets a
// file whose FIRST document is an empty store and whose second holds the real
// pins load as zero pins. js-yaml's load throws on multi-document input, so
// accepting it also diverges from Node on the shared file.
func TestLoadPinStoreRejectsTrailingDocuments(t *testing.T) {
	mustFailLoad(t,
		"pins: {}\naddresses: {}\n---\n"+
			"pins:\n  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\n"+
			"addresses:\n  alice@example.com: did:key:zA\n",
		"single document")
}
