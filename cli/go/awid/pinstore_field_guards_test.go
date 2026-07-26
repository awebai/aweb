package awid

import (
	"strings"
	"testing"
)

// ParsePinStore checks the forward and reverse indexes agree in both directions
// after every per-field guard has run. That check rejects most malformed stores
// on its own, so a fixture whose index does not already agree measures the index
// check rather than the field guard: remove the field guard and the store is
// still refused, just with a different message.
//
// Every fixture here is index-consistent, so removing the guard under test lets
// the store LOAD, which is the failure that matters — a trust database that
// silently accepts a rolled-back checkpoint or a type-coerced field.
// TestConsistentPinStoreLoadsCleanly pins the shared base, and each guard test
// changes exactly one field of it.

type pinFixture struct {
	address   string
	handle    string
	firstSeen string
	lastSeen  string
	extra     []string
}

func validPin() pinFixture {
	return pinFixture{
		address:   "a@b.c",
		handle:    "'@alice'",
		firstSeen: "'2026-02-22T10:00:00Z'",
		lastSeen:  "'2026-02-22T11:00:00Z'",
	}
}

func (f pinFixture) render() string {
	lines := []string{
		"pins:",
		"  did:key:zA:",
		"    address: " + f.address,
		"    handle: " + f.handle,
		"    first_seen: " + f.firstSeen,
		"    last_seen: " + f.lastSeen,
	}
	for _, extra := range f.extra {
		lines = append(lines, "    "+extra)
	}
	lines = append(lines, "addresses:", "  a@b.c: did:key:zA", "")
	return strings.Join(lines, "\n")
}

// rejectsPin asserts the store is refused for the reason named, not by a
// neighbouring check that happens to refuse the same fixture.
func rejectsPin(t *testing.T, f pinFixture, wantSubstring string) {
	t.Helper()

	ps, err := ParsePinStore([]byte(f.render()))
	if err == nil {
		t.Fatalf("store loaded with %d pins, want a load failure: the guard no longer rejects this field", len(ps.Pins))
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("error %q does not mention %q: the store was refused, but by a different check", err.Error(), wantSubstring)
	}
}

func TestConsistentPinStoreLoadsCleanly(t *testing.T) {
	t.Parallel()

	ps, err := ParsePinStore([]byte(validPin().render()))
	if err != nil {
		t.Fatalf("ParsePinStore: %v", err)
	}
	if got := ps.Pins["did:key:zA"]; got == nil || got.Address != "a@b.c" {
		t.Fatalf("pin=%+v, want the fixture pin", got)
	}
	if ps.Addresses["a@b.c"] != "did:key:zA" {
		t.Fatalf("addresses=%v, want a consistent reverse index", ps.Addresses)
	}
}

// log_seq is the anti-rollback checkpoint. Without the guard, log_seq: 0 loads
// as an absent checkpoint and the rollback it exists to refuse goes unnoticed.
func TestPinStoreRejectsNonPositiveLogSeq(t *testing.T) {
	t.Parallel()

	f := validPin()
	f.extra = []string{"log_seq: 0"}
	rejectsPin(t, f, "log_seq")

	f.extra = []string{"log_seq: -1"}
	rejectsPin(t, f, "log_seq")
}

// The guard reads the raw node because an explicit 0 and an absent field are
// indistinguishable once decoded; a non-integer must not decode to that same 0.
func TestPinStoreRejectsNonIntegerLogSeq(t *testing.T) {
	t.Parallel()

	f := validPin()
	f.extra = []string{"log_seq: notanumber"}
	rejectsPin(t, f, "log_seq")

	f.extra = []string{"log_seq: '3'"}
	rejectsPin(t, f, "log_seq")
}

// requireString refuses coercion so Go and Node agree on a shared file: yaml.v3
// would happily read 42 as the string "42" where Node's JSON_SCHEMA keeps it a
// number, and the two runtimes would then hold different pins.
func TestPinStoreRejectsCoercedStringField(t *testing.T) {
	t.Parallel()

	f := validPin()
	f.handle = "42"
	rejectsPin(t, f, "must be a string")

	f = validPin()
	f.handle = "true"
	rejectsPin(t, f, "must be a string")
}

func TestPinStoreRejectsEmptyFirstSeen(t *testing.T) {
	t.Parallel()

	f := validPin()
	f.firstSeen = "''"
	rejectsPin(t, f, "first_seen")
}

func TestPinStoreRejectsEmptyLastSeen(t *testing.T) {
	t.Parallel()

	f := validPin()
	f.lastSeen = "''"
	rejectsPin(t, f, "last_seen")
}
