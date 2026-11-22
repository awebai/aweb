package awid

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withCheckpoint(t *testing.T, ps *PinStore, registry, stableID string, head VerifiedLogHead) *PinStore {
	t.Helper()
	heads := map[string]map[string]*VerifiedLogHead{}
	if raw, ok := ps.unknown[receivedHeadsField]; ok {
		data, _ := json.Marshal(raw)
		if err := json.Unmarshal(data, &heads); err != nil {
			t.Fatal(err)
		}
	}
	if heads[registry] == nil {
		heads[registry] = map[string]*VerifiedLogHead{}
	}
	heads[registry][stableID] = &head
	data, _ := json.Marshal(heads)
	var plain map[string]any
	if err := json.Unmarshal(data, &plain); err != nil {
		t.Fatal(err)
	}
	if ps.unknown == nil {
		ps.unknown = map[string]any{}
	}
	ps.unknown[receivedHeadsField] = plain
	return ps
}

func roundTrip(t *testing.T, ps *PinStore) *PinStore {
	t.Helper()
	data, err := ps.Encode()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePinStore(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func hash(c string) string { return strings.Repeat(c, 64) }

// Two aw processes on one home each pin the sender they heard from and record
// its checkpoint. Neither touched the other's keys, so both changes are kept.
func TestMergeKeepsBothWritersChangesToDifferentKeys(t *testing.T) {
	base := roundTrip(t, NewPinStore())
	ours := NewPinStore()
	ours.StorePin("did:aw:g2", "head-g2.test/g2", "", "")
	ours = roundTrip(t, withCheckpoint(t, ours, "https://registry", "did:aw:g2", VerifiedLogHead{Seq: 2, EntryHash: hash("a"), CurrentDIDKey: "did:key:zG2"}))
	current := NewPinStore()
	current.StorePin("did:aw:g1", "head-g1.test/g1", "", "")
	current = roundTrip(t, withCheckpoint(t, current, "https://registry", "did:aw:g1", VerifiedLogHead{Seq: 1, EntryHash: hash("b"), CurrentDIDKey: "did:key:zG1"}))

	merged, err := MergePinStoreChanges(base, ours, current)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Addresses["head-g1.test/g1"] != "did:aw:g1" || merged.Addresses["head-g2.test/g2"] != "did:aw:g2" {
		t.Fatalf("both pins should be kept: %#v", merged.Addresses)
	}
	if got := checkpointHead(t, merged, "did:aw:g1"); got.Seq != 1 {
		t.Fatalf("the other writer's checkpoint was lost: %+v", got)
	}
	if got := checkpointHead(t, merged, "did:aw:g2"); got.Seq != 2 {
		t.Fatalf("this writer's checkpoint was lost: %+v", got)
	}
}

func TestMergeRefusesTheSameAddressPinnedToDifferentKeys(t *testing.T) {
	base := roundTrip(t, NewPinStore())
	ours := NewPinStore()
	ours.StorePin("did:key:zAlice", "acme.com/alice", "", "")
	current := NewPinStore()
	current.StorePin("did:key:zMallory", "acme.com/alice", "", "")

	_, err := MergePinStoreChanges(base, roundTrip(t, ours), roundTrip(t, current))
	var conflict *PinStoreConflictError
	if !errors.As(err, &conflict) || !strings.Contains(err.Error(), "acme.com/alice") {
		t.Fatalf("err=%v, want a conflict naming the address", err)
	}
}

func TestMergeKeepsTheHigherCheckpointAndRefusesAFork(t *testing.T) {
	const registry, id = "https://registry", "did:aw:x"
	base := roundTrip(t, withCheckpoint(t, NewPinStore(), registry, id, VerifiedLogHead{Seq: 1, EntryHash: hash("1"), CurrentDIDKey: "did:key:z1"}))
	at := func(seq int, entry string, fetched time.Time) *PinStore {
		return roundTrip(t, withCheckpoint(t, NewPinStore(), registry, id, VerifiedLogHead{Seq: seq, EntryHash: hash(entry), CurrentDIDKey: "did:key:z1", FetchedAt: fetched}))
	}
	now := time.Date(2026, 11, 21, 21, 47, 52, 0, time.UTC)

	for _, tc := range []struct {
		name          string
		ours, current *PinStore
		wantSeq       int
	}{
		{"ours is higher", at(3, "3", now), at(2, "2", now), 3},
		{"theirs is higher", at(2, "2", now), at(3, "3", now), 3},
		{"same entry read twice", at(2, "2", now), at(2, "2", now.Add(time.Second)), 2},
	} {
		merged, err := MergePinStoreChanges(base, tc.ours, tc.current)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := checkpointHead(t, merged, id); got.Seq != tc.wantSeq {
			t.Fatalf("%s: seq=%d, want %d", tc.name, got.Seq, tc.wantSeq)
		}
	}

	_, err := MergePinStoreChanges(base, at(2, "2", now), at(2, "f", now))
	var conflict *PinStoreConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("a fork at the same sequence must be refused, got %v", err)
	}
}

// A pin both writers changed merges field by field: one cleared the log
// anchor it moved into the checkpoint, the other refreshed last_seen.
func TestMergeCombinesDifferentFieldsOfOnePin(t *testing.T) {
	pin := func(seq int, hash, lastSeen string) *PinStore {
		ps := NewPinStore()
		ps.StorePin("did:aw:x", "acme.com/x", "", "")
		ps.Pins["did:aw:x"].LogSeq, ps.Pins["did:aw:x"].LogEntryHash = seq, hash
		ps.Pins["did:aw:x"].FirstSeen, ps.Pins["did:aw:x"].LastSeen = "2026-11-20T00:00:00Z", lastSeen
		return roundTrip(t, ps)
	}
	base := pin(2, hash("2"), "2026-11-21T00:00:00Z")
	ours := pin(0, "", "2026-11-21T21:47:51Z")
	current := pin(2, hash("2"), "2026-11-21T21:47:52Z")

	merged, err := MergePinStoreChanges(base, ours, current)
	if err != nil {
		t.Fatal(err)
	}
	got := merged.Pins["did:aw:x"]
	if got.LogSeq != 0 || got.LogEntryHash != "" || got.LastSeen != "2026-11-21T21:47:52Z" {
		t.Fatalf("merged pin=%+v, want the anchor cleared and the later last_seen", got)
	}

	conflicting := pin(2, hash("2"), "2026-11-21T21:47:52Z")
	conflicting.Pins["did:aw:x"].Server = "https://elsewhere"
	ours.Pins["did:aw:x"].Server = "https://here"
	if _, err := MergePinStoreChanges(base, ours, conflicting); err == nil {
		t.Fatal("a field both writers changed to different values must be refused")
	}
}

// mergingFilePersister is the cross-process protocol aw installs (cmd/aw
// compareAndSetPinStore) without its lock: commit when the precondition holds,
// otherwise merge onto what the other writer committed.
func mergingFilePersister(path string, expectedYAML, desiredYAML []byte) error {
	expected, err := ParsePinStore(expectedYAML)
	if err != nil {
		return err
	}
	desired, err := ParsePinStore(desiredYAML)
	if err != nil {
		return err
	}
	current, err := LoadPinStore(path)
	if err != nil {
		return err
	}
	if !current.SemanticallyEqual(expected) {
		if desired, err = MergePinStoreChanges(expected, desired, current); err != nil {
			return err
		}
	}
	return desired.Save(path)
}

// The run-2e waiting-chat failure: the reply's verification writes pin
// maintenance, then the verified registry head, while another aw process on
// the same home has committed its own pins since this one loaded the store.
// Both writes land and the reply stays verified.
func TestVerifiedReplyStaysVerifiedWhenAnotherWriterChangedTheStore(t *testing.T) {
	f := newDidLogRegistry(t)
	f.pins.StorePin(f.stableID, didLogTestAddress, "", "")
	f.pins.Pins[f.stableID].StableID = f.stableID
	f.pins.Pins[f.stableID].DIDKey = f.did2

	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	if err := f.pins.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	c := f.newClient()
	c.SetPinStore(loaded, path)
	c.SetPinStorePersister(mergingFilePersister)

	other, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	other.StorePin("did:key:zOther", "other.test/peer", "", "")
	if err := other.Save(path); err != nil {
		t.Fatal(err)
	}

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, didLogTestAddress, f.did2, f.stableID, nil, nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
	onDisk, err := LoadPinStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkpointHead(t, onDisk, f.stableID); got.Seq != 2 {
		t.Fatalf("the verified head is not on disk: %+v", got)
	}
	if onDisk.Addresses["other.test/peer"] != "did:key:zOther" {
		t.Fatalf("the other writer's pin was lost: %#v", onDisk.Addresses)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
