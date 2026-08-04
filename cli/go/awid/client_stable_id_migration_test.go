package awid

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A stable id is one key and a pin carries one address, so an identity reachable
// at a second address cannot be migrated onto a stable-id key that already holds
// a pin for another address. Migrating anyway overwrites that pin, and the store
// it produces is one this package's own loader refuses.
//
// The sequence below is three ordinary messages, all verified: first contact at
// one address carrying the stable id, first contact at a second address before
// the stable id is published, then a later message from the second address once
// it is.

func migrationClient(t *testing.T, path string) (*Client, *PinStore) {
	t.Helper()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, path)
	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{Outcome: StableIdentityDegraded},
	})
	return c, ps
}

const (
	migrationDID      = "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"
	migrationOtherDID = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP"
	migrationStableID = "did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t"
)

// seeAtBothAddresses drives the two ordinary first contacts that leave the same
// agent pinned under its stable id at one address and its did:key at another.
func seeAtBothAddresses(t *testing.T, c *Client) {
	t.Helper()

	ctx := context.Background()
	c.NormalizeSenderTrust(ctx, Verified, "acme.com/bob", migrationDID, migrationStableID, nil, nil, nil)
	c.NormalizeSenderTrust(ctx, Verified, "acme.com/alice", migrationDID, "", nil, nil, nil)
}

func TestStableIDMigrationKeepsBothPinsWhenTheKeyIsOccupied(t *testing.T) {
	t.Parallel()

	c, ps := migrationClient(t, "")
	seeAtBothAddresses(t, c)

	c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", migrationDID, migrationStableID, nil, nil, nil)

	if pin, ok := ps.Pins[migrationStableID]; !ok || pin.Address != "acme.com/bob" {
		t.Fatalf("the stable-id pin was destroyed or moved: %+v", ps.Pins[migrationStableID])
	}
	if pin, ok := ps.Pins[migrationDID]; !ok || pin.Address != "acme.com/alice" {
		t.Fatalf("the did:key pin was destroyed or moved: %+v", ps.Pins[migrationDID])
	}

	data, err := ps.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePinStore(data); err != nil {
		t.Fatalf("the store this wrote cannot be loaded back: %v", err)
	}
}

// The verdict at the second address is the second-order effect of declining:
// the reverse entry there still points at the did:key, so the check must be made
// against the did:key and not the stable id, or a legitimate agent is reported
// as an identity mismatch.
func TestStableIDMigrationDeclinedStillVerifiesTheSecondAddress(t *testing.T) {
	t.Parallel()

	c, _ := migrationClient(t, "")
	seeAtBothAddresses(t, c)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", migrationDID, migrationStableID, nil, nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q: declining the migration must not fail a legitimate sender", status, Verified)
	}
}

func TestStableIDMigrationDeclinedStoreSurvivesRestart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "known_agents.yaml")
	c, _ := migrationClient(t, path)
	seeAtBothAddresses(t, c)
	c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", migrationDID, migrationStableID, nil, nil, nil)

	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("nothing was persisted: %v", err)
	}
	reloaded, err := LoadPinStore(path)
	if err != nil {
		t.Fatalf("the next start cannot load the store: %v", err)
	}
	if got := reloaded.CheckPin("acme.com/bob", migrationStableID, IdentityModeGlobal); got != PinOK {
		t.Fatalf("CheckPin(bob)=%v, want %v: the pin for the first address was lost", got, PinOK)
	}
	if got := reloaded.CheckPin("acme.com/alice", migrationDID, IdentityModeGlobal); got != PinOK {
		t.Fatalf("CheckPin(alice)=%v, want %v", got, PinOK)
	}
}

// The action is the same whenever the key is occupied; the reported reason is
// not, because the operator situations differ. An occupant proven to be the same
// identity is benign, a different one is a conflict, and one that cannot be
// classified is repairable by recording its did:key.
func TestStableIDMigrationReportsWhyItDeclined(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		occupantDID string
		wantOutcome PinMigrationOutcome
	}{
		{"same identity at two addresses", migrationDID, PinMigrationSameIdentity},
		{"a different identity holds the stable id", migrationOtherDID, PinMigrationConflict},
		{"occupant did:key not recorded", "", PinMigrationUnclassifiable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, ps := migrationClient(t, "")
			ps.StorePin(migrationStableID, "acme.com/bob", "", "")
			ps.Pins[migrationStableID].StableID = migrationStableID
			ps.Pins[migrationStableID].DIDKey = tc.occupantDID
			ps.StorePin(migrationDID, "acme.com/alice", "", "")

			var got []PinMigrationDecline
			c.SetPinMigrationObserver(func(d PinMigrationDecline) { got = append(got, d) })

			c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", migrationDID, migrationStableID, nil, nil, nil)

			if len(got) != 1 {
				t.Fatalf("observer calls=%d, want exactly 1", len(got))
			}
			if got[0].Outcome != tc.wantOutcome {
				t.Fatalf("outcome=%q, want %q", got[0].Outcome, tc.wantOutcome)
			}
			if got[0].StableID != migrationStableID || got[0].Address != "acme.com/alice" {
				t.Fatalf("decline does not identify the situation: %+v", got[0])
			}
		})
	}
}
