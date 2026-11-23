package awid

import (
	"context"
	"testing"
)

// A sender known only by its member name is pinned under team/name: member
// names are team-scoped (docs/identity.md:93-107), so the namespace/name form
// collides with an address and with the same name in another team of the
// namespace (Antares d0e3fe47 item 2). A pin under the earlier
// namespace/name key moves to team/name only when the team roster names that
// pin's identity for the name; otherwise it is kept and reported.
const (
	aliasPinTeam         = "backend:acme.com"
	aliasPinTeamKey      = "backend:acme.com/bob"
	aliasPinNamespaceKey = "acme.com/bob"
	aliasPinDID          = "did:key:zBobCurrent"
	aliasPinStableID     = "did:aw:bobStable"
	otherStableID        = "did:aw:someoneElse"
)

func aliasPinClient(t *testing.T, pins *PinStore) (*Client, *[]PinMigrationDecline) {
	t.Helper()
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	c.SetAddress("acme.com/ada")
	c.teamID = aliasPinTeam
	c.SetPinStore(pins, "")
	roster := &ResolvedIdentity{DID: aliasPinDID, StableID: aliasPinStableID, IdentityScope: IdentityModeGlobal, Custody: CustodySelf, ResolvedVia: "team_roster"}
	c.SetResolver(&localFreshResolver{cached: roster, fresh: roster})
	declines := &[]PinMigrationDecline{}
	c.SetPinMigrationObserver(func(d PinMigrationDecline) { *declines = append(*declines, d) })
	return c, declines
}

func TestAliasOnlySenderIsPinnedUnderTeamAndName(t *testing.T) {
	pins := NewPinStore()
	c, _ := aliasPinClient(t, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "bob", aliasPinDID, aliasPinStableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified", status)
	}
	if pins.Addresses[aliasPinTeamKey] != aliasPinStableID {
		t.Fatalf("pins by key=%v, want %s under %s", pins.Addresses, aliasPinStableID, aliasPinTeamKey)
	}
	if _, ok := pins.Addresses[aliasPinNamespaceKey]; ok {
		t.Fatalf("pinned under the namespace form too: %v", pins.Addresses)
	}
}

func TestAliasPinMovesToTeamKeyWhenTheRosterNamesItsIdentity(t *testing.T) {
	pins := NewPinStore()
	pins.StorePin(aliasPinStableID, aliasPinNamespaceKey, "", "")
	pins.Pins[aliasPinStableID].StableID = aliasPinStableID
	pins.Pins[aliasPinStableID].DIDKey = aliasPinDID
	c, declines := aliasPinClient(t, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "bob", aliasPinDID, aliasPinStableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified", status)
	}
	if pins.Addresses[aliasPinTeamKey] != aliasPinStableID || pins.Pins[aliasPinStableID].Address != aliasPinTeamKey {
		t.Fatalf("pin not moved to %s: addresses=%v pin=%+v", aliasPinTeamKey, pins.Addresses, pins.Pins[aliasPinStableID])
	}
	if _, ok := pins.Addresses[aliasPinNamespaceKey]; ok {
		t.Fatalf("namespace key kept after the move: %v", pins.Addresses)
	}
	if len(*declines) != 0 {
		t.Fatalf("declines=%+v, want none", *declines)
	}
}

func TestAliasPinStaysAndIsReportedWhenTheRosterNamesAnotherIdentity(t *testing.T) {
	pins := NewPinStore()
	pins.StorePin(otherStableID, aliasPinNamespaceKey, "", "")
	pins.Pins[otherStableID].StableID = otherStableID
	pins.Pins[otherStableID].DIDKey = "did:key:zSomeoneElse"
	c, declines := aliasPinClient(t, pins)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, "bob", aliasPinDID, aliasPinStableID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want verified: the team key has no pin yet", status)
	}
	if pins.Addresses[aliasPinNamespaceKey] != otherStableID {
		t.Fatalf("the unconfirmed namespace-key pin was dropped or changed: %v", pins.Addresses)
	}
	if len(*declines) != 1 || (*declines)[0].Outcome != PinMigrationTeamUnconfirmed || (*declines)[0].Address != aliasPinNamespaceKey {
		t.Fatalf("declines=%+v, want one %q report for %s", *declines, PinMigrationTeamUnconfirmed, aliasPinNamespaceKey)
	}
}
