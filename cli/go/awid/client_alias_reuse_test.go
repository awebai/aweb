package awid

import (
	"context"
	"strings"
	"testing"
)

// An alias reissued to a new keypair leaves the previous holder's binding in the
// store, and the next holder is then reported as an identity mismatch on every
// message it sends (aweb-aava). These fixtures all reuse a name ALREADY PINNED to
// the previous holder's key: a fresh unused alias cannot fail for the right
// reason, because it has no previous holder to be confused with.
//
// The three cases separate disagreement from pinned-ness, which is the precision
// the defect is easy to lose. A pin that AGREES verifies (case 2), so "pinned"
// is not the discriminator; only a pin that DISAGREES with the key the sender
// presents flags the message.
const (
	reuseAddress       = "default:acme.com/reissued"
	previousHolderKey  = "did:key:zPreviousHolder"
	currentHolderKey   = "did:key:zCurrentHolder"
	previousHolderStID = "did:aw:previousHolderStableID"
	currentHolderStID  = "did:aw:currentHolderStableID"
)

// A global alias whose pin names the previous holder flags the current holder.
// This is the defect's mechanism stated positively: the pin is doing its job,
// and an alias reissue is one principal taking over an address from another.
func TestAliasReuseDisagreeingPinFlagsGlobalSender(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	pins.StorePin(previousHolderStID, reuseAddress, "", "")
	c.SetPinStore(pins, "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeGlobal, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeGlobal, Custody: CustodySelf},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, reuseAddress,
		currentHolderKey, currentHolderStID, nil, nil, nil)

	if status != IdentityMismatch {
		t.Fatalf("status=%q, want %q: a pin naming the previous holder must flag the current one",
			status, IdentityMismatch)
	}
}

// The same address, the same pinned-ness, and the pin AGREES with the presented
// identity: verified. Without this case a reader can conclude that removing the
// pin is the fix, which the measured evidence contradicts.
func TestAliasReuseAgreeingPinVerifiesGlobalSender(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	pins.StorePin(currentHolderStID, reuseAddress, "", "")
	c.SetPinStore(pins, "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeGlobal, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeGlobal, Custody: CustodySelf},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, reuseAddress,
		currentHolderKey, currentHolderStID, nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want %q: an agreeing pin must not flag the sender", status, Verified)
	}
}

// The property this task exists for, on a locally-scoped alias: the next holder
// of a name does not inherit the previous holder's key. The authenticated team
// roster names the alias's current holder, so a reissue is authorized by the
// roster rather than by a signature the new holder cannot hold - and the
// previous holder's binding is cleared as a result, not left to be tripped over.
func TestAliasReuseLocalSenderVerifiesAndRetiresPreviousHolderPin(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	pins.StorePin(previousHolderKey, reuseAddress, "", "")
	pins.Pins[previousHolderKey].LogSeq = 7
	pins.Pins[previousHolderKey].LogEntryHash = strings.Repeat("a", 64)
	c.SetPinStore(pins, "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: previousHolderKey, IdentityScope: IdentityModeLocal, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeLocal, Custody: CustodySelf},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, reuseAddress,
		currentHolderKey, "", nil, nil, nil)

	if status != Verified {
		t.Fatalf("status=%q, want %q: the roster's current holder must not be flagged by its predecessor's pin",
			status, Verified)
	}
	if pinKey, ok := pins.Addresses[reuseAddress]; ok {
		t.Fatalf("previous holder's binding survived as %q: the next holder inherits it", pinKey)
	}
	// The server's roster frees the name; it cannot erase the client's memory of
	// the previous holder: its record and anchor move to a retired key that no
	// lookup reaches (Antares 2e8881d7).
	pin, ok := pins.Pins[previousHolderKey]
	if !ok || !strings.HasPrefix(pin.Address, "retired:"+reuseAddress+"@") || pins.Addresses[pin.Address] != previousHolderKey {
		t.Fatalf("previous holder's pin not kept under a retired key: pin=%+v addresses=%v", pin, pins.Addresses)
	}
	if pin.LogSeq != 7 || pin.LogEntryHash != strings.Repeat("a", 64) {
		t.Fatalf("previous holder's anchor lost: %+v", pin)
	}
}

// A real address is never a team-scoped name: the roster's word about a local
// identity there leaves any pin at that address untouched.
func TestLocalSenderAtARealAddressLeavesItsPinUntouched(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	pins.StorePin(previousHolderStID, "acme.com/kestrel", "", "")
	c.SetPinStore(pins, "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeLocal, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: currentHolderKey, IdentityScope: IdentityModeLocal, Custody: CustodySelf},
	})

	c.NormalizeSenderTrust(context.Background(), Verified, "acme.com/kestrel", currentHolderKey, "", nil, nil, nil)

	if pins.Addresses["acme.com/kestrel"] != previousHolderStID {
		t.Fatalf("the pin at a real address was moved or removed: %v", pins.Addresses)
	}
}
