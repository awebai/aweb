package awid

import (
	"context"
	"fmt"
	"testing"
)

type stubStableIdentityResolver struct {
	result *StableIdentityVerification
}

func (s *stubStableIdentityResolver) Resolve(context.Context, string) (*ResolvedIdentity, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *stubStableIdentityResolver) VerifyStableIdentity(context.Context, string, string) *StableIdentityVerification {
	return s.result
}

func TestNormalizeSenderTrustRegistryDegradedFallsBackToTOFU(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{Outcome: StableIdentityDegraded},
	})

	address := "acme.com/alice"
	stableID := "did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t"
	did := "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, did, stableID, nil, nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
	pin, ok := ps.Pins[stableID]
	if !ok {
		t.Fatalf("expected stable_id pin %q", stableID)
	}
	if pin.DIDKey != did {
		t.Fatalf("pin DIDKey=%q, want %q", pin.DIDKey, did)
	}
}

func TestNormalizeSenderTrustRegistryHardErrorRejectsMessage(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{Outcome: StableIdentityHardError, Error: "registry key did:aw mismatch"},
	})

	status, _ := c.NormalizeSenderTrust(
		context.Background(),
		Verified,
		"acme.com/alice",
		"did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB",
		"did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t",
		nil,
		nil,
		nil,
	)
	if status != IdentityMismatch {
		t.Fatalf("status=%q, want %q", status, IdentityMismatch)
	}
	if len(ps.Pins) != 0 {
		t.Fatalf("pins=%d, want 0", len(ps.Pins))
	}
}

func TestNormalizeSenderTrustRegistryVerifiedMismatchRejectsMessage(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")
	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{
			Outcome:       StableIdentityVerified,
			CurrentDIDKey: "did:key:z6MktvG6qJusedKvbECR7XVTuiYzs5J689AgnDM9GosTtKSU",
		},
	})

	status, _ := c.NormalizeSenderTrust(
		context.Background(),
		Verified,
		"acme.com/alice",
		"did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB",
		"did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t",
		nil,
		nil,
		nil,
	)
	if status != IdentityMismatch {
		t.Fatalf("status=%q, want %q", status, IdentityMismatch)
	}
	if len(ps.Pins) != 0 {
		t.Fatalf("pins=%d, want 0", len(ps.Pins))
	}
}

func TestNormalizeSenderTrustRegistryVerifiedUpdatesStablePinDIDKey(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	address := "acme.com/alice"
	stableID := "did:aw:49RVkxsgqYDxawqpb77fvYEmHw1t"
	oldDID := "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"
	newDID := "did:key:z6MktvG6qJusedKvbECR7XVTuiYzs5J689AgnDM9GosTtKSU"
	ps.StorePin(stableID, address, "", "")
	ps.Pins[stableID].StableID = stableID
	ps.Pins[stableID].DIDKey = oldDID

	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{
			Outcome:       StableIdentityVerified,
			CurrentDIDKey: newDID,
		},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, newDID, stableID, nil, nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
	if got := ps.Addresses[address]; got != stableID {
		t.Fatalf("address pin=%q, want %q", got, stableID)
	}
	if got := ps.Pins[stableID].DIDKey; got != newDID {
		t.Fatalf("pin DIDKey=%q, want %q", got, newDID)
	}
}

func TestNormalizeSenderTrustRegistryVerifiedReplacesStaleAddressPin(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	address := "acme.com/alice"
	oldStableID := "did:aw:oldAmy"
	newStableID := "did:aw:newAmy"
	oldDID := "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"
	newDID := "did:key:z6MktvG6qJusedKvbECR7XVTuiYzs5J689AgnDM9GosTtKSU"
	ps.StorePin(oldStableID, address, "", "")
	ps.Pins[oldStableID].StableID = oldStableID
	ps.Pins[oldStableID].DIDKey = oldDID

	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{
			Outcome:       StableIdentityVerified,
			CurrentDIDKey: newDID,
		},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, newDID, newStableID, nil, nil, nil)
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
	if _, ok := ps.Pins[oldStableID]; ok {
		t.Fatalf("old stable_id pin %q still present", oldStableID)
	}
	if got := ps.Addresses[address]; got != newStableID {
		t.Fatalf("address pin=%q, want %q", got, newStableID)
	}
	if got := ps.Pins[newStableID].DIDKey; got != newDID {
		t.Fatalf("pin DIDKey=%q, want %q", got, newDID)
	}
}

func TestNormalizeSenderTrustRegistryDegradedRejectsStaleAddressPin(t *testing.T) {
	t.Parallel()

	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	ps := NewPinStore()
	c.SetPinStore(ps, "")

	address := "acme.com/alice"
	oldStableID := "did:aw:oldAmy"
	newStableID := "did:aw:newAmy"
	oldDID := "did:key:z6Mks3e5U8apRpvF9c8mpPGZ3TQyeG2gXpv4qcbF8DvnVSpB"
	newDID := "did:key:z6MktvG6qJusedKvbECR7XVTuiYzs5J689AgnDM9GosTtKSU"
	ps.StorePin(oldStableID, address, "", "")
	ps.Pins[oldStableID].StableID = oldStableID
	ps.Pins[oldStableID].DIDKey = oldDID

	c.SetResolver(&stubStableIdentityResolver{
		result: &StableIdentityVerification{Outcome: StableIdentityDegraded},
	})

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, newDID, newStableID, nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("status=%q, want %q", status, IdentityMismatch)
	}
	if got := ps.Addresses[address]; got != oldStableID {
		t.Fatalf("address pin=%q, want stale %q", got, oldStableID)
	}
}
