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
