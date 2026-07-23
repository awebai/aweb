package awid

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type localFreshResolver struct {
	cached   *ResolvedIdentity
	fresh    *ResolvedIdentity
	freshErr error
	freshes  int
}

func (r *localFreshResolver) Resolve(context.Context, string) (*ResolvedIdentity, error) {
	if r.cached == nil {
		return nil, errors.New("missing cached identity")
	}
	return r.cached, nil
}

func (r *localFreshResolver) ResolveFresh(context.Context, string) (*ResolvedIdentity, error) {
	r.freshes++
	if r.freshErr != nil {
		return nil, r.freshErr
	}
	if r.fresh == nil {
		return nil, errors.New("missing fresh identity")
	}
	return r.fresh, nil
}

func TestNormalizeSenderTrustRelabelsAuthoritativelyRefreshedLocalCache(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	c.SetPinStore(pins, "")
	resolver := &localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:current", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	}
	c.SetResolver(resolver)
	address := "default:acme.com/alice"

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)
	if status != Verified {
		t.Fatalf("initial status=%q", status)
	}
	status, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:current", "", nil, nil, nil)
	if status != VerificationStale {
		t.Fatalf("refreshed status=%q, want %q", status, VerificationStale)
	}
	if resolver.freshes != 1 {
		t.Fatalf("fresh resolves=%d", resolver.freshes)
	}
	if len(pins.Pins) != 0 || len(pins.Addresses) != 0 {
		t.Fatalf("stale pins were not purged: %+v", pins)
	}
	status, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:current", "", nil, nil, nil)
	if status != Verified {
		t.Fatalf("subsequent current-key status=%q", status)
	}
}

func TestNormalizeSenderTrustDoesNotReconcileRecipientBindingMismatch(t *testing.T) {
	c, _ := New("http://example")
	pins := NewPinStore()
	c.SetPinStore(pins, "")
	resolver := &localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:current", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	}
	c.SetResolver(resolver)
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), IdentityMismatch, address, "did:key:current", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("recipient-binding status=%q, want %q", status, IdentityMismatch)
	}
	if resolver.freshes != 0 {
		t.Fatalf("recipient mismatch triggered local sender reconciliation: fresh resolves=%d", resolver.freshes)
	}
	if len(pins.Pins) == 0 || len(pins.Addresses) == 0 {
		t.Fatalf("recipient mismatch purged sender pins: %+v", pins)
	}
}

func TestNormalizeSenderTrustPreservesMismatchForLocalRosterKeyDifference(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:roster", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:attacker", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("attacker status=%q, want %q", status, IdentityMismatch)
	}
}

func TestNormalizeSenderTrustPreservesMismatchWhenLocalSenderAbsent(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached:   &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		freshErr: &APIError{StatusCode: http.StatusNotFound},
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:attacker", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("absent attacker status=%q, want %q", status, IdentityMismatch)
	}
}

func TestNormalizeSenderTrustReportsStaleWhenLocalRefreshUnavailable(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached:   &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		freshErr: errors.New("network unavailable"),
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:changed", "", nil, nil, nil)
	if status != VerificationStale {
		t.Fatalf("unavailable refresh status=%q, want %q", status, VerificationStale)
	}
}
