package awid

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ResolvedIdentity holds resolved identity information for an identity reference.
type ResolvedIdentity struct {
	DID           string
	StableID      string
	Address       string // address when known; may be empty for addressless references
	ControllerDID string
	Handle        string
	PublicKey     ed25519.PublicKey
	RegistryURL   string
	Custody       string // "self" or "custodial"
	Lifetime      string // "persistent" or "ephemeral"
	ResolvedAt    time.Time
	ResolvedVia   string // "did:key", "registry", "pin"
}

// IdentityResolver resolves an identifier to a ResolvedIdentity.
type IdentityResolver interface {
	Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error)
}

type StableIdentityVerifier interface {
	VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification
}

// HandleFromAddress extracts the handle/name portion from a public address.
func HandleFromAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" || strings.HasPrefix(address, "did:") {
		return ""
	}
	if idx := strings.LastIndexByte(address, '/'); idx >= 0 && idx+1 < len(address) {
		return strings.TrimSpace(address[idx+1:])
	}
	if idx := strings.LastIndexByte(address, '~'); idx >= 0 && idx+1 < len(address) {
		return strings.TrimSpace(address[idx+1:])
	}
	return address
}

// DIDKeyResolver extracts the public key from a did:key string.
// No network call required.
type DIDKeyResolver struct{}

func (r *DIDKeyResolver) Resolve(_ context.Context, identifier string) (*ResolvedIdentity, error) {
	pub, err := ExtractPublicKey(identifier)
	if err != nil {
		return nil, fmt.Errorf("DIDKeyResolver: %w", err)
	}
	return &ResolvedIdentity{
		DID:         identifier,
		PublicKey:   pub,
		ResolvedAt:  time.Now().UTC(),
		ResolvedVia: "did:key",
	}, nil
}

// PinResolver looks up identity from the local TOFU pin store.
type PinResolver struct {
	Store *PinStore
}

func (r *PinResolver) Resolve(_ context.Context, identifier string) (*ResolvedIdentity, error) {
	if r == nil || r.Store == nil {
		return nil, fmt.Errorf("PinResolver: no pin store")
	}
	// Try direct DID lookup.
	if pin, ok := r.Store.Pins[identifier]; ok {
		return resolvedIdentityFromPin(identifier, pin), nil
	}
	// Try reverse lookup by address.
	if did, ok := r.Store.Addresses[identifier]; ok {
		pin, exists := r.Store.Pins[did]
		if !exists {
			return nil, fmt.Errorf("PinResolver: address %q maps to DID %q not in pins", identifier, did)
		}
		return resolvedIdentityFromPin(did, pin), nil
	}
	return nil, fmt.Errorf("PinResolver: no pin for %q", identifier)
}

func resolvedIdentityFromPin(pinKey string, pin *Pin) *ResolvedIdentity {
	stableID := strings.TrimSpace(pin.StableID)
	did := strings.TrimSpace(pinKey)
	if strings.HasPrefix(did, "did:aw:") {
		stableID = did
		if key := strings.TrimSpace(pin.DIDKey); key != "" {
			did = key
		}
	}
	return &ResolvedIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     pin.Address,
		Handle:      pin.Handle,
		RegistryURL: pin.Server,
		ResolvedAt:  time.Now().UTC(),
		ResolvedVia: "pin",
	}
}

// ChainResolver dispatches resolution by identifier format.
// did:key identifiers use DIDKeyResolver; registry identifiers use RegistryResolver.
type ChainResolver struct {
	DIDKey   *DIDKeyResolver
	Registry *RegistryResolver
	Pin      *PinResolver
}

func (r *ChainResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	if strings.HasPrefix(identifier, didKeyPrefix) {
		identity, err := r.DIDKey.Resolve(ctx, identifier)
		if err != nil {
			return nil, err
		}
		// Supplement with pin metadata if available.
		if r.Pin != nil {
			if pinIdentity, pinErr := r.Pin.Resolve(ctx, identifier); pinErr == nil {
				identity.Address = pinIdentity.Address
				identity.Handle = pinIdentity.Handle
				identity.RegistryURL = pinIdentity.RegistryURL
			}
		}
		return identity, nil
	}

	if strings.Contains(identifier, "/") {
		if r.Registry != nil {
			identity, err := r.Registry.Resolve(ctx, identifier)
			if err == nil {
				return identity, nil
			}
			if r.Pin != nil && registryMissAllowsPinFallback(err) {
				if pinIdentity, pinErr := r.Pin.Resolve(ctx, identifier); pinErr == nil {
					return pinIdentity, nil
				}
			}
			return nil, err
		}
		if r.Pin != nil {
			return r.Pin.Resolve(ctx, identifier)
		}
		return nil, fmt.Errorf("ChainResolver: no registry resolver for address %q", identifier)
	}

	if r.Registry == nil {
		return nil, fmt.Errorf("ChainResolver: no registry resolver for address %q", identifier)
	}
	identity, err := r.Registry.Resolve(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if identity.DID != "" {
		pub, err := ExtractPublicKey(identity.DID)
		if err != nil {
			return nil, fmt.Errorf("ChainResolver: registry-reported DID invalid: %w", err)
		}
		identity.PublicKey = pub
	}
	return identity, nil
}

func registryMissAllowsPinFallback(err error) bool {
	apiErr, ok := err.(*APIError)
	return ok && apiErr.StatusCode == http.StatusNotFound
}

func (r *ChainResolver) VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification {
	if r.Registry == nil || !strings.Contains(strings.TrimSpace(address), "/") {
		return &StableIdentityVerification{Outcome: StableIdentityDegraded}
	}
	return r.Registry.VerifyStableIdentity(ctx, address, stableID)
}
