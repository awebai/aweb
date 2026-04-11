package awid

import (
	"context"
	"crypto/ed25519"
	"fmt"
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
	// Try direct DID lookup.
	if pin, ok := r.Store.Pins[identifier]; ok {
		return &ResolvedIdentity{
			DID:         identifier,
			Address:     pin.Address,
			Handle:      pin.Handle,
			RegistryURL: pin.Server,
			ResolvedAt:  time.Now().UTC(),
			ResolvedVia: "pin",
		}, nil
	}
	// Try reverse lookup by address.
	if did, ok := r.Store.Addresses[identifier]; ok {
		pin, exists := r.Store.Pins[did]
		if !exists {
			return nil, fmt.Errorf("PinResolver: address %q maps to DID %q not in pins", identifier, did)
		}
		return &ResolvedIdentity{
			DID:         did,
			Address:     pin.Address,
			Handle:      pin.Handle,
			RegistryURL: pin.Server,
			ResolvedAt:  time.Now().UTC(),
			ResolvedVia: "pin",
		}, nil
	}
	return nil, fmt.Errorf("PinResolver: no pin for %q", identifier)
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
		if r.Registry == nil {
			return nil, fmt.Errorf("ChainResolver: no registry resolver for address %q", identifier)
		}
		return r.Registry.Resolve(ctx, identifier)
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

func (r *ChainResolver) VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification {
	if r.Registry == nil || !strings.Contains(strings.TrimSpace(address), "/") {
		return &StableIdentityVerification{Outcome: StableIdentityDegraded}
	}
	return r.Registry.VerifyStableIdentity(ctx, address, stableID)
}
