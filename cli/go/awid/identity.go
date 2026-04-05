package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// ResolvedIdentity holds resolved identity information for an identity address.
type ResolvedIdentity struct {
	DID           string
	StableID      string
	IdentityID    string // server-assigned UUID
	Address       string // namespace/handle
	ControllerDID string
	Handle        string
	PublicKey     ed25519.PublicKey
	ServerURL     string
	Custody       string // "self" or "custodial"
	Lifetime      string // "persistent" or "ephemeral"
	ResolvedAt    time.Time
	ResolvedVia   string // "did:key", "server", "pin"
}

// IdentityResolver resolves an identifier to a ResolvedIdentity.
type IdentityResolver interface {
	Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error)
}

type StableIdentityVerifier interface {
	VerifyStableIdentity(ctx context.Context, address, stableID string) *StableIdentityVerification
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

// serverResolveResponse is the wire format returned by
// GET /v1/agents/resolve/{namespace}/{handle}.
type serverResolveResponse struct {
	DID           string `json:"did"`
	StableID      string `json:"stable_id"`
	IdentityID    string `json:"identity_id"`
	AgentID       string `json:"agent_id"`
	Address       string `json:"address"`
	HumanName     string `json:"human_name"`
	Handle        string `json:"handle"`
	Server        string `json:"server"`
	PublicKey     string `json:"public_key"`
	ControllerDID string `json:"controller_did"`
	Custody       string `json:"custody"`
	Lifetime      string `json:"lifetime"`
	Status        string `json:"status"`
}

// ServerResolver resolves an identity address via the aweb server.
type ServerResolver struct {
	Client *Client
}

func (r *ServerResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	var resp serverResolveResponse
	path := r.resolvePath(identifier)
	if err := r.Client.Get(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("ServerResolver: %w", err)
	}
	identityID := strings.TrimSpace(resp.IdentityID)
	if identityID == "" {
		identityID = strings.TrimSpace(resp.AgentID)
	}
	handle := strings.TrimSpace(resp.Handle)
	if handle == "" {
		handle = resolveHandleFromAddress(resp.Address)
	}
	identity := &ResolvedIdentity{
		DID:           resp.DID,
		StableID:      resp.StableID,
		IdentityID:    identityID,
		Address:       resp.Address,
		ControllerDID: resp.ControllerDID,
		Handle:        handle,
		ServerURL:     resp.Server,
		Custody:       resp.Custody,
		Lifetime:      resp.Lifetime,
		ResolvedAt:    time.Now().UTC(),
		ResolvedVia:   "server",
	}
	if strings.TrimSpace(resp.PublicKey) != "" {
		pub, err := decodeServerPublicKey(strings.TrimSpace(resp.PublicKey))
		if err != nil {
			if identity.DID == "" {
				return nil, fmt.Errorf("ServerResolver: invalid public_key: %w", err)
			}
			pub, err = ExtractPublicKey(identity.DID)
			if err != nil {
				return nil, fmt.Errorf("ServerResolver: invalid public_key: %w", err)
			}
		}
		identity.PublicKey = pub
		if identity.DID != "" && ComputeDIDKey(identity.PublicKey) != identity.DID {
			return nil, fmt.Errorf("ServerResolver: DID/public_key mismatch")
		}
	}
	return identity, nil
}

func decodeServerPublicKey(raw string) (ed25519.PublicKey, error) {
	var lastErr error
	for _, encoding := range []*base64.Encoding{
		base64.RawStdEncoding,
		base64.StdEncoding,
		base64.RawURLEncoding,
		base64.URLEncoding,
	} {
		pub, err := encoding.DecodeString(raw)
		if err != nil {
			lastErr = err
			continue
		}
		if len(pub) != ed25519.PublicKeySize {
			lastErr = fmt.Errorf("invalid public_key length %d", len(pub))
			continue
		}
		return ed25519.PublicKey(pub), nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("unsupported public_key encoding")
}

func (r *ServerResolver) resolvePath(identifier string) string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return "/v1/agents/resolve/"
	}
	addr := ParseNetworkAddress(identifier)
	if addr.IsNetwork && strings.TrimSpace(r.Client.projectSlug) != "" && strings.EqualFold(addr.OrgSlug, r.Client.projectSlug) {
		return "/v1/agents/resolve/" + urlPathEscape(addr.Alias)
	}
	return "/v1/agents/resolve/" + identifier
}

func resolveHandleFromAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
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
			ServerURL:   pin.Server,
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
			ServerURL:   pin.Server,
			ResolvedAt:  time.Now().UTC(),
			ResolvedVia: "pin",
		}, nil
	}
	return nil, fmt.Errorf("PinResolver: no pin for %q", identifier)
}

// ChainResolver dispatches resolution by identifier format.
// did:key identifiers use DIDKeyResolver; addresses use ServerResolver.
// After server resolution, the public key is cross-checked by extracting
// it from the server-reported DID.
type ChainResolver struct {
	DIDKey   *DIDKeyResolver
	Registry *RegistryResolver
	Server   *ServerResolver
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
				identity.ServerURL = pinIdentity.ServerURL
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

	// Address-based resolution: use server, then cross-check DID.
	if r.Server == nil {
		return nil, fmt.Errorf("ChainResolver: no server resolver for address %q", identifier)
	}
	identity, err := r.Server.Resolve(ctx, identifier)
	if err != nil {
		return nil, err
	}
	// Cross-check: extract public key from server-reported DID.
	if identity.DID != "" {
		pub, err := ExtractPublicKey(identity.DID)
		if err != nil {
			return nil, fmt.Errorf("ChainResolver: server-reported DID invalid: %w", err)
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
