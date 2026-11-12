package awid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type firstContactVectorFile struct {
	Schema  string               `json:"schema"`
	Vectors []firstContactVector `json:"vectors"`
}

type firstContactVector struct {
	Name              string                     `json:"name"`
	FromAddress       string                     `json:"from_address"`
	FromDID           string                     `json:"from_did"`
	FromStableID      string                     `json:"from_stable_id"`
	Resolver          string                     `json:"resolver"`
	AddressResolution *firstContactResolution    `json:"address_resolution"`
	StableIdentity    *registryStateVerification `json:"stable_identity"`
	PinStoreBefore    firstContactPinStore       `json:"pin_store_before"`
	ExpectedStatus    string                     `json:"expected_status"`
	ExpectedPinStore  *firstContactPinStore      `json:"expected_pin_store_after"`
}

type firstContactResolution struct {
	Outcome  string `json:"outcome"`
	DIDKey   string `json:"did_key"`
	StableID string `json:"stable_id"`
}

type firstContactPinStore struct {
	Pins      map[string]firstContactPin `json:"pins"`
	Addresses map[string]string          `json:"addresses"`
}

type firstContactPin struct {
	Address     string `json:"address"`
	StableID    string `json:"stable_id"`
	DIDKey      string `json:"did_key"`
	ConfirmedBy string `json:"confirmed_by"`
}

// firstContactRegistry answers as the registry of one vector does.
type firstContactRegistry struct {
	resolution *firstContactResolution
	stable     *registryStateVerification
}

func (r *firstContactRegistry) Resolve(_ context.Context, address string) (*ResolvedIdentity, error) {
	switch r.resolution.Outcome {
	case "resolved":
		return &ResolvedIdentity{
			DID: r.resolution.DIDKey, StableID: r.resolution.StableID, Address: address,
			Custody: CustodySelf, IdentityScope: IdentityModeGlobal, ResolvedVia: "registry",
		}, nil
	case "not_found":
		return nil, &RegistryError{StatusCode: http.StatusNotFound, Detail: "address not found"}
	default:
		return nil, errors.New("registry unreachable")
	}
}

func (r *firstContactRegistry) VerifyStableIdentity(context.Context, string, string) *StableIdentityVerification {
	if r.stable == nil {
		return &StableIdentityVerification{Outcome: StableIdentityHardError, Error: "unexpected stable identity lookup"}
	}
	switch r.stable.Outcome {
	case "verified":
		return &StableIdentityVerification{Outcome: StableIdentityVerified, CurrentDIDKey: r.stable.CurrentDIDKey}
	case "ok_degraded":
		return &StableIdentityVerification{Outcome: StableIdentityDegraded}
	default:
		return &StableIdentityVerification{Outcome: StableIdentityHardError}
	}
}

func firstContactPins(store *PinStore) firstContactPinStore {
	out := firstContactPinStore{Pins: map[string]firstContactPin{}, Addresses: map[string]string{}}
	for key, pin := range store.Pins {
		out.Pins[key] = firstContactPin{
			Address: pin.Address, StableID: pin.StableID, DIDKey: pin.DIDKey, ConfirmedBy: pin.ConfirmedBy,
		}
	}
	for address, key := range store.Addresses {
		out.Addresses[address] = key
	}
	return out
}

// A sender outside the reader's team is pinned, and reported verified, only
// after the registry confirms that its address belongs to the signing key.
func TestFirstContactConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "test-vectors", "trust", "first-contact-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors firstContactVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.trust.first-contact.v1" || len(vectors.Vectors) == 0 {
		t.Fatalf("schema=%q vectors=%d", vectors.Schema, len(vectors.Vectors))
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			pins := NewPinStore()
			for key, pin := range vector.PinStoreBefore.Pins {
				pins.Pins[key] = &Pin{
					Address: pin.Address, StableID: pin.StableID, DIDKey: pin.DIDKey, ConfirmedBy: pin.ConfirmedBy,
					FirstSeen: "2026-01-01T00:00:00Z", LastSeen: "2026-01-01T00:00:00Z",
				}
			}
			for address, key := range vector.PinStoreBefore.Addresses {
				pins.Addresses[address] = key
			}
			client := &Client{pinStore: pins}
			if vector.Resolver == "registry" {
				client.SetResolver(&firstContactRegistry{resolution: vector.AddressResolution, stable: vector.StableIdentity})
			}

			status, _ := client.NormalizeSenderTrust(
				context.Background(), Verified, vector.FromAddress, vector.FromDID, vector.FromStableID, nil, nil, nil,
			)
			if status != VerificationStatus(vector.ExpectedStatus) {
				t.Errorf("status=%q, want %q", status, vector.ExpectedStatus)
			}

			want := vector.PinStoreBefore
			if vector.ExpectedPinStore != nil {
				want = *vector.ExpectedPinStore
			}
			got, _ := json.Marshal(firstContactPins(pins))
			expected, _ := json.Marshal(want)
			if string(got) != string(expected) {
				t.Errorf("pin store=%s, want %s", got, expected)
			}
		})
	}
}
