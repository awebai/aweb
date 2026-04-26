package awid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type recipientBindingVectorFile struct {
	Schema  string                   `json:"schema"`
	Vectors []recipientBindingVector `json:"vectors"`
}

type recipientBindingVector struct {
	Name           string `json:"name"`
	InitialStatus  string `json:"initial_status"`
	SelfDID        string `json:"self_did"`
	SelfStableID   string `json:"self_stable_id"`
	ToDID          string `json:"to_did"`
	ToStableID     string `json:"to_stable_id"`
	ExpectedStatus string `json:"expected_status"`
}

type cryptoSignatureVectorFile struct {
	Schema  string                  `json:"schema"`
	Vectors []cryptoSignatureVector `json:"vectors"`
}

type cryptoSignatureVector struct {
	Name           string  `json:"name"`
	SignedPayload  string  `json:"signed_payload"`
	Signature      string  `json:"signature"`
	FromDID        string  `json:"from_did"`
	SigningKeyID   *string `json:"signing_key_id"`
	ExpectedStatus string  `json:"expected_status"`
}

type registryVectorFile struct {
	Schema  string           `json:"schema"`
	Vectors []registryVector `json:"vectors"`
}

type registryVector struct {
	Name                        string                               `json:"name"`
	InitialStatus               string                               `json:"initial_status"`
	TrustAddress                string                               `json:"trust_address"`
	FromDID                     string                               `json:"from_did"`
	FromStableID                string                               `json:"from_stable_id"`
	RegistryState               map[string]registryStateVerification `json:"registry_state"`
	ExpectedStatus              string                               `json:"expected_status"`
	ExpectedConfirmedCurrentKey bool                                 `json:"expected_confirmed_current_key"`
}

type registryStateVerification struct {
	Outcome       string `json:"outcome"`
	CurrentDIDKey string `json:"current_did_key"`
}

type conformanceRegistryResolver struct {
	state map[string]registryStateVerification
}

func (r *conformanceRegistryResolver) Resolve(context.Context, string) (*ResolvedIdentity, error) {
	return nil, fmt.Errorf("not implemented")
}

func (r *conformanceRegistryResolver) VerifyStableIdentity(_ context.Context, _ string, stableID string) *StableIdentityVerification {
	entry, ok := r.state[stableID]
	if !ok {
		return &StableIdentityVerification{Outcome: StableIdentityHardError, Error: "unexpected registry lookup"}
	}
	switch entry.Outcome {
	case "verified":
		return &StableIdentityVerification{
			Outcome:       StableIdentityVerified,
			CurrentDIDKey: entry.CurrentDIDKey,
		}
	case "hard_error":
		return &StableIdentityVerification{Outcome: StableIdentityHardError}
	case "ok_degraded":
		return &StableIdentityVerification{Outcome: StableIdentityDegraded}
	default:
		return &StableIdentityVerification{Outcome: StableIdentityHardError, Error: "unknown registry outcome"}
	}
}

func TestCryptoSignatureConformanceVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test-vectors", "trust", "crypto-sig-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors cryptoSignatureVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.trust.crypto-sig.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			signingKeyID := ""
			if vector.SigningKeyID != nil {
				signingKeyID = *vector.SigningKeyID
			}
			got, _ := VerifySignedPayload(
				vector.SignedPayload,
				vector.Signature,
				vector.FromDID,
				signingKeyID,
			)
			if got != VerificationStatus(vector.ExpectedStatus) {
				t.Fatalf("status=%q, want %q", got, vector.ExpectedStatus)
			}
		})
	}
}

func TestRegistryConformanceVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test-vectors", "trust", "registry-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors registryVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.trust.registry.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			client := &Client{}
			client.SetResolver(&conformanceRegistryResolver{state: vector.RegistryState})

			gotStatus, gotConfirmed := client.checkStableIdentityRegistry(
				context.Background(),
				VerificationStatus(vector.InitialStatus),
				vector.TrustAddress,
				vector.FromDID,
				vector.FromStableID,
			)
			if gotStatus != VerificationStatus(vector.ExpectedStatus) {
				t.Fatalf("status=%q, want %q", gotStatus, vector.ExpectedStatus)
			}
			if gotConfirmed != vector.ExpectedConfirmedCurrentKey {
				t.Fatalf("confirmedCurrentKey=%v, want %v", gotConfirmed, vector.ExpectedConfirmedCurrentKey)
			}
		})
	}
}

func TestRecipientBindingConformanceVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test-vectors", "trust", "recipient-binding-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors recipientBindingVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.trust.recipient-binding.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			client := &Client{
				did:      vector.SelfDID,
				stableID: vector.SelfStableID,
			}
			got := client.NormalizeRecipientBinding(
				VerificationStatus(vector.InitialStatus),
				vector.ToDID,
				vector.ToStableID,
			)
			if got != VerificationStatus(vector.ExpectedStatus) {
				t.Fatalf("status=%q, want %q", got, vector.ExpectedStatus)
			}
		})
	}
}
