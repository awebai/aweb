package awid

import (
	"encoding/json"
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
