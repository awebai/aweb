package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
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

type tofuVectorFile struct {
	Schema  string       `json:"schema"`
	Vectors []tofuVector `json:"vectors"`
}

type tofuVector struct {
	Name                        string                         `json:"name"`
	InitialStatus               string                         `json:"initial_status"`
	RawAddress                  string                         `json:"raw_address"`
	TrustAddress                string                         `json:"trust_address"`
	FromDID                     string                         `json:"from_did"`
	FromStableID                string                         `json:"from_stable_id"`
	RotationAnnouncement        *rotationAnnouncementVector    `json:"rotation_announcement"`
	ReplacementAnnouncement     *replacementAnnouncementVector `json:"replacement_announcement"`
	AgentMeta                   tofuAgentMeta                  `json:"agent_meta"`
	RegistryConfirmedCurrentKey bool                           `json:"registry_confirmed_current_key"`
	PinStoreBefore              pinStoreVector                 `json:"pin_store_before"`
	ExpectedStatus              string                         `json:"expected_status"`
	ExpectedPinStoreAfter       *pinStoreVector                `json:"expected_pin_store_after"`
}

type tofuAgentMeta struct {
	Lifetime      string `json:"lifetime"`
	Custody       string `json:"custody"`
	ControllerDID string `json:"controller_did"`
}

type rotationAnnouncementVector struct {
	Mode                  string `json:"mode"`
	OldDID                string `json:"old_did"`
	NewDID                string `json:"new_did"`
	TimestampDeltaSeconds int    `json:"timestamp_delta_seconds"`
	OldSeedByte           int    `json:"old_seed_byte"`
	CorruptSignature      bool   `json:"corrupt_signature"`
}

type replacementAnnouncementVector struct {
	Mode                  string `json:"mode"`
	Address               string `json:"address"`
	OldDID                string `json:"old_did"`
	NewDID                string `json:"new_did"`
	ControllerDID         string `json:"controller_did"`
	TimestampDeltaSeconds int    `json:"timestamp_delta_seconds"`
	ControllerSeedByte    int    `json:"controller_seed_byte"`
}

type pinStoreVector struct {
	Pins      map[string]pinVector `json:"pins"`
	Addresses map[string]string    `json:"addresses"`
}

type pinVector struct {
	Address   string `json:"address"`
	StableID  string `json:"stable_id"`
	DIDKey    string `json:"did_key"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Server    string `json:"server"`
}

type conformanceTOFUResolver struct {
	controllerDID string
}

func (r *conformanceTOFUResolver) Resolve(context.Context, string) (*ResolvedIdentity, error) {
	return &ResolvedIdentity{ControllerDID: r.controllerDID}, nil
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

func TestTOFUConformanceVectors(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test-vectors", "trust", "tofu-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var vectors tofuVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.trust.tofu.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			pins := pinStoreFromVector(vector.PinStoreBefore)
			client := &Client{pinStore: pins}
			client.SetResolver(&conformanceTOFUResolver{controllerDID: vector.AgentMeta.ControllerDID})

			rotation := buildRotationAnnouncement(t, vector.RotationAnnouncement)
			replacement := buildReplacementAnnouncement(t, vector.ReplacementAnnouncement)
			meta := &agentMeta{
				Lifetime: vector.AgentMeta.Lifetime,
				Custody:  vector.AgentMeta.Custody,
				Resolved: true,
			}

			got := client.checkTOFUPinWithMeta(
				context.Background(),
				VerificationStatus(vector.InitialStatus),
				vector.RawAddress,
				vector.TrustAddress,
				vector.FromDID,
				vector.FromStableID,
				rotation,
				replacement,
				meta,
				vector.RegistryConfirmedCurrentKey,
			)
			if got != VerificationStatus(vector.ExpectedStatus) {
				t.Fatalf("status=%q, want %q", got, vector.ExpectedStatus)
			}

			expected := &vector.PinStoreBefore
			if vector.ExpectedPinStoreAfter != nil {
				expected = vector.ExpectedPinStoreAfter
			}
			assertPinStoreMatchesVector(t, pins, *expected, vector.PinStoreBefore)
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

func pinStoreFromVector(vector pinStoreVector) *PinStore {
	store := NewPinStore()
	for key, pin := range vector.Pins {
		store.Pins[key] = &Pin{
			Address:   pin.Address,
			StableID:  pin.StableID,
			DIDKey:    pin.DIDKey,
			FirstSeen: pin.FirstSeen,
			LastSeen:  pin.LastSeen,
			Server:    pin.Server,
		}
	}
	for address, key := range vector.Addresses {
		store.Addresses[address] = key
	}
	return store
}

func buildRotationAnnouncement(t *testing.T, vector *rotationAnnouncementVector) *RotationAnnouncement {
	t.Helper()
	if vector == nil {
		return nil
	}
	if vector.Mode != "runtime_generated" {
		t.Fatalf("unsupported rotation announcement mode %q", vector.Mode)
	}
	key := privateKeyFromSeedByte(vector.OldSeedByte)
	if got := ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != vector.OldDID {
		t.Fatalf("old seed did=%q, want %q", got, vector.OldDID)
	}
	timestamp := time.Now().UTC().Add(time.Duration(vector.TimestampDeltaSeconds) * time.Second).Format(time.RFC3339)
	signature, err := SignRotation(key, vector.OldDID, vector.NewDID, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if vector.CorruptSignature {
		signature = corruptBase64Signature(signature)
	}
	return &RotationAnnouncement{
		OldDID:          vector.OldDID,
		NewDID:          vector.NewDID,
		Timestamp:       timestamp,
		OldKeySignature: signature,
	}
}

func corruptBase64Signature(signature string) string {
	if signature == "" {
		return "A"
	}
	if signature[len(signature)-1] == 'A' {
		return signature[:len(signature)-1] + "B"
	}
	return signature[:len(signature)-1] + "A"
}

func buildReplacementAnnouncement(t *testing.T, vector *replacementAnnouncementVector) *ReplacementAnnouncement {
	t.Helper()
	if vector == nil {
		return nil
	}
	if vector.Mode != "runtime_generated" {
		t.Fatalf("unsupported replacement announcement mode %q", vector.Mode)
	}
	key := privateKeyFromSeedByte(vector.ControllerSeedByte)
	if got := ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != vector.ControllerDID {
		t.Fatalf("controller seed did=%q, want %q", got, vector.ControllerDID)
	}
	timestamp := time.Now().UTC().Add(time.Duration(vector.TimestampDeltaSeconds) * time.Second).Format(time.RFC3339)
	payload := CanonicalReplacementJSON(vector.Address, vector.ControllerDID, vector.OldDID, vector.NewDID, timestamp)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(payload)))
	return &ReplacementAnnouncement{
		Address:             vector.Address,
		OldDID:              vector.OldDID,
		NewDID:              vector.NewDID,
		ControllerDID:       vector.ControllerDID,
		Timestamp:           timestamp,
		ControllerSignature: signature,
	}
}

func privateKeyFromSeedByte(seedByte int) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(seedByte)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func assertPinStoreMatchesVector(t *testing.T, got *PinStore, expected pinStoreVector, before pinStoreVector) {
	t.Helper()
	if !reflect.DeepEqual(got.Addresses, expected.Addresses) {
		t.Fatalf("addresses=%#v, want %#v", got.Addresses, expected.Addresses)
	}
	if len(got.Pins) != len(expected.Pins) {
		t.Fatalf("pin count=%d, want %d: %#v", len(got.Pins), len(expected.Pins), got.Pins)
	}
	for key, expectedPin := range expected.Pins {
		gotPin, ok := got.Pins[key]
		if !ok {
			t.Fatalf("missing pin %q", key)
		}
		beforePin := before.Pins[key]
		assertPinField(t, key, "address", gotPin.Address, expectedPin.Address, beforePin.Address)
		assertPinField(t, key, "stable_id", gotPin.StableID, expectedPin.StableID, beforePin.StableID)
		assertPinField(t, key, "did_key", gotPin.DIDKey, expectedPin.DIDKey, beforePin.DIDKey)
		assertPinField(t, key, "first_seen", gotPin.FirstSeen, expectedPin.FirstSeen, beforePin.FirstSeen)
		assertPinField(t, key, "last_seen", gotPin.LastSeen, expectedPin.LastSeen, beforePin.LastSeen)
		assertPinField(t, key, "server", gotPin.Server, expectedPin.Server, beforePin.Server)
	}
}

func assertPinField(t *testing.T, pinKey, field, got, expected, before string) {
	t.Helper()
	switch expected {
	case "$ANY_TIMESTAMP":
		if _, err := time.Parse(time.RFC3339, got); err != nil {
			t.Fatalf("%s.%s=%q is not RFC3339: %v", pinKey, field, got, err)
		}
	case "$CHANGED_TIMESTAMP":
		if _, err := time.Parse(time.RFC3339, got); err != nil {
			t.Fatalf("%s.%s=%q is not RFC3339: %v", pinKey, field, got, err)
		}
		if got == before {
			t.Fatalf("%s.%s=%q, want changed from before", pinKey, field, got)
		}
	default:
		if got != expected {
			t.Fatalf("%s.%s=%q, want %q", pinKey, field, got, expected)
		}
	}
}
