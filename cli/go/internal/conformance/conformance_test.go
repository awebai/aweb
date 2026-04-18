package conformance_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	awid "github.com/awebai/aw/awid"
)

//go:embed vectors/*.json
var vectorsFS embed.FS

// --- message-signing-v1 ---

type messageSigningVector struct {
	Name             string        `json:"name"`
	SigningSeedHex   string        `json:"signing_seed_hex"`
	SigningDIDKey    string        `json:"signing_did_key"`
	Message          messageFields `json:"message"`
	CanonicalPayload string        `json:"canonical_payload"`
	SignatureB64     string        `json:"signature_b64"`
}

type messageFields struct {
	From         string `json:"from"`
	FromDID      string `json:"from_did"`
	To           string `json:"to"`
	ToDID        string `json:"to_did"`
	Type         string `json:"type"`
	MessageID    string `json:"message_id"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Timestamp    string `json:"timestamp"`
	FromStableID string `json:"from_stable_id"`
	ToStableID   string `json:"to_stable_id"`
}

func TestMessageSigningVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/message-signing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []messageSigningVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(v.SigningSeedHex)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(seed)

			// Verify did:key matches seed.
			got := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
			if got != v.SigningDIDKey {
				t.Fatalf("ComputeDIDKey: got %s, want %s", got, v.SigningDIDKey)
			}

			env := &awid.MessageEnvelope{
				From:         v.Message.From,
				FromDID:      v.Message.FromDID,
				To:           v.Message.To,
				ToDID:        v.Message.ToDID,
				Type:         v.Message.Type,
				MessageID:    v.Message.MessageID,
				Subject:      v.Message.Subject,
				Body:         v.Message.Body,
				Timestamp:    v.Message.Timestamp,
				FromStableID: v.Message.FromStableID,
				ToStableID:   v.Message.ToStableID,
			}

			// Test canonical payload matches expected.
			canonical := awid.CanonicalJSON(env)
			if canonical != v.CanonicalPayload {
				t.Errorf("CanonicalJSON:\n  got:  %s\n  want: %s", canonical, v.CanonicalPayload)
			}

			// Test signing produces expected signature.
			sig, err := awid.SignMessage(key, env)
			if err != nil {
				t.Fatal(err)
			}
			if sig != v.SignatureB64 {
				t.Errorf("SignMessage:\n  got:  %s\n  want: %s", sig, v.SignatureB64)
			}

			// Test verification succeeds.
			env.Signature = v.SignatureB64
			env.SigningKeyID = v.SigningDIDKey
			status, verifyErr := awid.VerifyMessage(env)
			if verifyErr != nil {
				t.Errorf("VerifyMessage error: %v", verifyErr)
			}
			if status != awid.Verified {
				t.Errorf("VerifyMessage: got %s, want %s", status, awid.Verified)
			}
		})
	}
}

// --- stable-id-v1 ---

type stableIDVector struct {
	Name         string `json:"name"`
	SeedHex      string `json:"seed_hex"`
	DIDKey       string `json:"did_key"`
	PublicKeyHex string `json:"public_key_hex"`
	StableIDAW   string `json:"stable_id_aw"`
}

func TestStableIDVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/stable-id-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []stableIDVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := awid.ExtractPublicKey(v.DIDKey)
			if err != nil {
				t.Fatal(err)
			}

			// Verify public key hex matches.
			if hex.EncodeToString(pub) != v.PublicKeyHex {
				t.Errorf("public key hex: got %s, want %s", hex.EncodeToString(pub), v.PublicKeyHex)
			}

			gotAW := awid.ComputeStableID(pub)
			if gotAW != v.StableIDAW {
				t.Errorf("ComputeStableID: got %s, want %s", gotAW, v.StableIDAW)
			}
		})
	}
}

// --- identity-log-v1 ---

type identityLogVectors struct {
	KeySeeds map[string]string `json:"key_seeds"`
	Mapping  struct {
		DIDAW         string `json:"did_aw"`
		InitialDIDKey string `json:"initial_did_key"`
		RotatedDIDKey string `json:"rotated_did_key"`
	} `json:"mapping"`
	Entries []identityLogEntryVector `json:"entries"`
}

type identityLogEntryVector struct {
	Name                  string         `json:"name"`
	Comment               string         `json:"comment"`
	StatePayload          map[string]any `json:"state_payload"`
	CanonicalStatePayload string         `json:"canonical_state_payload"`
	StateHash             string         `json:"state_hash"`
	EntryPayload          map[string]any `json:"entry_payload"`
	CanonicalEntryPayload string         `json:"canonical_entry_payload"`
	EntryHash             string         `json:"entry_hash"`
	SignatureB64          string         `json:"signature_b64"`
}

func TestIdentityLogVectors(t *testing.T) {
	data := readRootVector(t, "identity-log-v1.json")
	var vectors identityLogVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	initialSeed, err := hex.DecodeString(vectors.KeySeeds["initial_seed_hex"])
	if err != nil {
		t.Fatal(err)
	}
	rotatedSeed, err := hex.DecodeString(vectors.KeySeeds["rotated_seed_hex"])
	if err != nil {
		t.Fatal(err)
	}
	initialKey := ed25519.NewKeyFromSeed(initialSeed)
	rotatedKey := ed25519.NewKeyFromSeed(rotatedSeed)
	if got := awid.ComputeDIDKey(initialKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.InitialDIDKey {
		t.Fatalf("initial did:key: got %s, want %s", got, vectors.Mapping.InitialDIDKey)
	}
	if got := awid.ComputeDIDKey(rotatedKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.RotatedDIDKey {
		t.Fatalf("rotated did:key: got %s, want %s", got, vectors.Mapping.RotatedDIDKey)
	}
	if got := awid.ComputeStableID(initialKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.DIDAW {
		t.Fatalf("did:aw: got %s, want %s", got, vectors.Mapping.DIDAW)
	}

	seedByDID := map[string][]byte{
		vectors.Mapping.InitialDIDKey: initialSeed,
		vectors.Mapping.RotatedDIDKey: rotatedSeed,
	}
	var previousEntryHash string
	for _, entry := range vectors.Entries {
		t.Run(entry.Name, func(t *testing.T) {
			statePayload, err := awid.CanonicalJSONValue(entry.StatePayload)
			if err != nil {
				t.Fatal(err)
			}
			if statePayload != entry.CanonicalStatePayload {
				t.Fatalf("state canonical:\n got:  %s\n want: %s", statePayload, entry.CanonicalStatePayload)
			}
			stateHash := sha256.Sum256([]byte(statePayload))
			if got := hex.EncodeToString(stateHash[:]); got != entry.StateHash {
				t.Fatalf("state_hash: got %s, want %s", got, entry.StateHash)
			}
			requireNoAddressFields(t, entry.StatePayload)

			entryPayload, err := awid.CanonicalJSONValue(entry.EntryPayload)
			if err != nil {
				t.Fatal(err)
			}
			requireNoAddressFields(t, entry.EntryPayload)
			if entryPayload != entry.CanonicalEntryPayload {
				t.Fatalf("entry canonical:\n got:  %s\n want: %s", entryPayload, entry.CanonicalEntryPayload)
			}
			entryHash := sha256.Sum256([]byte(entryPayload))
			if got := hex.EncodeToString(entryHash[:]); got != entry.EntryHash {
				t.Fatalf("entry_hash: got %s, want %s", got, entry.EntryHash)
			}
			if got := nullableString(entry.EntryPayload["prev_entry_hash"]); got != previousEntryHash {
				t.Fatalf("prev_entry_hash: got %q, want %q", got, previousEntryHash)
			}
			authorizedBy, ok := entry.EntryPayload["authorized_by"].(string)
			if !ok || authorizedBy == "" {
				t.Fatalf("missing authorized_by")
			}
			seed, ok := seedByDID[authorizedBy]
			if !ok {
				t.Fatalf("unknown authorized_by %s", authorizedBy)
			}
			key := ed25519.NewKeyFromSeed(seed)
			signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(entryPayload)))
			if signature != entry.SignatureB64 {
				t.Fatalf("signature:\n got:  %s\n want: %s", signature, entry.SignatureB64)
			}
		})
		previousEntryHash = entry.EntryHash
	}
}

func readRootVector(t *testing.T, name string) []byte {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireNoAddressFields(t *testing.T, payload map[string]any) {
	t.Helper()
	for _, field := range []string{"address", "handle", "server"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("identity vector payload must not contain %q", field)
		}
	}
}

func nullableString(value any) string {
	if value == nil {
		return ""
	}
	if out, ok := value.(string); ok {
		return out
	}
	return ""
}

// --- rotation-announcements-v1 ---

type rotationVector struct {
	Name               string         `json:"name"`
	Links              []rotationLink `json:"links"`
	PinnedDIDKey       string         `json:"pinned_did_key"`
	EnvelopeFromDIDKey string         `json:"envelope_from_did_key"`
}

type rotationLink struct {
	OldSeedHex       string `json:"old_seed_hex"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	Timestamp        string `json:"timestamp"`
	CanonicalPayload string `json:"canonical_payload"`
	SignatureB64     string `json:"signature_b64"`
}

func TestRotationAnnouncementVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/rotation-announcements-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []rotationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			for i, link := range v.Links {
				oldPub, err := awid.ExtractPublicKey(link.OldDIDKey)
				if err != nil {
					t.Fatalf("link %d: ExtractPublicKey: %v", i, err)
				}

				// Verify canonical payload matches expected.
				gotCanonical := awid.CanonicalRotationJSON(link.OldDIDKey, link.NewDIDKey, link.Timestamp)
				if gotCanonical != link.CanonicalPayload {
					t.Errorf("link %d: CanonicalRotationJSON:\n  got:  %s\n  want: %s", i, gotCanonical, link.CanonicalPayload)
				}

				// Verify rotation signature.
				ok, err := awid.VerifyRotationSignature(oldPub, link.OldDIDKey, link.NewDIDKey, link.Timestamp, link.SignatureB64)
				if err != nil {
					t.Fatalf("link %d: VerifyRotationSignature: %v", i, err)
				}
				if !ok {
					t.Errorf("link %d: VerifyRotationSignature returned false", i)
				}

				// Verify signing with the old key produces the expected signature.
				seed, err := hex.DecodeString(link.OldSeedHex)
				if err != nil {
					t.Fatal(err)
				}
				key := ed25519.NewKeyFromSeed(seed)
				sig, err := awid.SignRotation(key, link.OldDIDKey, link.NewDIDKey, link.Timestamp)
				if err != nil {
					t.Fatalf("link %d: SignRotation: %v", i, err)
				}
				if sig != link.SignatureB64 {
					t.Errorf("link %d: SignRotation:\n  got:  %s\n  want: %s", i, sig, link.SignatureB64)
				}
			}

			// Verify chain semantics: first link's old_did matches pinned,
			// each link's new_did matches next link's old_did,
			// last link's new_did matches envelope from_did.
			if len(v.Links) > 0 {
				if v.Links[0].OldDIDKey != v.PinnedDIDKey {
					t.Errorf("chain: first link old_did %s != pinned %s", v.Links[0].OldDIDKey, v.PinnedDIDKey)
				}
				for i := 1; i < len(v.Links); i++ {
					if v.Links[i].OldDIDKey != v.Links[i-1].NewDIDKey {
						t.Errorf("chain: link %d old_did %s != link %d new_did %s", i, v.Links[i].OldDIDKey, i-1, v.Links[i-1].NewDIDKey)
					}
				}
				lastNew := v.Links[len(v.Links)-1].NewDIDKey
				if lastNew != v.EnvelopeFromDIDKey {
					t.Errorf("chain: last new_did %s != envelope from_did %s", lastNew, v.EnvelopeFromDIDKey)
				}
			}
		})
	}
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func intField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}
