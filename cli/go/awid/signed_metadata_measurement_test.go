package awid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"log/slog"
	"strings"
	"testing"
)

func TestVerifiedCaseInsensitiveMetadataIsRetainedAndMeasured(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	did := ComputeDIDKey(key.Public().(ed25519.PublicKey))
	for _, test := range []struct {
		name, payload string
		measured      bool
	}{
		{"canonical", `{"conversation_id":"thread"}`, false},
		{"alias", `{"Conversation_ID":"thread"}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			logs.Reset()
			sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(test.payload)))
			result, err := VerifySignedPayload(test.payload, sig, did, "")
			if result != Verified || err != nil {
				t.Fatalf("signature: %s %v", result, err)
			}
			if SignedPayloadConversationStatus(test.payload, "thread") != Verified {
				t.Fatal("released metadata alias was narrowed")
			}
			if strings.Contains(logs.String(), "aw_noncanonical_signed_metadata_verified") != test.measured {
				t.Fatalf("measurement = %s", logs.String())
			}
			if strings.Contains(logs.String(), sig) {
				t.Fatal("signature leaked to log")
			}
		})
	}
	logs.Reset()
	status, err := VerifySignedPayload(`{"Conversation_ID":"thread"}`, base64.RawStdEncoding.EncodeToString(make([]byte, 64)), did, "")
	if status != Failed || err != nil {
		t.Fatalf("invalid signature: %s %v", status, err)
	}
	if logs.Len() != 0 {
		t.Fatal("unverified metadata counted")
	}
}
