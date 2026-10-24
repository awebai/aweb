package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDIDKeyRequestHeadersForAudienceBindEveryRequestComponent(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"steward","inbound_mode":"contacts_only"}`)
	headers, err := DIDKeyRequestHeadersForAudience("POST", "/api/v1/cli/identities", "https://cloud.example", body, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Fields(headers["Authorization"])
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != ComputeDIDKey(pub) {
		t.Fatal("wrong request credential")
	}
	timestamp := headers["X-AWEB-Timestamp"]
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(parsed) > time.Minute || time.Until(parsed) > time.Minute {
		t.Fatal("invalid request timestamp")
	}
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	fields := map[string]string{"aud": "https://cloud.example", "body_sha256": hex.EncodeToString(digest[:]), "method": "POST", "path": "/api/v1/cli/identities", "timestamp": timestamp}
	canonical, _ := json.Marshal(fields)
	if !ed25519.Verify(pub, canonical, sig) {
		t.Fatal("independent request envelope did not verify")
	}
	for _, field := range []string{"aud", "body_sha256", "method", "path", "timestamp"} {
		t.Run(field, func(t *testing.T) {
			altered := make(map[string]string, len(fields))
			for k, v := range fields {
				altered[k] = v
			}
			altered[field] += "-changed"
			encoded, _ := json.Marshal(altered)
			if ed25519.Verify(pub, encoded, sig) {
				t.Error("substituted request component verified")
			}
		})
	}
}

func TestDIDKeyRequestHeadersForAudienceRefuseMissingAuthority(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DIDKeyRequestHeadersForAudience("POST", "/api/v1/cli/identities", "https://cloud.example", nil, nil); err == nil {
		t.Error("accepted missing signing key")
	}
	for _, aud := range []string{"", "https://cloud.example/other", "https://user@cloud.example", "https://cloud.example?other=true", "https://cloud.example?"} {
		if _, err := DIDKeyRequestHeadersForAudience("POST", "/api/v1/cli/identities", aud, nil, key); err == nil {
			t.Error("accepted a non-origin audience")
		}
	}
}
