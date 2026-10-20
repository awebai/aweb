package awid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Sign the actual v2 wire shape independently of the production certificate builder.
func lifetimeCertificate(t *testing.T, expiry any, include bool) (*TeamCertificate, ed25519.PublicKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"version": 2, "certificate_id": "finite-cert", "team_id": "ops:example.test",
		"team_did_key": ComputeDIDKey(pub), "member_did_key": ComputeDIDKey(pub),
		"alias": "alice", "identity_scope": "local", "validity_class": "member",
		"issued_at": "2026-01-01T00:00:00Z",
	}
	if include {
		payload["expires_at"] = expiry
	}
	canonical, err := CanonicalJSONValue(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["signature"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(canonical)))
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var cert TeamCertificate
	if err := json.Unmarshal(data, &cert); err != nil {
		t.Fatal(err)
	}
	return &cert, pub
}

func TestCertificateV2OptionalSignedExpiry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expiry  any
		include bool
		want    string
	}{
		{"unbounded", nil, false, ""},
		{"future", time.Now().Add(time.Hour).UTC().Format(time.RFC3339), true, ""},
		{"expired", "2026-01-02T00:00:00Z", true, "certificate_expired"},
		{"malformed", "not-a-time", true, "certificate_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, pub := lifetimeCertificate(t, tc.expiry, tc.include)
			err := VerifyTeamCertificate(cert, pub)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
			// Transport round trips must preserve every signed field.
			encoded, err := EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			again, err := DecodeTeamCertificateHeader(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if err := VerifyTeamCertificate(again, pub); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
