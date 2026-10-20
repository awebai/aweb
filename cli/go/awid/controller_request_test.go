package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestAWIDControllerRequestPublishedVector(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/awid-controller-request-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Seed      string `json:"seed_hex"`
		Body      string `json:"body_utf8"`
		Canonical string `json:"canonical_payload"`
		Signature string `json:"signature_b64"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	headers, err := SignAWIDControllerRequest(key, "POST", "http://registry.test/v1/namespaces/local/teams", []byte(vector.Body), map[string]string{"domain": "local", "operation": "create_team", "name": "vector"}, "2026-06-12T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := base64.RawURLEncoding.DecodeString(headers["X-AWEB-Signed-Payload"])
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != vector.Canonical {
		t.Fatalf("canonical payload differs from published vector: %s", canonical)
	}
	expected := "DIDKey " + ComputeDIDKey(key.Public().(ed25519.PublicKey)) + " " + vector.Signature
	if headers["Authorization"] != expected {
		t.Fatalf("signature differs from published vector")
	}
	for _, name := range []string{"v", "type", "aud", "method", "path", "body_sha256", "timestamp"} {
		if _, err := SignAWIDControllerRequest(key, "POST", "http://registry.test/", nil, map[string]string{name: "override"}, "2026-06-12T10:00:00Z"); err == nil {
			t.Fatalf("reserved claim %s accepted", name)
		}
	}
}

func TestRegisterCertificateRefusesUnsignedBlob(t *testing.T) {
	client := NewAWIDRegistryClient(nil, nil)
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*TeamCertificate{nil, {CertificateID: "unsigned"}} {
		if err := client.RegisterCertificate(context.Background(), "http://127.0.0.1:0", "local", "base", cert, key); err == nil {
			t.Fatal("unsigned certificate accepted")
		}
	}
}
