package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func signedChainViewFixture(t *testing.T) (map[string]any, string) {
	t.Helper()
	issuerPublic, issuer, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	childPublic, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	id := ComputeDIDKey(childPublic)
	certificate := map[string]any{"v": 1, "type": "aweb.id-certificate", "id": id, "domain": "example.com", "parent": map[string]any{"kind": "namespace", "id": "example.com"}, "kind": "agent", "issuer_key": ComputeDIDKey(issuerPublic), "issued_at": "2026-01-01T00:00:00Z"}
	payload, err := IDCertificateSigningBytes(certificate)
	if err != nil {
		t.Fatal(err)
	}
	signed := map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuer, payload))}
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{signed}}, id
}

func TestIDChainViewChecksTheBundleAndKeepsItsOwnSnapshot(t *testing.T) {
	bundle, id := signedChainViewFixture(t)
	chain, err := IDChainFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	leaf := chain.Leaf()
	if leaf.ID() != id || leaf.Domain() != "example.com" || leaf.Kind() != IDCertificateKindAgent || leaf.Parent().Kind() != IDParentKindNamespace || leaf.Parent().ID() != "example.com" {
		t.Fatalf("wrong checked leaf: %+v", leaf)
	}
	wantHeader, err := EncodeIDChainHeader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundle["certificates"] = []any{}
	copy := chain.Bundle()
	copy["certificates"] = []any{}
	certificates := chain.Certificates()
	certificates[0] = IDCertificateView{}
	if chain.Leaf().ID() != id || len(chain.Certificates()) != 1 {
		t.Fatal("caller changed the checked chain snapshot")
	}
	header, err := chain.Header()
	if err != nil || header != wantHeader {
		t.Fatalf("checked view changed signed bytes: %v", err)
	}
}

func TestIDChainViewRefusesMalformedOrInvalidlySignedBundles(t *testing.T) {
	for _, name := range []string{"empty", "wrong certificate type", "bad signature"} {
		t.Run(name, func(t *testing.T) {
			bundle, _ := signedChainViewFixture(t)
			switch name {
			case "empty":
				bundle["certificates"] = []any{}
			case "wrong certificate type":
				bundle["certificates"] = []any{"not a signed certificate"}
			case "bad signature":
				bundle["certificates"].([]any)[0].(map[string]any)["signature"] = "invalid"
			}
			if _, err := IDChainFromBundle(bundle); err == nil {
				t.Fatal("invalid bundle became a checked view")
			}
		})
	}
}
