package awid

import "testing"

func TestLocalIdentityKeyReplacementPayloadMatchesServerCanonicalOrder(t *testing.T) {
	got, err := LocalIdentityKeyReplacementPayload(LocalIdentityKeyReplacementPayloadInput{
		Alias: "alice",
		Request: LocalIdentityKeyReplacementRequest{
			TeamID: "backend:acme.com", OldDIDKey: "did:key:old", NewDIDKey: "did:key:new",
			OldCertificateID: "cert-old", NewCertificateID: "cert-new",
		},
		Timestamp: "2026-07-23T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_alias":"alice","new_certificate_id":"cert-new","new_did_key":"did:key:new","old_certificate_id":"cert-old","old_did_key":"did:key:old","operation":"replace_local_identity_key","team_id":"backend:acme.com","timestamp":"2026-07-23T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("canonical payload=%s\nwant=%s", got, want)
	}
}

// The server rebuilds this payload with Python's canonical_json_bytes, which
// writes '<', '>', '&', U+2028 and U+2029 as themselves.
func TestLocalIdentityKeyReplacementPayloadWritesTextAsTheServerDoes(t *testing.T) {
	text := "t<&>" + string(rune(0x2028)) + string(rune(0x2029))
	got, err := LocalIdentityKeyReplacementPayload(LocalIdentityKeyReplacementPayloadInput{
		Alias:     "alice",
		Request:   LocalIdentityKeyReplacementRequest{TeamID: text},
		Timestamp: "2026-07-23T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_alias":"alice","new_certificate_id":"","new_did_key":"","old_certificate_id":"","old_did_key":"","operation":"replace_local_identity_key","team_id":"` + text + `","timestamp":"2026-07-23T00:00:00Z"}`
	if string(got) != want {
		t.Fatalf("canonical payload=%q\nwant=%q", got, want)
	}
}
