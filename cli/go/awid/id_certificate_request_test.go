package awid

import "testing"

func TestSignIDCertificateRequestProducesAParsableRequestUnderTheSubjectKey(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": "20000000-0000-4000-8000-000000000001", "operation": "issue",
		"id": ComputeStableID(pub), "domain": "example.com", "parent": map[string]any{"kind": "namespace", "id": "example.com"},
		"kind": "human", "subject_key": ComputeDIDKey(pub), "invitation_id": "10000000-0000-4000-8000-000000000001", "old_certificate": nil,
	}
	raw, err := SignIDCertificateRequest(request, KeySigner(key))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseIDCertificateRequest(raw); err != nil {
		t.Fatalf("signed request does not parse: %v", err)
	}
	_, other, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := SignIDCertificateRequest(request, KeySigner(other)); err == nil || raw != nil {
		t.Fatal("signed a request with a key other than its subject key")
	}
}
