package awid

import (
	"bytes"
	"testing"
)

func TestIDRequestViewKeepsTheVerifiedRequestIndependentOfCallerMaps(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	id := ComputeStableID(pub)
	raw, err := SignIDCertificateRequest(map[string]any{
		"v": 1, "type": "aweb.id-certificate-request", "request_id": "20000000-0000-4000-8000-000000000001", "operation": "issue",
		"id": id, "domain": "example.com", "parent": map[string]any{"kind": "namespace", "id": "example.com"},
		"kind": "human", "subject_key": ComputeDIDKey(pub), "invitation_id": "10000000-0000-4000-8000-000000000001", "old_certificate": nil,
	}, KeySigner(key))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeIDCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if request.InvitationID() != "10000000-0000-4000-8000-000000000001" || request.ID() != id || request.RequestID() != "20000000-0000-4000-8000-000000000001" || request.Domain() != "example.com" || request.Operation() != IDCertificateRequestIssue || request.Kind() != IDCertificateKindHuman || request.SubjectKey() != ComputeDIDKey(pub) || request.Parent().Kind() != IDParentKindNamespace || request.Parent().ID() != "example.com" {
		t.Fatal("request binding lost")
	}
	copy := request.Signed()
	fields, ok := copy["request"].(map[string]any)
	if !ok {
		t.Fatal("missing signed request")
	}
	fields["id"] = "mutated"
	again, err := idCertificateCanonical(request.Signed())
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("caller mutation reached the checked request")
	}
	if _, err := DecodeIDCertificateRequest([]byte(`{"request":null,"signature":""}`)); err == nil {
		t.Fatal("unchecked request received a view")
	}
}

func TestIDResponseViewPreservesTheExactChainThroughTheMapAdapter(t *testing.T) {
	bundle, id := signedChainViewFixture(t)
	raw, err := EncodeIDCertificateResponse("20000000-0000-4000-8000-000000000001", bundle)
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeIDCertificateResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestID() != "20000000-0000-4000-8000-000000000001" || response.Chain().Leaf().ID() != id {
		t.Fatal("response selection lost")
	}
	copy := response.Chain().Bundle()
	copy["certificates"] = nil
	again, err := EncodeIDCertificateResponse(response.RequestID(), response.Chain().Bundle())
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatal("response signature bytes or owned chain changed")
	}
	if _, err := DecodeIDCertificateResponse([]byte(`{"v":1,"request_id":"invalid","chain":{}}`)); err == nil {
		t.Fatal("unchecked response received a view")
	}
}
