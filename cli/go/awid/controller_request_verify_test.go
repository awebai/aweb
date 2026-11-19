package awid

import "testing"

func TestAControllerRequestSignatureVerifiesOnlyOverItsOwnPayloadAndKey(t *testing.T) {
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"operation":"protected_operation_prepare"}`)
	did, signature, err := KeySigner(key)(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyControllerRequestSignature(did, signature, payload); err != nil {
		t.Fatalf("its own signature: %v", err)
	}
	otherDID, _, _ := KeySigner(other)(payload)
	for name, check := range map[string]func() error{
		"another payload": func() error { return VerifyControllerRequestSignature(did, signature, append(payload, ' ')) },
		"another key":     func() error { return VerifyControllerRequestSignature(otherDID, signature, payload) },
		"a short signature": func() error {
			return VerifyControllerRequestSignature(did, signature[:63], payload)
		},
		"no key": func() error { return VerifyControllerRequestSignature("did:key:z", signature, payload) },
	} {
		if check() == nil {
			t.Errorf("%s verified", name)
		}
	}
}
