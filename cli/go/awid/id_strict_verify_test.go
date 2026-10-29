package awid

import "testing"

// idStrictVerify holds its own length check: a short signature from any
// caller is refused, never sliced.
func TestIDStrictVerifyRefusesASignatureOfTheWrongLength(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 31, 63, 65} {
		err := idStrictVerify(ComputeDIDKey(pub), make([]byte, n), func() ([]byte, error) { return []byte("payload"), nil })
		if IDCertificateErrorCode(err) != "invalid_signature" {
			t.Fatalf("length %d: %v", n, err)
		}
	}
}
