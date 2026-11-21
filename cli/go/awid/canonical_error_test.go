package awid

import "testing"

func TestCurrentCertificateDigestFailureDoesNotMatchEmptyID(t *testing.T) {
	certificate := map[string]any{"unsupported": float64(1)}
	if idCurrentCertificateMatches(certificate, "") {
		t.Fatal("an unencodable certificate matched an empty commitment")
	}
	valid := map[string]any{"v": 1, "name": "checked"}
	digest, err := IDCertificateID(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !idCurrentCertificateMatches(valid, digest) {
		t.Fatal("an encodable certificate did not match its own commitment")
	}
	if idCurrentCertificateMatches(valid, digest+"changed") {
		t.Fatal("a different commitment matched")
	}
}
