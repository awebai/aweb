package conformance_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestIDCreationChainImportBindsBeforeRegistration(t *testing.T) {
	fixtures := loadIDChildExchange(t)
	for _, fixture := range []struct{ request, response, status string }{
		{"local-resign", "local-resigned", "alice-rotated"},
		{"human-issue", "human-issued", "normal"},
		{"root-human-issue", "root-human-issued", "normal"},
	} {
		t.Run(fixture.response, func(t *testing.T) {
			parsed, err := awid.ParseIDCertificateResponse([]byte(fixtures.responses[fixture.response].CanonicalUTF8))
			if err != nil {
				t.Fatal(err)
			}
			chain := parsed["chain"].(map[string]any)
			binding := fixtures.requests[fixture.request].Signed["request"].(map[string]any)
			evidence := fixtures.evidence(fixture.status)
			imported, err := awid.ImportIDCertificateChain(binding, chain, evidence, "example.com")
			original, originalErr := awid.ImportIDCertificateResponse(fixtures.requests[fixture.request].Signed,
				[]byte(fixtures.responses[fixture.response].CanonicalUTF8), evidence, "example.com")
			if err != nil || originalErr != nil || !reflect.DeepEqual(imported, original) {
				t.Fatalf("chain import differs from bound exchange: %v / %v", err, originalErr)
			}
			for _, field := range []string{"id", "domain", "parent", "kind"} {
				t.Run("wrong-"+field, func(t *testing.T) {
					wrong := make(map[string]any)
					for key, value := range binding {
						wrong[key] = value
					}
					wrong[field] = "unselected"
					if got, err := awid.ImportIDCertificateChain(wrong, chain, evidence, "example.com"); got != nil || awid.IDCertificateErrorCode(err) != "request_binding_mismatch" {
						t.Fatalf("accepted a different %s: %+v %v", field, got, err)
					}
				})
			}
			raw, marshalErr := json.Marshal(chain)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			var tampered map[string]any
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&tampered); err != nil {
				t.Fatal(err)
			}
			signed := tampered["certificates"].([]any)[0].(map[string]any)
			signature := signed["signature"].(string)
			first := "A"
			if signature[:1] == first {
				first = "B"
			}
			signed["signature"] = first + signature[1:]
			if got, err := awid.ImportIDCertificateChain(binding, tampered, evidence, "example.com"); got != nil || awid.IDCertificateErrorCode(err) != "invalid_signature" {
				t.Fatalf("accepted bogus parent signature: %+v %v", got, err)
			}

			if got, err := awid.ImportIDCertificateChain(binding, chain, nil, "example.com"); got != nil || awid.IDCertificateErrorCode(err) != "evidence_unavailable" {
				t.Fatalf("accepted without issuer evidence: %+v %v", got, err)
			}
		})
	}
}
