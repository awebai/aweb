package awid

import (
	"encoding/json"
	"testing"
)

func TestTypedIDChainVerdictKeepsTheFrozenResultProfile(t *testing.T) {
	vectors := loadStatusVectors(t)
	for _, test := range vectors.Cases {
		if test.Status != "normal" || test.Expected.Outcome != "nearest_human" {
			continue
		}
		var bundle map[string]any
		if len(test.Chain) != 0 {
			certificates := make([]any, 0, len(test.Chain))
			for _, name := range test.Chain {
				certificates = append(certificates, vectors.Certificates[name].Signed)
			}
			bundle = map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}
		}
		encodedSubject, err := json.Marshal(test.Subject)
		if err != nil {
			t.Fatal(err)
		}
		var subject IDChainSubject
		if err := json.Unmarshal(encodedSubject, &subject); err != nil {
			t.Fatal(err)
		}
		verdict := CheckIDChain(bundle, subject, normalEvidence(t, nil), "example.com")
		if verdict.Outcome != IDChainOutcomeNearestHuman || verdict.Refusal != "" {
			t.Fatalf("frozen case %s: %+v", test.Name, verdict)
		}
		got, err := json.Marshal(verdict)
		if err != nil {
			t.Fatal(err)
		}
		want, err := json.Marshal(test.Expected)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("frozen case %s changed profile:\n%s\n%s", test.Name, got, want)
		}
		return
	}
	t.Fatal("missing ordinary nearest-human vector")
}

func TestTypedRequestPolicyRetainsLocalAdvisoryAndHumanRequiredRules(t *testing.T) {
	subject := IDChainSubject{ID: "did:key:local", DIDKey: "did:key:local"}
	verdict := CheckIDChain(nil, subject, nil, "")
	if verdict.Outcome != IDChainOutcomeUnknown || verdict.Refusal != IDRefusalLegacyNoChain {
		t.Fatalf("chainless local result changed: %+v", verdict)
	}
	if DecideIDRequest(IDRequestInput{Verdict: verdict, Subject: subject, AuthenticationPassed: true}) != IDRequestContinue {
		t.Fatal("ordinary authenticated local identity was refused")
	}
	if DecideIDRequest(IDRequestInput{Verdict: verdict, Subject: subject, AuthenticationPassed: true, HumanRequired: true}) != IDRequestRefuse {
		t.Fatal("chainless local identity satisfied human-required policy")
	}
	if DecideIDRequest(IDRequestInput{Verdict: verdict, Subject: subject}) != IDRequestRefuse {
		t.Fatal("ancestry replaced request authentication")
	}
}
