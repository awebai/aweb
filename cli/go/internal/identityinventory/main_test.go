package main

import "testing"

func TestPrimitiveBoundary(t *testing.T) {
	source := []byte(`package p; import ed "crypto/ed25519"; func Check(){ ed.Verify(k,p,s) }`)
	calls, err := scanGoSource(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		file, symbol string
		allowed      bool
	}{
		{"pkg/consumer.go", "Check", false}, {strictModule, "idStrictVerify", true}, {strictModule, "idCertificatePrimePoint", true},
		{strictModule, "VerifyIDCertificate", false}, {strictModule, "idSignatureBytes", false}, {strictModule, "bypass", false},
	} {
		var uses map[string]bool
		for _, v := range calls {
			uses = v
		}
		errors := checkPrimitiveUses(map[siteKey]map[string]bool{{c.file, c.symbol}: uses}, nil)
		if (len(errors) == 0) != c.allowed {
			t.Fatalf("%+v: %v", c, errors)
		}
	}
}
func TestPublicHelperDoesNotRequireCatalog(t *testing.T) {
	calls, err := scanGoSource([]byte(`package p; import "github.com/awebai/aw/awid"; func Check(){ awid.VerifyIDCertificate(c,k) }`))
	if err != nil {
		t.Fatal(err)
	}
	uses := map[siteKey]map[string]bool{}
	for symbol, c := range calls {
		uses[siteKey{"pkg/consumer.go", symbol}] = c
	}
	if errors := checkPrimitiveUses(uses, nil); len(errors) > 0 {
		t.Fatal(errors)
	}
}
func TestLegacyReasonAndRepeatedCalls(t *testing.T) {
	uses := map[siteKey]map[string]bool{{"pkg/legacy.go", "Sign"}: {"crypto/ed25519.Sign": true}}
	if e := checkPrimitiveUses(uses, []legacyFile{{File: "pkg/legacy.go", Reason: "Existing released message signature family."}}); len(e) > 0 {
		t.Fatal(e)
	}
	if e := checkPrimitiveUses(uses, []legacyFile{{File: "pkg/legacy.go"}}); len(e) == 0 {
		t.Fatal("missing legacy reason accepted")
	}
}
func TestPackageAliasesAndCallbackReferences(t *testing.T) {
	calls, err := scanGoSource([]byte(`package p; import curve "filippo.io/edwards25519"; import ed "crypto/ed25519"; func Check(){ callback(ed.Verify); _=curve.NewIdentityPoint() }`))
	if err != nil {
		t.Fatal(err)
	}
	if len(calls["Check"]) != 2 {
		t.Fatal(calls)
	}
}
