package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInventoryExemptionRequiresExactlyOneCall(t *testing.T) {
	const declaration = `package p; import ed "crypto/ed25519"; `
	const entry = `{"file":"consumer.go","symbol":"Check","callee":"crypto/ed25519.Verify","reason":"Existing signed family."}`
	for _, tc := range []struct {
		name, source, entries, want string
	}{
		{"unused", `func Check(){}`, entry, "unused primitive exemption: consumer.go:Check: crypto/ed25519.Verify"},
		{"missing file", "", entry, "listed source file consumer.go is missing"},
		{"one call", `func Check(){ ed.Verify(k,p,s) }`, entry, ""},
		{"second call", `func Check(){ ed.Verify(k,p,s); ed.Verify(k,q,s) }`, entry, "primitive exemption matches 2 calls: consumer.go:Check: crypto/ed25519.Verify"},
		{"different symbol", `func Check(){ ed.Verify(k,p,s) }; func Other(){ ed.Verify(k,p,s) }`, entry, "raw Go crypto must use the shared verifier: consumer.go:Other: crypto/ed25519.Verify"},
		{"duplicate", `func Check(){ ed.Verify(k,p,s) }`, entry + "," + entry, "duplicate primitive exemption: consumer.go:Check: crypto/ed25519.Verify"},
		{"blank reason", `func Check(){ ed.Verify(k,p,s) }`, strings.Replace(entry, "Existing signed family.", " ", 1), "primitive exemption requires file, symbol, callee and reason"},
		{"reference", `func Check(){ callback(ed.Verify) }`, strings.Replace(entry, "crypto/ed25519.Verify", "reference:crypto/ed25519.Verify", 1), "primitive exemption must name a call: consumer.go:Check: reference:crypto/ed25519.Verify"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if out, err := exec.Command("git", "init", "-q", root).CombinedOutput(); err != nil {
				t.Fatalf("git init: %v: %s", err, out)
			}
			if tc.source != "" {
				if err := os.WriteFile(filepath.Join(root, "consumer.go"), []byte(declaration+tc.source), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(root, "docs"), 0o700); err != nil {
				t.Fatal(err)
			}
			data := fmt.Sprintf(`{"primitive_guard":{"exempt_calls":[%s]}}`, tc.entries)
			if err := os.WriteFile(filepath.Join(root, "docs", "identity-tree-coverage.json"), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			err := run(root)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

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
		{"pkg/consumer.go", "Check", false}, {strictModule, "Verify", true}, {strictModule, "PrimePoint", true},
		{strictModule, "VerifyIDCertificate", false}, {strictModule, "idSignatureBytes", false}, {strictModule, "bypass", false},
	} {
		errors := checkPrimitiveUses(map[siteKey]map[string]int{{c.file, c.symbol}: calls["Check"]}, nil)
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
	uses := map[siteKey]map[string]int{}
	for symbol, c := range calls {
		uses[siteKey{"pkg/consumer.go", symbol}] = c
	}
	if errors := checkPrimitiveUses(uses, nil); len(errors) > 0 {
		t.Fatal(errors)
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

func TestEd25519OptionsAndSignerCalls(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []string
	}{
		{
			name:   "verify with options",
			source: `import ed "crypto/ed25519"; func Check(){ ed.VerifyWithOptions(k, m, s, opts) }`,
			want:   []string{"raw Go crypto must use the shared verifier: consumer.go:Check: crypto/ed25519.VerifyWithOptions"},
		},
		{
			name:   "hash zero signer",
			source: `import c "crypto"; func Check(){ priv.Sign(nil, m, c.Hash(0)) }`,
			want:   []string{"raw Go crypto must use the shared verifier: consumer.go:Check: crypto.Signer.Sign"},
		},
		{
			name:   "hashed signer and standalone hash conversion",
			source: `import "crypto"; func Check(){ priv.Sign(nil, digest, crypto.SHA256); _ = crypto.Hash(0) }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, err := scanGoSource([]byte("package p; " + tc.source))
			if err != nil {
				t.Fatal(err)
			}
			got := checkPrimitiveUses(map[siteKey]map[string]int{{"consumer.go", "Check"}: calls["Check"]}, nil)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
