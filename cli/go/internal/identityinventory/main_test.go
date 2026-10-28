package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoScannerFindsIdentitySites(t *testing.T) {
	cases := []struct{ name, source, symbol, primitive string }{
		{"aliased raw verify", `package p; import ed "crypto/ed25519"; func f(){ed.Verify(a,b,c)}`, "f", "crypto/ed25519.Verify"},
		{"dot import", `package p; import . "crypto/ed25519"; func f(){Verify(a,b,c)}`, "", ""},
		{"renamed identity API", `package p; import id "github.com/awebai/aw/awid"; func f(){id.VerifyIDChain(a,b,c)}`, "f", "github.com/awebai/aw/awid.VerifyIDChain"},
		{"callback", `package p; import ed "crypto/ed25519"; func f(){check := ed.Verify; _ = check}`, "f", "reference:crypto/ed25519.Verify"},
		{"method expression", `package p; import ed "crypto/ed25519"; type T struct{}; func (x *T) f(){_ = ed.Sign}`, "(*T).f", "reference:crypto/ed25519.Sign"},
		{"generic wrapper", `package p; func f(){verifyProof(a)}`, "f", "verifyProof"},
		{"DID prefix", `package p; const prefix = "did:key:z"; func f(){_ = "did:aw:"+a}`, "<module>", "literal:did:key"},
		{"nested closure", `package p; import ed "crypto/ed25519"; func f(){run(func(){ed.GenerateKey(nil)})}`, "f", "crypto/ed25519.GenerateKey"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := scanGoSource([]byte(c.source))
			if c.symbol == "" {
				if err == nil {
					t.Fatal("dot crypto import must refuse")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got[c.symbol][c.primitive] != 1 {
				t.Fatalf("missing %s.%s: %#v", c.symbol, c.primitive, got)
			}
		})
	}
}

func TestGoScannerIgnoresCommentsAndOrdinaryCalls(t *testing.T) {
	got, err := scanGoSource([]byte("package p; // did:key:z\nfunc f(){ println(\"ordinary\"); _ = 1 }"))
	if err != nil || len(got) != 0 {
		t.Fatalf("%#v %v", got, err)
	}
}

func TestGoCatalogDetectsDriftAndStrictBypasses(t *testing.T) {
	file := "cli/go/awid/id_certificates.go"
	key := siteKey{file, "VerifyIDCertificate"}
	rows := map[string]row{"r": {ID: "r", Repo: "aweb", Files: []string{file}, Profile: "strict", Sites: []site{{File: file, Symbol: key.Symbol}}}}
	entry := catalogSite{Row: "r", File: file, Symbol: key.Symbol, Calls: map[string]int{"crypto/ed25519.Verify": 1}}
	observed := map[siteKey]map[string]int{key: entry.Calls}
	if es := checkCatalog(rows, []catalogSite{entry}, observed); len(es) != 0 {
		t.Fatal(es)
	}
	for _, c := range []struct {
		name    string
		entries []catalogSite
		actual  map[siteKey]map[string]int
		want    string
	}{
		{"new site", nil, observed, "unlisted"},
		{"stale", []catalogSite{entry}, map[siteKey]map[string]int{}, "stale"},
		{"count drift", []catalogSite{entry}, map[siteKey]map[string]int{key: {"crypto/ed25519.Verify": 2}}, "changed"},
		{"duplicate", []catalogSite{entry, entry}, observed, "duplicate"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(strings.Join(checkCatalog(rows, c.entries, c.actual), "\n"), c.want) {
				t.Fatal("did not refuse " + c.want)
			}
		})
	}
	rogue := entry
	rogue.Symbol = "anotherVerifier"
	rows["r"] = row{ID: "r", Repo: "aweb", Files: []string{file}, Profile: "strict", Sites: []site{{File: file, Symbol: rogue.Symbol}}}
	if es := checkCatalog(rows, []catalogSite{rogue}, map[siteKey]map[string]int{{file, rogue.Symbol}: rogue.Calls}); !strings.Contains(strings.Join(es, "\n"), "shared strict") {
		t.Fatal(es)
	}
	rows["r"] = row{ID: "r", Repo: "aweb", Files: []string{file}, Profile: "legacy", Sites: []site{{File: file, Symbol: key.Symbol}}}
	if es := checkCatalog(rows, []catalogSite{entry}, observed); !strings.Contains(strings.Join(es, "\n"), "downgrade") {
		t.Fatal(es)
	}
}

func TestGoSourceExclusions(t *testing.T) {
	for _, file := range []string{"new/package/identity.go", "cli/go/awid/test_identity.go", "cli/go/awid/test/source.go"} {
		if excluded(file) {
			t.Fatal("production excluded: " + file)
		}
	}
	for _, file := range []string{"cli/go/awid/identity_test.go", "new/testdata/fixture.go", "cli/go/internal/identityinventory/main.go"} {
		if !excluded(file) {
			t.Fatal("fixture/scanner included: " + file)
		}
	}
}

func TestGoScannerCatchesNewPackageAndRawBypass(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	directory := filepath.Join(root, "new", "package")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(directory, "identity.go")
	source := `package p; import renamed "crypto/ed25519"; func added(){renamed.Verify(a,b,c)}`
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	observed, err := scanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	errors := checkCatalog(map[string]row{}, nil, observed)
	if !strings.Contains(strings.Join(errors, "\n"), "unlisted Go identity primitive site") {
		t.Fatalf("new package bypassed guard: %v", errors)
	}
	// Listing a raw verifier under a strict row does not exempt it.
	key := siteKey{"new/package/identity.go", "added"}
	rows := map[string]row{"strict": {ID: "strict", Repo: "aweb", Files: []string{key.File}, Profile: "strict", Sites: []site{{File: key.File, Symbol: key.Symbol}}}}
	entries := []catalogSite{{Row: "strict", File: key.File, Symbol: key.Symbol, Calls: observed[key]}}
	if !strings.Contains(strings.Join(checkCatalog(rows, entries, observed), "\n"), "shared strict") {
		t.Fatal("listed strict raw verifier bypassed guard")
	}
}

func TestGoCryptoPackagesArePrimitiveRegardlessOfName(t *testing.T) {
	for _, module := range []string{"crypto/ed25519", "golang.org/x/crypto/ed25519", "filippo.io/edwards25519"} {
		for _, operation := range []string{"SetBytes", "SetCanonicalBytes", "SetUniformBytes", "VarTimeDoubleScalarBaseMult", "Negate", "Bytes", "VerifyWithOptions"} {
			t.Run(module+"/"+operation, func(t *testing.T) {
				source := `package p; import curve "` + module + `"; func f(){curve.` + operation + `(a)}`
				got, err := scanGoSource([]byte(source))
				if err != nil {
					t.Fatal(err)
				}
				if got["f"][module+"."+operation] != 1 {
					t.Fatalf("package primitive hidden: %#v", got)
				}
			})
		}
	}
}

func TestGoIdentityPublicAPIIsDiscoveredFromSource(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, output)
	}
	directory := filepath.Join(root, "cli", "go", "awid")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	source := `package awid; func GenerateKeypair(){}; func ComputeStableID(){}; func LoadSigningKey(){}; func SaveSigningKey(){}; func EncodeTeamCertificateHeader(){}; func DecodeTeamCertificateHeader(){}; func ScanKeysForPublicKey(){}; type Client struct{}; func (*Client) RotateDIDKey(){}`
	if err := os.WriteFile(filepath.Join(directory, "keys_new.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	consumer := `package x; import id "github.com/awebai/aw/awid"; func f(){id.GenerateKeypair();id.ComputeStableID();id.LoadSigningKey();id.SaveSigningKey();id.EncodeTeamCertificateHeader();id.DecodeTeamCertificateHeader();id.ScanKeysForPublicKey();client.RotateDIDKey()}`
	if err := os.WriteFile(filepath.Join(root, "consumer.go"), []byte(consumer), 0600); err != nil {
		t.Fatal(err)
	}
	sites, err := scanRepository(root)
	if err != nil {
		t.Fatal(err)
	}
	calls := sites[siteKey{"consumer.go", "f"}]
	for _, name := range []string{"GenerateKeypair", "ComputeStableID", "LoadSigningKey", "SaveSigningKey", "EncodeTeamCertificateHeader", "DecodeTeamCertificateHeader", "ScanKeysForPublicKey"} {
		if calls["github.com/awebai/aw/awid."+name] != 1 {
			t.Fatal("undiscovered API: " + name)
		}
	}
	if calls["client.RotateDIDKey"] != 1 {
		t.Fatal("rotation escaped")
	}
}

func TestGoHandRolledVerifyCannotHideInStrictRow(t *testing.T) {
	source := `package p; import curve "filippo.io/edwards25519"; func alternate(){
  A,_:=new(curve.Point).SetBytes(a); R,_:=new(curve.Point).SetBytes(r)
  S,_:=new(curve.Scalar).SetCanonicalBytes(s); K,_:=new(curve.Scalar).SetUniformBytes(k)
  check:=new(curve.Point).VarTimeDoubleScalarBaseMult(K,A,S)
  _=check.Equal(R); _=new(curve.Point).Negate(A).Bytes()
 }`
	got, err := scanGoSource([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	calls := got["alternate"]
	for _, name := range []string{"filippo.io/edwards25519.Point().SetBytes", "filippo.io/edwards25519.Scalar().SetCanonicalBytes", "filippo.io/edwards25519.Scalar().SetUniformBytes", "filippo.io/edwards25519.Point().VarTimeDoubleScalarBaseMult", "filippo.io/edwards25519.Point().Negate"} {
		if calls[name] < 1 {
			t.Fatalf("hand-rolled verify missed %s: %#v", name, calls)
		}
	}
	file := "new/package/alternate.go"
	rows := map[string]row{"strict": {ID: "strict", Repo: "aweb", Profile: "strict", Files: []string{file}, Sites: []site{{File: file, Symbol: "alternate"}}}}
	entries := []catalogSite{{Row: "strict", File: file, Symbol: "alternate", Calls: calls}}
	if errors := checkCatalog(rows, entries, map[siteKey]map[string]int{{file, "alternate"}: calls}); !strings.Contains(strings.Join(errors, "\n"), "shared strict") {
		t.Fatal(errors)
	}
}
