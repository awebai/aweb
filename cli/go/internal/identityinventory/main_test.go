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
