package awconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func frozenChain(t *testing.T, names ...string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "id-certificates-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Certificates map[string]struct {
			Signed map[string]any `json:"signed"`
		} `json:"certificates"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var certs []any
	for _, n := range names {
		certs = append(certs, v.Certificates[n].Signed)
	}
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-chain", "certificates": certs}
}

const coordinatorKey = "did:key:z6Mkon22vwz9JoNpGDxCrGZRgeNFTdRTwXYYN3fvAhA3K19x"

func TestInstalledIDChainAbsentMeansNoChain(t *testing.T) {
	chain, err := LoadInstalledIDChain(t.TempDir())
	if err != nil || chain != nil {
		t.Fatalf("chain=%v err=%v", chain, err)
	}
}

func TestInstalledIDChainRoundTripsWithItsHeader(t *testing.T) {
	home := t.TempDir()
	bundle := frozenChain(t, "alice", "coordinator")
	if err := SaveInstalledIDChain(home, bundle); err != nil {
		t.Fatal(err)
	}
	chain, err := LoadInstalledIDChain(home)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(chain.Bundle, bundle) {
		t.Fatalf("bundle %v", chain.Bundle)
	}
	header, err := awid.EncodeIDChainHeader(bundle)
	if err != nil || chain.Header != header {
		t.Fatalf("header %q (%v)", chain.Header, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(home, "id-chain.json"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v (%v)", info.Mode().Perm(), err)
		}
	}
}

func TestInstalledIDChainSaveRefusesAnInvalidBundle(t *testing.T) {
	home := t.TempDir()
	bundle := frozenChain(t, "alice", "coordinator")
	leaf := bundle["certificates"].([]any)[1].(map[string]any)
	tampered := map[string]any{"certificate": leaf["certificate"], "signature": bundle["certificates"].([]any)[0].(map[string]any)["signature"]}
	bundle["certificates"] = []any{bundle["certificates"].([]any)[0], tampered}
	if err := SaveInstalledIDChain(home, bundle); awid.IDCertificateErrorCode(err) != "invalid_signature" {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "id-chain.json")); !os.IsNotExist(err) {
		t.Fatal("an invalid bundle was written")
	}
}

func TestInstalledIDChainLoadRefusesDamagedFiles(t *testing.T) {
	canonical, err := awid.CanonicalJSONValue(frozenChain(t, "alice", "coordinator"))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		data   string
		reason string
	}{
		"garbage":      {"not json", "invalid_json"},
		"noncanonical": {strings.Replace(canonical, ",", ", ", 1), "noncanonical_json"},
		"oversized":    {strings.Repeat("x", awid.IDChainMaxBytes+1), "bundle_too_large"},
		"tampered":     {strings.Replace(canonical, `"kind":"agent"`, `"kind":"human"`, 1), "invalid_shape"},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, "id-chain.json"), []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			chain, err := LoadInstalledIDChain(home)
			if chain != nil || awid.IDCertificateErrorCode(err) != tc.reason {
				t.Fatalf("chain=%v err=%v want %s", chain, err, tc.reason)
			}
		})
	}
}

func TestInstalledIDChainSubject(t *testing.T) {
	local := &InstalledIDChain{Bundle: frozenChain(t, "alice", "coordinator")}
	subject, err := local.Subject(coordinatorKey)
	if err != nil || subject != (awid.IDChainSubject{ID: coordinatorKey, DIDKey: coordinatorKey}) {
		t.Fatalf("local subject %+v (%v)", subject, err)
	}
	if _, err := local.Subject("did:key:z6MkmtWtY63GQVBrpMyRJWEzsnxfsGkemu6CtMDwGTv4RYj2"); awid.IDCertificateErrorCode(err) != "subject_mismatch" {
		t.Fatalf("another key: %v", err)
	}
	human := &InstalledIDChain{Bundle: frozenChain(t, "alice")}
	key := "did:key:z6Mkt6316e2PN3mZdB6N9CrzomJYUd1s5yBZi1XYHmwT9TUP"
	subject, err = human.Subject(key)
	if err != nil || subject != (awid.IDChainSubject{ID: "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", DIDKey: key}) {
		t.Fatalf("global subject %+v (%v)", subject, err)
	}
}
