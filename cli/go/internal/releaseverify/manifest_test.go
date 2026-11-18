package releaseverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestAuthenticationAndRollback(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherPrivate) != ed25519.PrivateKeySize {
		t.Fatal("invalid successor fixture key")
	}
	keys := Keys{"active": base64.StdEncoding.EncodeToString(public), "next": base64.StdEncoding.EncodeToString(other)}
	raw := []byte(`{"schema":"aw-release-manifest-v1","version":"2.0.0","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifacts":{"aw.tgz":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0}}}`)
	statement := []byte(fmt.Sprintf("aw-release-statement-v1\nversion=2.0.0\nsource_commit=%s\nmanifest_sha256=%x\n", strings.Repeat("a", 40), sha256.Sum256(raw)))
	detached, err := json.Marshal(Signature{KeyID: "active", Statement: base64.StdEncoding.EncodeToString(statement), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, statement))})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, requested, current string
		raw, signature           []byte
		want                     string
	}{
		{name: "valid", requested: "2.0.0", current: "1.0.0", raw: raw, signature: detached},
		{name: "rollback requested", requested: "3.0.0", current: "1.0.0", raw: raw, signature: detached, want: "older"},
		{name: "rollback running", requested: "2.0.0", current: "3.0.0", raw: raw, signature: detached, want: "older"},
		{name: "changed bytes", requested: "2.0.0", raw: append(append([]byte(nil), raw...), '\n'), signature: detached, want: "digest"},
		{name: "missing signature", requested: "2.0.0", raw: raw, want: "release-manifest.sig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			artifact, err := Verify(VerificationRequest{ManifestBytes: tc.raw, SignatureBytes: tc.signature, Keys: keys, RequestedVersion: tc.requested, RunningVersion: tc.current, ArtifactName: "aw.tgz"})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "Retry the installer or aw upgrade") {
					t.Fatalf("refusal: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "aw.tgz")
			if err := os.WriteFile(file, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyFile(file, artifact); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyFile(file, artifact); err == nil {
				t.Fatal("changed artifact accepted")
			}
		})
	}
}

func TestMalformedPinnedKeysDoNotPanic(t *testing.T) {
	original := pinnedKeys
	pinnedKeys = []byte("{broken")
	t.Cleanup(func() { pinnedKeys = original })
	defer func() {
		if failure := recover(); failure != nil {
			t.Fatalf("malformed embedded release pins panic: %v", failure)
		}
	}()
	keys, err := PinnedKeys()
	if err == nil || !strings.Contains(err.Error(), "Reinstall aw from a current verified release.") {
		t.Fatalf("missing actionable malformed-pins error: %v", err)
	}
	if keys != nil {
		t.Fatal("malformed pins returned authority")
	}
}

func TestStatementVersionAndCommitMustEqualManifest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"schema":"aw-release-manifest-v1","version":"2.0.0","source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","artifacts":{"aw.tgz":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0}}}`)
	canonical := fmt.Sprintf("aw-release-statement-v1\nversion=2.0.0\nsource_commit=%s\nmanifest_sha256=%x\n", strings.Repeat("a", 40), sha256.Sum256(raw))
	for _, tc := range []struct {
		name      string
		statement string
		want      string
	}{
		{name: "matching metadata", statement: canonical},
		{name: "different version", statement: strings.Replace(canonical, "version=2.0.0", "version=3.0.0", 1), want: "differs from manifest"},
		{name: "different commit", statement: strings.Replace(canonical, strings.Repeat("a", 40), strings.Repeat("b", 40), 1), want: "differs from manifest"},
		{name: "extra line", statement: canonical + "\n", want: "canonical"},
		{name: "CRLF", statement: strings.ReplaceAll(canonical, "\n", "\r\n"), want: "canonical"},
		{name: "oversized", statement: strings.Repeat("x", 257), want: "bounded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statement := []byte(tc.statement)
			envelope, err := json.Marshal(Signature{KeyID: "proof", Statement: base64.StdEncoding.EncodeToString(statement), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(private, statement))})
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(VerificationRequest{ManifestBytes: raw, SignatureBytes: envelope, Keys: Keys{"proof": base64.StdEncoding.EncodeToString(public)}, RequestedVersion: "2.0.0", ArtifactName: "aw.tgz"})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "aw.tgz") || !strings.Contains(err.Error(), "Retry the installer or aw upgrade") {
				t.Fatalf("refusal: %v", err)
			}
		})
	}
}
