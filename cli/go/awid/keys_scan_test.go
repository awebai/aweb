package awid

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestScanKeysForPublicKeyFindsExpectedPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	address := "mycompany/researcher"
	if err := SaveKeypair(keysDir, address, pub, priv); err != nil {
		t.Fatal(err)
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, pub)
	if err != nil {
		t.Fatal(err)
	}
	expected := SigningKeyPath(keysDir, address)
	if foundPath != expected {
		t.Fatalf("got %q, want %q", foundPath, expected)
	}
}

func TestScanKeysForPublicKeyFindsAmongMultiple(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	var targetPub ed25519.PublicKey
	for i, addr := range []string{"ns/alice", "ns/bob", "ns/carol"} {
		pub, priv, err := GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			targetPub = pub
		}
		if err := SaveKeypair(keysDir, addr, pub, priv); err != nil {
			t.Fatal(err)
		}
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, targetPub)
	if err != nil {
		t.Fatal(err)
	}
	expected := SigningKeyPath(keysDir, "ns/bob")
	if foundPath != expected {
		t.Fatalf("got %q, want %q", foundPath, expected)
	}
}

func TestScanKeysForPublicKeyFindsInRotated(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	// Archive the key (simulating a rotation).
	oldDID := "did:key:z6Mktest"
	if err := ArchiveKey(keysDir, oldDID, pub, priv); err != nil {
		t.Fatal(err)
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if foundPath == "" {
		t.Fatal("expected to find archived key, got empty")
	}
}

func TestScanKeysForPublicKeyNotFound(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeypair(keysDir, "ns/alice", pub, priv); err != nil {
		t.Fatal(err)
	}

	otherPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, otherPub)
	if err != nil {
		t.Fatal(err)
	}
	if foundPath != "" {
		t.Fatalf("expected empty, got %q", foundPath)
	}
}

func TestScanKeysForPublicKeySkipsMalformedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveKeypair(keysDir, "ns/good", pub, priv); err != nil {
		t.Fatal(err)
	}

	// Create a malformed .key file.
	badPath := filepath.Join(keysDir, "bad.signing.key")
	if err := os.WriteFile(badPath, []byte("not a valid PEM file"), 0o600); err != nil {
		t.Fatal(err)
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if foundPath == "" {
		t.Fatal("should find good key despite malformed file present")
	}
}

func TestScanKeysForPublicKeyEmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}

	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	foundPath, err := ScanKeysForPublicKey(keysDir, pub)
	if err != nil {
		t.Fatal(err)
	}
	if foundPath != "" {
		t.Fatalf("expected empty, got %q", foundPath)
	}
}
