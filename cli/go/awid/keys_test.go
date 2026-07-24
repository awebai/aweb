package awid

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	t.Parallel()

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key length=%d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private key length=%d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	// Verify the keypair works: sign and verify.
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("generated keypair fails sign/verify")
	}
}

func TestSaveLoadKeypairRoundtrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := SaveKeypair(dir, "mycompany/researcher", pub, priv); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	keyPath := filepath.Join(dir, "mycompany-researcher.signing.key")
	pubPath := filepath.Join(dir, "mycompany-researcher.signing.pub")

	// Check private key permissions are 0600.
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("private key perm=%o, want 0600", perm)
	}

	// Check public key permissions are 0644.
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	if perm := pubInfo.Mode().Perm(); perm != 0o644 {
		t.Fatalf("public key perm=%o, want 0644", perm)
	}

	// Load and verify roundtrip.
	loadedPriv, err := LoadSigningKey(keyPath)
	if err != nil {
		t.Fatalf("LoadSigningKey: %v", err)
	}
	if !priv.Equal(loadedPriv) {
		t.Fatal("loaded private key does not match original")
	}

	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if !pub.Equal(loadedPub) {
		t.Fatal("loaded public key does not match original")
	}
}

func TestSaveSigningKeyExclusiveNeverOverwritesExistingKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".aw", "signing.key")
	_, first, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSigningKeyExclusive(path, first); err != nil {
		t.Fatal(err)
	}
	if err := SaveSigningKeyExclusive(path, second); err == nil {
		t.Fatal("expected exclusive write to refuse existing key")
	}
	loaded, err := LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Equal(loaded) {
		t.Fatal("exclusive write replaced the original key")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestSaveKeypairAddressNormalization(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	if err := SaveKeypair(dir, "org/agent", pub, priv); err != nil {
		t.Fatalf("SaveKeypair: %v", err)
	}

	keyPath := filepath.Join(dir, "org-agent.signing.key")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected file at %s: %v", keyPath, err)
	}
}

func TestArchiveKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	oldDID := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

	if err := ArchiveKey(dir, oldDID, pub, priv); err != nil {
		t.Fatalf("ArchiveKey: %v", err)
	}

	archivedKey := filepath.Join(dir, "rotated", "did-key-z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.key")
	archivedPub := filepath.Join(dir, "rotated", "did-key-z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.pub")

	// Check archived private key permissions are 0600.
	keyInfo, err := os.Stat(archivedKey)
	if err != nil {
		t.Fatalf("archived key missing: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("archived key perm=%o, want 0600", perm)
	}

	if _, err := os.Stat(archivedPub); err != nil {
		t.Fatalf("archived pub missing: %v", err)
	}

	// Verify archived key is loadable and matches.
	loadedPriv, err := LoadSigningKey(archivedKey)
	if err != nil {
		t.Fatalf("LoadSigningKey from archive: %v", err)
	}
	if !priv.Equal(loadedPriv) {
		t.Fatal("archived private key does not match original")
	}
}

func TestLoadSigningKeyErrors(t *testing.T) {
	t.Parallel()

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		_, err := LoadSigningKey("/nonexistent/path/key.key")
		if err == nil {
			t.Fatal("expected error for nonexistent file")
		}
	})

	t.Run("no PEM block", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "garbage.key")
		if err := os.WriteFile(path, []byte("not a pem file"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSigningKey(path)
		if err == nil {
			t.Fatal("expected error for non-PEM content")
		}
	})

	t.Run("wrong PEM type", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "wrong.key")
		data := "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----\n"
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSigningKey(path)
		if err == nil {
			t.Fatal("expected error for wrong PEM type")
		}
	})

	t.Run("wrong seed size", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "short.key")
		data := "-----BEGIN ED25519 PRIVATE KEY-----\nYWJj\n-----END ED25519 PRIVATE KEY-----\n"
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadSigningKey(path)
		if err == nil {
			t.Fatal("expected error for wrong seed size")
		}
	})
}

func TestLoadPublicKeyErrors(t *testing.T) {
	t.Parallel()

	t.Run("no PEM block", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "garbage.pub")
		if err := os.WriteFile(path, []byte("not a pem file"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error for non-PEM content")
		}
	})

	t.Run("wrong PEM type", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "wrong.pub")
		data := "-----BEGIN RSA PUBLIC KEY-----\nYWJj\n-----END RSA PUBLIC KEY-----\n"
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error for wrong PEM type")
		}
	})

	t.Run("wrong key size", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "short.pub")
		data := "-----BEGIN ED25519 PUBLIC KEY-----\nYWJj\n-----END ED25519 PUBLIC KEY-----\n"
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadPublicKey(path)
		if err == nil {
			t.Fatal("expected error for wrong key size")
		}
	})
}

func TestKeyFilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		want    string
	}{
		{"namespace/alias", "mycompany/researcher", "mycompany-researcher"},
		{"plain alias", "researcher", "researcher"},
		{"multiple slashes", "a/b/c", "a-b-c"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := addressToKeyFileBase(tc.address)
			if got != tc.want {
				t.Fatalf("addressToKeyFileBase(%q)=%q, want %q", tc.address, got, tc.want)
			}
		})
	}
}
