//go:build !windows

package awid

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestExclusiveSigningKeyCreatesPrivateDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "signing.key")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := SaveSigningKeyExclusive(path, key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %o, want 700", info.Mode().Perm())
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
	if err := SaveSigningKeyExclusive(path, ed25519.NewKeyFromSeed(make([]byte, 32))); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing key overwritten: %v", err)
	}
}

func TestOpenPermissionKeyRemainsReadableAndWarnsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing.key")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := SaveSigningKey(path, key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	logs := captureStderrForTest(t, func() {
		for i := 0; i < 2; i++ {
			loaded, err := LoadSigningKey(path)
			if err != nil || !loaded.Equal(key) {
				t.Fatalf("released key read refused: %v", err)
			}
		}
	})
	if strings.Count(logs, "Run chmod 600") != 1 || !strings.Contains(logs, path) {
		t.Fatalf("wanted one actionable permission warning: %s", logs)
	}
}

func TestKeyWriterLeavesExistingParentPermissionsUnchanged(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveSigningKey(filepath.Join(parent, "signing.key"), ed25519.NewKeyFromSeed(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatal("key writer changed a directory it did not create")
	}
}

func TestPermissionRepairCommandQuotesLiteralFileNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key' literal.key")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	if err := SaveSigningKey(path, key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	command, err := PermissionFixCommand(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput(); err != nil {
		t.Fatalf("repair command: %v %s", err, output)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal("quoted repair command did not fix the exact file")
	}
}

func TestPrivatePEMRefusalsExplainHowToRestoreTheKey(t *testing.T) {
	cases := []struct {
		Name string
		Data []byte
		Want string
	}{
		{Name: "missing block", Data: []byte("broken"), Want: "no PEM block; restore an Ed25519 private key PEM file"},
		{Name: "wrong kind", Data: pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: make([]byte, 32)}), Want: "unexpected PEM type \"OTHER\"; restore an ED25519 PRIVATE KEY PEM file"},
		{Name: "wrong size", Data: pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: make([]byte, 31)}), Want: "invalid seed size 31; restore a 32-byte Ed25519 private key seed"},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := ParseSigningKey(c.Data)
			if err == nil || err.Error() != c.Want {
				t.Fatalf("refusal = %v, want %s", err, c.Want)
			}
		})
	}
}

func TestEncryptionPEMRefusalsExplainHowToRestoreTheKey(t *testing.T) {
	cases := []struct {
		Name string
		Data []byte
		Want string
	}{
		{Name: "missing block", Data: []byte("broken"), Want: "no PEM block; restore an X25519 private key PEM file"},
		{Name: "wrong kind", Data: pem.EncodeToMemory(&pem.Block{Type: "OTHER", Bytes: make([]byte, 32)}), Want: "unexpected PEM type \"OTHER\"; restore an X25519 PRIVATE KEY PEM file"},
		{Name: "wrong size", Data: pem.EncodeToMemory(&pem.Block{Type: "X25519 PRIVATE KEY", Bytes: make([]byte, 31)}), Want: "invalid seed size 31; restore a 32-byte X25519 private key seed"},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "encryption.key")
			if err := os.WriteFile(path, c.Data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadX25519PrivateKey(path)
			if err == nil || !strings.Contains(err.Error(), c.Want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("refusal = %v; want recovery %q and path", err, c.Want)
			}
		})
	}
}
