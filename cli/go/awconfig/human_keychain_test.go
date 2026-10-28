package awconfig

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

func TestHumanKeychainHoldsTheEncryptedBackup(t *testing.T) {
	keyring.MockInit()
	store := HumanKeychain{}
	const id = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
	if _, err := store.LoadHumanKey(id); !errors.Is(err, awid.ErrHumanKeyNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	if err := awid.InstallHumanKey(store, id, key, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
	item, err := keyring.Get(humanKeychainService, id)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix([]byte(item), []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		t.Fatal("the keychain item is not the encrypted backup")
	}
	blob, err := store.LoadHumanKey(id)
	if err != nil || string(blob) != item {
		t.Fatalf("load: %v", err)
	}
	if _, err := awid.ImportHumanKeyBackup(blob, []byte("correct horse")); err != nil {
		t.Fatal(err)
	}
}

func TestHumanKeychainRefusesToStoreAPlaintextKey(t *testing.T) {
	keyring.MockInit()
	store := HumanKeychain{}
	plaintext := []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD\n-----END PRIVATE KEY-----\n")
	if err := store.SaveHumanKey("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", plaintext); err == nil {
		t.Fatal("stored something other than an encrypted backup")
	}
	if _, err := keyring.Get(humanKeychainService, "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("keychain holds an item: %v", err)
	}
}
