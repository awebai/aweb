package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A real encrypted backup on the private fixture filesystem. OS-keychain and
// controlling-terminal integration is exercised by the product journey.
type humanBackupFile struct{ id, path string }

func (f humanBackupFile) LoadHumanKey(id string) ([]byte, error) {
	if id != f.id {
		return nil, awid.ErrHumanKeyNotFound
	}
	return os.ReadFile(f.path)
}
func (f humanBackupFile) SaveHumanKey(id string, blob []byte) error {
	if id != f.id {
		return fmt.Errorf("wrong fixture identity")
	}
	return os.WriteFile(f.path, blob, 0600)
}
func commandUnlockFixture(t *testing.T, passphrase string) (*humanParticipation, *[]string, *[]byte) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(awconfig.IdentityHomeEnv, "")
	old := identityHomeFlag
	identityHomeFlag = ""
	t.Cleanup(func() { identityHomeFlag = old })
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	t.Cleanup(func() { clear(key) })
	rec := &awconfig.HumanRecord{StableID: awid.ComputeStableID(key.Public().(ed25519.PublicKey)), DIDKey: awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), Domain: "example.test", State: awconfig.HumanPrepared}
	if err := awconfig.SaveHumanRecord(rec); err != nil {
		t.Fatal(err)
	}
	store := humanBackupFile{rec.StableID, filepath.Join(home, "backup.pbes2")}
	if err := awid.InstallHumanKey(store, rec.StableID, key, []byte(humanPassphrase)); err != nil {
		t.Fatal(err)
	}
	prompts := []string{}
	var supplied []byte
	h, err := loadHumanParticipationState(rec.StableID, rec.Domain, store, func(text string) ([]byte, error) {
		prompts = append(prompts, text)
		supplied = []byte(passphrase)
		return supplied, nil
	}, func() error { return nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	return h, &prompts, &supplied
}
func TestHumanCommandUnlocksOnceForMultipleSignatures(t *testing.T) {
	h, prompts, supplied := commandUnlockFixture(t, humanPassphrase)
	h.operation = "enroll your approval key"
	for _, description := range []string{"start", "material", "confirm", "finish", "activate"} {
		payload := []byte(description)
		did, signature, err := h.sign(payload, description)
		if err != nil {
			t.Fatal(err)
		}
		public, err := awid.ExtractPublicKey(did)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(public, payload, signature) {
			t.Fatal("signature invalid")
		}
	}
	if len(*prompts) != 1 {
		t.Fatalf("passphrase prompts=%d, want one for the command", len(*prompts))
	}
	if !strings.Contains((*prompts)[0], h.record.StableID) || !strings.Contains((*prompts)[0], h.operation) {
		t.Fatal("unlock prompt does not name selected human and operation")
	}
	if !bytes.Equal(*supplied, make([]byte, len(*supplied))) {
		t.Fatal("passphrase bytes retained")
	}
}
func TestHumanCommandWrongPassphraseDoesNotRetryOrSign(t *testing.T) {
	h, prompts, supplied := commandUnlockFixture(t, "a wrong passphrase")
	for i := 0; i < 2; i++ {
		did, signature, err := h.sign([]byte("act"), "attempt")
		if err == nil || did != "" || len(signature) != 0 {
			t.Fatal("wrong passphrase signed an act")
		}
	}
	if len(*prompts) != 1 {
		t.Fatalf("failed command retried its passphrase %d times", len(*prompts))
	}
	if !bytes.Equal(*supplied, make([]byte, len(*supplied))) {
		t.Fatal("failed passphrase not wiped")
	}
}
