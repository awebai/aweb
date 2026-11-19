package awconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/zalando/go-keyring"
)

func TestLogKeyRecordInstallsPerTeamUnderUserState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const teamID = "acme:example.com"

	if _, err := LoadLogKeyRecord(teamID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no record installed yet: %v", err)
	}

	_, teamKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	rec, err := awid.NewLogKeyRecord(teamID, pair.Public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignLogKeyRecord(rec, teamKey); err != nil {
		t.Fatal(err)
	}
	if err := SaveLogKeyRecord(rec); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, ".config", "aw", "log-keys", "acme__example.com.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("record not at %s: %v", path, err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode %v", info.Mode().Perm())
	}
	loaded, err := LoadLogKeyRecord(teamID)
	if err != nil {
		t.Fatal(err)
	}
	if *loaded != *rec {
		t.Fatalf("loaded %+v, want %+v", loaded, rec)
	}
	if _, err := LoadLogKeyRecord("other:example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("another team has no record: %v", err)
	}
}

func TestLogKeychainHoldsOnlyEncryptedLogKeyBackups(t *testing.T) {
	keyring.MockInit()
	store := LogKeychain{}
	pair, err := awid.GenerateLogKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := pair.KeyID()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadLogKey(keyID); !errors.Is(err, ErrLogKeyNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if err := store.SaveLogKey(keyID, pair.Private.Bytes()); err == nil {
		t.Fatal("a raw private key must not be stored")
	}
	blob, err := awid.ExportLogKeyBackup(pair.Private, []byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveLogKey(keyID, blob); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadLogKey(keyID)
	if err != nil || string(loaded) != string(blob) {
		t.Fatalf("load: %v", err)
	}
	if _, err := keyring.Get(humanKeychainService, keyID); err == nil {
		t.Fatal("log keys must not share the human key keychain service")
	}
}
