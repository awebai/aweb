package awconfig

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestSaveTeamKeyRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveTeamKey("Acme.com", "backend", key); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadTeamKey("acme.com", "backend")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ed25519.PrivateKey(loaded).Seed(), ed25519.PrivateKey(key).Seed(); string(got) != string(want) {
		t.Fatal("team key seed mismatch")
	}
}

func TestSaveTeamKeyWrites0600(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveTeamKey("acme.com", "backend", key); err != nil {
		t.Fatal(err)
	}

	path, err := TeamKeyPath("acme.com", "backend")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o want %#o", got, 0o600)
	}
}

func TestTeamKeyExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	exists, err := TeamKeyExists("acme.com", "backend")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("team key should not exist yet")
	}

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveTeamKey("acme.com", "backend", key); err != nil {
		t.Fatal(err)
	}

	exists, err = TeamKeyExists("Acme.com", "backend")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("team key should exist")
	}
}

func TestTeamKeyPathLayout(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	path, err := TeamKeyPath("Acme.com", "Backend")
	if err != nil {
		t.Fatal(err)
	}
	root, err := DefaultTeamKeysDir()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(root, "acme.com", "backend.key") {
		t.Fatalf("path=%q", path)
	}
}
