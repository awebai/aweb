package awconfig

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestSaveControllerKeyRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveControllerKey("Acme.com", key); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadControllerKey("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ed25519.PrivateKey(loaded).Seed(), ed25519.PrivateKey(key).Seed(); string(got) != string(want) {
		t.Fatal("controller key seed mismatch")
	}
}

func TestSaveControllerKeyWrites0600(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveControllerKey("acme.com", key); err != nil {
		t.Fatal(err)
	}

	path, err := ControllerKeyPath("acme.com")
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

func TestSaveControllerMetaRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	want := &ControllerMeta{
		Domain:        "acme.com",
		ControllerDID: "did:key:z6MkController",
		RegistryURL:   "https://registry.example.com",
		CreatedAt:     "2026-04-05T00:00:00Z",
	}
	if err := SaveControllerMeta("Acme.com", want); err != nil {
		t.Fatal(err)
	}

	got, err := LoadControllerMeta("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if *got != *want {
		t.Fatalf("meta mismatch: got %+v want %+v", *got, *want)
	}
}

func TestControllerKeyExists(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	exists, err := ControllerKeyExists("acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("controller key should not exist yet")
	}

	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveControllerKey("acme.com", key); err != nil {
		t.Fatal(err)
	}

	exists, err = ControllerKeyExists("Acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("controller key should exist")
	}
}

func TestControllerPathsUseControllersDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	keyPath, err := ControllerKeyPath("Acme.com")
	if err != nil {
		t.Fatal(err)
	}
	metaPath, err := ControllerMetaPath("Acme.com")
	if err != nil {
		t.Fatal(err)
	}
	root, err := DefaultControllersDir()
	if err != nil {
		t.Fatal(err)
	}
	if keyPath != filepath.Join(root, "acme.com.key") {
		t.Fatalf("keyPath=%q", keyPath)
	}
	if metaPath != filepath.Join(root, "acme.com.yaml") {
		t.Fatalf("metaPath=%q", metaPath)
	}
}
