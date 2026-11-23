package awconfig

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

func generatedTeamKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestCreateTeamKeyNeverReplacesASavedKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first, second := generatedTeamKey(t), generatedTeamKey(t)
	if err := CreateTeamKey("acme.com", "default", first); err != nil {
		t.Fatal(err)
	}
	if err := CreateTeamKey("acme.com", "default", second); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err=%v, want os.ErrExist", err)
	}
	held, err := LoadTeamKey("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	if !held.Equal(first) {
		t.Fatal("the saved key was replaced")
	}
}

func TestRemoveTeamKeyLeavesADifferentKeyInPlace(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	held, other := generatedTeamKey(t), generatedTeamKey(t)
	if err := CreateTeamKey("acme.com", "default", held); err != nil {
		t.Fatal(err)
	}
	err := RemoveTeamKey("acme.com", "default", other.Public().(ed25519.PublicKey))
	if !errors.Is(err, ErrTeamKeyNotExpected) {
		t.Fatalf("err=%v, want ErrTeamKeyNotExpected", err)
	}
	still, err := LoadTeamKey("acme.com", "default")
	if err != nil {
		t.Fatalf("the key file is gone: %v", err)
	}
	if !still.Equal(held) {
		t.Fatal("the key file changed")
	}
}

func TestRemoveTeamKeyRemovesTheExpectedKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	key := generatedTeamKey(t)
	if err := CreateTeamKey("acme.com", "default", key); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTeamKey("acme.com", "default", key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	exists, err := TeamKeyExists("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("the expected key was not removed")
	}
}
