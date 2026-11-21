package awconfig

import (
	"crypto/ed25519"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func newTeamKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// A team key set aside as unconfirmed keeps its mode, is never read as the
// team key, and comes back intact when the registry confirms it.
func TestUnconfirmedTeamKeyIsKeptAsideAndRestored(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	pub, priv := newTeamKey(t)
	if err := CreateTeamKey("acme.com", "ops", priv); err != nil {
		t.Fatal(err)
	}

	aside, err := SetAsideUnconfirmedTeamKey("acme.com", "ops", pub)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(aside)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("set-aside key mode=%v, want 0600", info.Mode().Perm())
	}
	// Every reader of the team key sees the set-aside key and refuses, naming
	// the registration that settles it.
	const settle = "aw id team create --namespace acme.com --name ops"
	if exists, err := TeamKeyExists("acme.com", "ops"); !errors.Is(err, ErrTeamKeyUnconfirmed) || exists {
		t.Fatalf("TeamKeyExists exists=%v err=%v, want ErrTeamKeyUnconfirmed", exists, err)
	} else if !strings.Contains(err.Error(), settle) {
		t.Fatalf("TeamKeyExists refusal %q does not name %q", err, settle)
	}
	if _, err := LoadTeamKey("acme.com", "ops"); !errors.Is(err, ErrTeamKeyUnconfirmed) {
		t.Fatalf("LoadTeamKey err=%v, want ErrTeamKeyUnconfirmed", err)
	} else if !strings.Contains(err.Error(), settle) {
		t.Fatalf("LoadTeamKey refusal %q does not name %q", err, settle)
	}

	if err := RestoreUnconfirmedTeamKey("acme.com", "ops"); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTeamKey("acme.com", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(priv) {
		t.Fatal("the restored team key is not the key set aside")
	}
	if _, err := os.Lstat(aside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("set-aside file still present: %v", err)
	}
}

// A key already set aside is never replaced: a second set-aside fails and
// leaves both keys where they are.
func TestSettingAsideNeverReplacesAnUnconfirmedTeamKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	firstPub, firstPriv := newTeamKey(t)
	if err := CreateTeamKey("acme.com", "ops", firstPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := SetAsideUnconfirmedTeamKey("acme.com", "ops", firstPub); err != nil {
		t.Fatal(err)
	}
	secondPub, secondPriv := newTeamKey(t)
	if err := CreateTeamKey("acme.com", "ops", secondPriv); err != nil {
		t.Fatal(err)
	}

	if _, err := SetAsideUnconfirmedTeamKey("acme.com", "ops", secondPub); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second set-aside err=%v, want os.ErrExist", err)
	}
	aside, _, err := LoadUnconfirmedTeamKey("acme.com", "ops")
	if err != nil || !aside.Equal(firstPriv) {
		t.Fatalf("set-aside key changed: err=%v", err)
	}
	path, err := TeamKeyPath("acme.com", "ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := teamKeyFileHolds(path, secondPub); err != nil {
		t.Fatalf("the second key was not left in place: %v", err)
	}
}

// The set-aside key is removed only while it holds the key the registry was
// shown to pin elsewhere.
func TestUnconfirmedTeamKeyIsRemovedOnlyWhenItHoldsTheExpectedKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	pub, priv := newTeamKey(t)
	if err := CreateTeamKey("acme.com", "ops", priv); err != nil {
		t.Fatal(err)
	}
	aside, err := SetAsideUnconfirmedTeamKey("acme.com", "ops", pub)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _ := newTeamKey(t)

	if err := RemoveUnconfirmedTeamKey("acme.com", "ops", otherPub); !errors.Is(err, ErrTeamKeyNotExpected) {
		t.Fatalf("remove with another key err=%v, want ErrTeamKeyNotExpected", err)
	}
	if err := RemoveUnconfirmedTeamKey("acme.com", "ops", pub); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(aside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("set-aside file still present: %v", err)
	}
	if _, err := LoadTeamKey("acme.com", "ops"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadTeamKey err=%v, want no team key", err)
	}
}
