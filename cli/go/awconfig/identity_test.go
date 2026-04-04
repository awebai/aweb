package awconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveWorktreeIdentityToRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "identity.yaml")
	want := &WorktreeIdentity{
		DID:            "did:key:z6MkkRoundTrip",
		StableID:       "did:aw:roundtrip",
		Address:        "acme.com/alice",
		Custody:        "self",
		Lifetime:       "persistent",
		RegistryURL:    "https://registry.example.com",
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-04T00:00:00Z",
	}
	if err := SaveWorktreeIdentityTo(path, want); err != nil {
		t.Fatalf("SaveWorktreeIdentityTo: %v", err)
	}

	got, err := LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if *got != *want {
		t.Fatalf("identity mismatch: got %+v want %+v", *got, *want)
	}
}

func TestSaveWorktreeIdentityToWrites0600(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "identity.yaml")
	if err := SaveWorktreeIdentityTo(path, &WorktreeIdentity{
		DID:            "did:key:z6MkkPerms",
		StableID:       "did:aw:perms",
		Address:        "acme.com/perms",
		Custody:        "self",
		Lifetime:       "persistent",
		RegistryURL:    "https://registry.example.com",
		RegistryStatus: "pending",
		CreatedAt:      "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatalf("SaveWorktreeIdentityTo: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o want %#o", got, 0o600)
	}
}
