package awconfig

import (
	"os"
	"path/filepath"
	"strings"
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
		IdentityScope:  "global",
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
	want.SchemaVersion = WorktreeIdentitySchemaVersion
	want.Lifetime = "persistent"
	if *got != *want {
		t.Fatalf("identity mismatch: got %+v want %+v", *got, *want)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "identity_scope: global") {
		t.Fatalf("new identity config must write identity_scope: %s", string(data))
	}
	if strings.Contains(string(data), "lifetime:") {
		t.Fatalf("new identity config must not write deprecated lifetime: %s", string(data))
	}
}

func TestLoadWorktreeIdentityReadsDeprecatedLifetimeCompat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".aw", "identity.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("did: did:key:z6MkkCompat\nstable_id: did:aw:compat\naddress: acme.com/compat\ncustody: self\nlifetime: persistent\ncreated_at: 2026-04-04T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if got.IdentityScope != "global" {
		t.Fatalf("identity_scope=%q", got.IdentityScope)
	}
	if got.Lifetime != "persistent" {
		t.Fatalf("deprecated-read-compat lifetime=%q", got.Lifetime)
	}
}

func TestLoadWorktreeIdentityReadsIdentityScopeWithLifetimeMirror(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".aw", "identity.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("schema_version: 2\ndid: did:key:z6MkkScope\ncustody: self\nidentity_scope: local\ncreated_at: 2026-04-04T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadWorktreeIdentityFrom(path)
	if err != nil {
		t.Fatalf("LoadWorktreeIdentityFrom: %v", err)
	}
	if got.IdentityScope != "local" {
		t.Fatalf("identity_scope=%q", got.IdentityScope)
	}
	if got.Lifetime != "ephemeral" {
		t.Fatalf("deprecated-read-compat lifetime=%q", got.Lifetime)
	}
}

func TestLoadWorktreeIdentityRejectsConflictingScopeAndDeprecatedLifetime(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), ".aw", "identity.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("did: did:key:z6MkkConflict\ncustody: self\nidentity_scope: local\nlifetime: persistent\ncreated_at: 2026-04-04T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadWorktreeIdentityFrom(path)
	if err == nil || !strings.Contains(err.Error(), "conflicts with deprecated lifetime") {
		t.Fatalf("expected conflict error, got %v", err)
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
		IdentityScope:  "global",
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

func TestResolveIdentityReadsStandaloneIdentityWithoutWorkspace(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, ".aw", "identity.yaml")
	if err := SaveWorktreeIdentityTo(path, &WorktreeIdentity{
		DID:            "did:key:z6MkkResolve",
		StableID:       "did:aw:resolve",
		Address:        "acme.com/support",
		Custody:        "self",
		IdentityScope:  "global",
		RegistryURL:    "https://registry.example.com",
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-05T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	resolved, err := ResolveIdentity(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.IdentityPath != path {
		t.Fatalf("IdentityPath=%q want %q", resolved.IdentityPath, path)
	}
	if resolved.SigningKeyPath != filepath.Join(tmp, ".aw", "signing.key") {
		t.Fatalf("SigningKeyPath=%q", resolved.SigningKeyPath)
	}
	if resolved.Handle != "support" {
		t.Fatalf("Handle=%q", resolved.Handle)
	}
	if resolved.Domain != "acme.com" {
		t.Fatalf("Domain=%q", resolved.Domain)
	}
	if resolved.IdentityScope != "global" {
		t.Fatalf("IdentityScope=%q", resolved.IdentityScope)
	}
	if resolved.Lifetime != "persistent" {
		t.Fatalf("deprecated-read-compat Lifetime=%q", resolved.Lifetime)
	}
	if resolved.RegistryURL != "https://registry.example.com" {
		t.Fatalf("RegistryURL=%q", resolved.RegistryURL)
	}
}
