package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// These exercise the production wiring in configureResolvedClient, not a private
// copy of it: every aw command that resolves a client goes through this function,
// and it is where a corrupt trust database used to be swallowed and replaced with
// an empty in-memory store — silently reopening first-contact TOFU for every
// pinned identity (default-aajc.9).

func withHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := awconfig.DefaultKnownAgentsPath()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, home) {
		t.Fatalf("test did not redirect the trust store: %s is outside %s", path, home)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func configureForTest(t *testing.T) error {
	t.Helper()
	const baseURL = "https://app.aweb.ai/api"
	c, err := aweb.New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return configureResolvedClient(c, &awconfig.Selection{
		Address:       "me@example.com",
		IdentityScope: awid.IdentityModeGlobal,
		BaseURL:       baseURL,
	}, baseURL)
}

func TestConfigureResolvedClientFailsClosedOnCorruptPinStore(t *testing.T) {
	path := withHome(t)
	if err := os.WriteFile(path, []byte("pins: {}\naddresses:\n  alice@example.com: did:key:zMissing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := configureForTest(t)
	if err == nil {
		t.Fatal("a corrupt trust database must abort the command, not be replaced by an empty store")
	}
	if !strings.Contains(err.Error(), "trust pin store") {
		t.Errorf("error should identify the trust store, got: %v", err)
	}
}

func TestConfigureResolvedClientFailsClosedOnEmptyPinStore(t *testing.T) {
	path := withHome(t)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureForTest(t); err == nil {
		t.Fatal("a truncated trust database must abort the command, not read as no pins")
	}
}

func TestConfigureResolvedClientFailsClosedOnUnreadablePinStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}
	path := withHome(t)
	if err := os.WriteFile(path, []byte("pins: {}\naddresses: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if err := configureForTest(t); err == nil {
		t.Fatal("an unreadable trust database must abort the command, not read as no pins")
	}
}

// First run must still work: an absent store is the only case that legitimately
// yields an empty one, and breaking this would break every new install.
func TestConfigureResolvedClientAcceptsAbsentPinStore(t *testing.T) {
	withHome(t)
	if err := configureForTest(t); err != nil {
		t.Fatalf("first run with no trust store must succeed: %v", err)
	}
}

func TestConfigureResolvedClientAcceptsValidPinStore(t *testing.T) {
	path := withHome(t)
	content := "pins:\n  did:key:zA:\n    address: alice@example.com\n    first_seen: t\n    last_seen: t\naddresses:\n  alice@example.com: did:key:zA\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureForTest(t); err != nil {
		t.Fatalf("a valid trust store must load: %v", err)
	}
}
