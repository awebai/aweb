package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

func localRequest(root string) unaddressedCreate {
	return unaddressedCreate{Root: root}
}

func assertKeyOnlyIdentity(t *testing.T, root string, result map[string]any) {
	t.Helper()
	key, err := awid.LoadSigningKey(filepath.Join(root, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(filepath.Join(root, "signing.key")); info.Mode().Perm() != 0o600 {
		t.Fatalf("signing key mode %v", info.Mode().Perm())
	}
	didKey := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	if result["did_key"] != didKey || result["did_aw"] != nil || result["registry_url"] != nil {
		t.Fatalf("result %v for %s", result, didKey)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(root, "identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != didKey || identity.StableID != "" || identity.Address != "" || identity.Custody != awid.CustodySelf ||
		identity.IdentityScope != awid.IdentityModeLocal || identity.RegistryURL != "" || identity.RegistryStatus != "" {
		t.Fatalf("identity %+v", identity)
	}
	if _, err := os.Stat(filepath.Join(root, unaddressedStateFile)); !os.IsNotExist(err) {
		t.Fatal("the creation state remains after completion")
	}
}

func TestALocalIdentityIsAKeyOnlyHomeWithNoRegistration(t *testing.T) {
	root := t.TempDir()
	result, err := createUnaddressedIdentity(context.Background(), localRequest(root))
	if err != nil {
		t.Fatal(err)
	}
	if result["status"] != "created" {
		t.Fatalf("status %v", result["status"])
	}
	assertKeyOnlyIdentity(t, root, result)
}

func TestALocalIdentityRerunReturnsTheSameIdentityAndChangesNothing(t *testing.T) {
	root := t.TempDir()
	first, err := createUnaddressedIdentity(context.Background(), localRequest(root))
	if err != nil {
		t.Fatal(err)
	}
	contents := homeContents(t, root)
	again, err := createUnaddressedIdentity(context.Background(), localRequest(root))
	if err != nil {
		t.Fatal(err)
	}
	if again["status"] != "already_exists" || again["did_key"] != first["did_key"] {
		t.Fatalf("rerun %v after %v", again, first)
	}
	if !maps.Equal(contents, homeContents(t, root)) {
		t.Fatal("the rerun changed the home")
	}
}

func TestAKilledLocalCreationResumesWithItsOriginalKey(t *testing.T) {
	for name, installKey := range map[string]bool{"before its key": false, "after its key": true} {
		root := t.TempDir()
		key := interruptedCreation(t, root, "", installKey)
		result, err := createUnaddressedIdentity(context.Background(), localRequest(root))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if result["status"] != "resumed" {
			t.Errorf("%s: status %v", name, result["status"])
		}
		assertKeyOnlyIdentity(t, root, result)
		if installKey && result["did_key"] != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
			t.Errorf("%s: resumed with another key", name)
		}
	}
}

func TestALocalCreationRefusesAnyOtherHomeAndLeavesItUnchanged(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, root string){
		"a registered identity": func(t *testing.T, root string) {
			registry := newMappingRegistry(t)
			if _, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root)); err != nil {
				t.Fatal(err)
			}
		},
		"a registered creation in progress": func(t *testing.T, root string) {
			interruptedCreation(t, root, "https://registry.example", true)
		},
		"a key with no creation state": func(t *testing.T, root string) {
			_, key, _ := ed25519.GenerateKey(nil)
			_ = awid.SaveSigningKey(filepath.Join(root, "signing.key"), key)
		},
		"another file": func(t *testing.T, root string) {
			_ = os.WriteFile(filepath.Join(root, "teams.yaml"), []byte("{}"), 0o600)
		},
		"a key-only identity that has begun an exchange": func(t *testing.T, root string) {
			if _, err := createUnaddressedIdentity(context.Background(), localRequest(root)); err != nil {
				t.Fatal(err)
			}
			_ = os.MkdirAll(awconfig.IdentityRequestsDir(root), 0o700)
		},
		"a key-only identity for another key": func(t *testing.T, root string) {
			if _, err := createUnaddressedIdentity(context.Background(), localRequest(root)); err != nil {
				t.Fatal(err)
			}
			_, key, _ := ed25519.GenerateKey(nil)
			_ = os.Remove(filepath.Join(root, "signing.key"))
			_ = awid.SaveSigningKey(filepath.Join(root, "signing.key"), key)
		},
		"a dangling identity entry": func(t *testing.T, root string) {
			_ = os.Symlink(filepath.Join(root, "missing-target"), filepath.Join(root, "identity.yaml"))
		},
	} {
		root := t.TempDir()
		prepare(t, root)
		contents := homeContents(t, root)
		_, err := createUnaddressedIdentity(context.Background(), localRequest(root))
		if errorCodeOf(err) != "identity_exists" {
			t.Errorf("%s: err %v", name, err)
		}
		if !maps.Equal(contents, homeContents(t, root)) {
			t.Errorf("%s: the refusal changed the home", name)
		}
	}
}

func TestARegisteredCreationRefusesALocalCreationInProgress(t *testing.T) {
	registry := newMappingRegistry(t)
	root := t.TempDir()
	interruptedCreation(t, root, "", true)
	_, err := createUnaddressedIdentity(context.Background(), unaddressedRequest(t, registry, root))
	if errorCodeOf(err) != "identity_exists" || registry.count() != 0 {
		t.Fatalf("err %v after %d registrations", err, registry.count())
	}
}

func TestLocalNeedsAnExplicitHomeAndNoAddressRegistryOrParentFlags(t *testing.T) {
	for name, tc := range map[string]struct {
		set      map[string]string
		explicit bool
		ok       bool
	}{
		"explicit home":          {map[string]string{}, true, true},
		"implicit home":          {map[string]string{}, false, false},
		"with --registry":        {map[string]string{"registry": "https://registry.example"}, true, false},
		"with --no-address":      {map[string]string{"no-address": "true"}, true, false},
		"with --name":            {map[string]string{"name": "agent"}, true, false},
		"with --domain":          {map[string]string{"domain": "example.com"}, true, false},
		"with --org":             {map[string]string{"org": "acme"}, true, false},
		"with --team-id":         {map[string]string{"team-id": "t"}, true, false},
		"with --human-parent":    {map[string]string{"human-parent": "did:aw:x"}, true, false},
		"with --root-parent":     {map[string]string{"root-parent": "true"}, true, false},
		"with --skip-dns-verify": {map[string]string{"skip-dns-verify": "true"}, true, false},
	} {
		cmd := &cobra.Command{}
		flags := cmd.Flags()
		for _, flag := range []string{"registry", "name", "domain", "org", "human-parent", "team-id", "inbound-mode", "owner-identity-home"} {
			flags.String(flag, "", "")
		}
		for _, flag := range []string{"root-parent", "skip-dns-verify", "no-address"} {
			flags.Bool(flag, false, "")
		}
		for flag, value := range tc.set {
			if err := flags.Set(flag, value); err != nil {
				t.Fatal(err)
			}
		}
		err := localFlagsRefusal(cmd, tc.explicit)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

// The real command makes a home the parent/child exchange accepts as a local
// agent, and a rerun returns the same identity.
func TestTheLocalCommandMakesAHomeTheParentExchangeAccepts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "child")
	create := func() map[string]any {
		t.Helper()
		command := exec.CommandContext(ctx, bin, "--json", "--identity-home", home, "id", "create", "--local")
		command.Dir, command.Env = root, testCommandEnv(root)
		out, err := command.Output()
		if err != nil {
			t.Fatalf("create --local: %v %s", err, out)
		}
		var result map[string]any
		if err := json.Unmarshal(out, &result); err != nil {
			t.Fatalf("output %s: %v", out, err)
		}
		return result
	}
	first := create()
	if first["status"] != "created" {
		t.Fatalf("first %v", first)
	}
	if again := create(); again["status"] != "already_exists" || again["did_key"] != first["did_key"] {
		t.Fatalf("rerun %v after %v", again, first)
	}
	parentPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "request.json")
	request := exec.CommandContext(ctx, bin, "--identity-home", home, "id", "parent", "request", "--domain", "example.com",
		"--invitation-id", "11111111-1111-4111-8111-111111111111", "--parent", awid.ComputeDIDKey(parentPub), "--out", out)
	request.Dir, request.Env = root, testCommandEnv(root)
	if output, err := request.CombinedOutput(); err != nil {
		t.Fatalf("parent request: %v %s", err, output)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := awid.ParseIDCertificateRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if body := signed["request"].(map[string]any); body["id"] != first["did_key"] || body["subject_key"] != first["did_key"] || body["kind"] != "agent" {
		t.Fatalf("request binds %v, not %v", body, first["did_key"])
	}
	if strings.TrimSpace(first["identity_home"].(string)) != home {
		t.Fatalf("identity_home %v", first["identity_home"])
	}
}
