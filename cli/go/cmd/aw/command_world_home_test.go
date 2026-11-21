package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

// This is a local filesystem/CLI control of the harness, not registry admission.
// docs/cli-identity-selection.md:34 keeps controller custody at the user level.
func TestCommandWorldSharesUserControllerStoreAcrossExplicitIdentityHomes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	world := &realCommandWorld{
		Context: ctx, Binary: filepath.Join(t.TempDir(), "aw"), UserHome: t.TempDir(),
		Domain: "shared-user.test", NamespaceKey: newKey(t),
		Stack: commandStack{RegistryURL: "http://127.0.0.1:1"},
	}
	buildAwBinary(t, ctx, world.Binary)
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	keyPath, err := awconfig.ControllerKeyPath(world.Domain)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for range 2 {
		root := t.TempDir()
		home := filepath.Join(root, ".aw")
		world.requireCommand(t, home, "id", "create", "--local")
		identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(home, "identity.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if identity.DID == "" || seen[identity.DID] {
			t.Fatalf("explicit identity homes did not keep separate keys: %s", identity.DID)
		}
		seen[identity.DID] = true
		out := world.requireCommand(t, home, "id", "namespace", "prepare-controller", "--domain", world.Domain)
		var controller idNamespacePrepareControllerOutput
		if err := json.Unmarshal([]byte(out), &controller); err != nil {
			t.Fatal(err)
		}
		if controller.ControllerDID != didOf(world.NamespaceKey) || controller.ControllerKey != keyPath {
			t.Fatalf("command in %s did not use the shared user controller: %+v", home, controller)
		}
		if _, err := os.Stat(filepath.Join(root, ".awid")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("identity parent acquired a separate controller store: %v", err)
		}
	}
	other := *world
	other.UserHome = t.TempDir()
	home := filepath.Join(t.TempDir(), ".aw")
	other.requireCommand(t, home, "id", "create", "--local")
	out := other.requireCommand(t, home, "id", "namespace", "prepare-controller", "--domain", world.Domain)
	var controller idNamespacePrepareControllerOutput
	if err := json.Unmarshal([]byte(out), &controller); err != nil {
		t.Fatal(err)
	}
	if controller.ControllerDID == didOf(world.NamespaceKey) {
		t.Fatal("separate user homes shared controller custody")
	}
	shared, err := awconfig.LoadControllerKey(world.Domain)
	if err != nil {
		t.Fatal(err)
	}
	if !shared.Equal(world.NamespaceKey) {
		t.Fatal("separate user changed the original user's controller key")
	}
}
