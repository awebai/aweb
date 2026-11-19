package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// deliveryOriginWorld is a real world seen from the machine holding its
// namespace controller key.
func deliveryOriginWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	world := newRealCommandWorld(t)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	return world
}

func (world *realCommandWorld) deliveryOrigin(t *testing.T) string {
	t.Helper()
	namespace, _, err := world.Registry.GetNamespaceAt(world.Context, world.Stack.RegistryURL, world.Domain)
	if err != nil {
		t.Fatal(err)
	}
	return namespace.DefaultDeliveryOrigin
}

func TestIDNamespaceDeliveryOriginHappyPath(t *testing.T) {
	world := deliveryOriginWorld(t)

	out, err := executeIDNamespaceDeliveryOrigin(world.Context, idNamespaceDeliveryOriginOptions{
		Domain: world.Domain,
		Origin: "https://Aweb.Acme.Com/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "updated" || out.Origin != "https://aweb.acme.com" {
		t.Fatalf("output = %+v, want updated to the canonical origin", out)
	}
	if got := world.deliveryOrigin(t); got != "https://aweb.acme.com" {
		t.Fatalf("registry delivery origin = %q", got)
	}
}

func TestIDNamespaceDeliveryOriginUnchangedDoesNotPatch(t *testing.T) {
	world := deliveryOriginWorld(t)
	if _, err := executeIDNamespaceDeliveryOrigin(world.Context, idNamespaceDeliveryOriginOptions{
		Domain: world.Domain, Origin: "https://aweb.acme.com",
	}); err != nil {
		t.Fatal(err)
	}
	origin, recording := world.recordRegistry(t)
	t.Setenv("AWID_REGISTRY_URL", origin)

	out, err := executeIDNamespaceDeliveryOrigin(world.Context, idNamespaceDeliveryOriginOptions{
		Domain: world.Domain,
		Origin: "https://aweb.acme.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "unchanged" {
		t.Fatalf("status=%q", out.Status)
	}
	for _, answer := range recording.Answers() {
		if answer.Method != http.MethodGet {
			t.Fatalf("an unchanged origin wrote to the registry: %+v", recording.Answers())
		}
	}
}

func TestIDNamespaceDeliveryOriginControllerMismatch(t *testing.T) {
	world := deliveryOriginWorld(t)
	// This machine holds a key the registry does not name as controller.
	if err := awconfig.SaveControllerKey(world.Domain, newKey(t)); err != nil {
		t.Fatal(err)
	}

	_, err := executeIDNamespaceDeliveryOrigin(world.Context, idNamespaceDeliveryOriginOptions{
		Domain: world.Domain,
		Origin: "https://aweb.acme.com",
	})
	if err == nil {
		t.Fatal("expected controller mismatch")
	}
	if got := err.Error(); !strings.Contains(got, "does not match registered controller") {
		t.Fatalf("err=%v", err)
	}
	if got := world.deliveryOrigin(t); got != "" {
		t.Fatalf("refused update changed the registry delivery origin to %q", got)
	}
}
