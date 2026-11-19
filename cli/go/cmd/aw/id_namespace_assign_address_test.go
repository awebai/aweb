package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// assignAddressWorld is a real world seen from the machine holding its
// namespace controller key.
func assignAddressWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	world := newRealCommandWorld(t)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	return world
}

func TestIDNamespaceAssignAddressHappyPath(t *testing.T) {
	world := assignAddressWorld(t)
	subject := world.registerIdentity(t)
	// The registry accepts and ignores the retired reachability field, so
	// only the request shows whether the client still sends it.
	var bodies []map[string]any
	t.Setenv("AWID_REGISTRY_URL", world.frontRegistry(t, registryFault{Answer: func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/addresses") {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read address registration: %v", err)
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var body map[string]any
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("address registration body %q: %v", raw, err)
			}
			bodies = append(bodies, body)
		}
		return false
	}}))

	out, err := executeIDNamespaceAssignAddress(world.Context, idNamespaceAssignAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		DIDAW:  subject.DIDAW,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "assigned" || out.Address != world.Domain+"/alice" || out.DIDAW != subject.DIDAW || out.DIDKey != subject.DIDKey {
		t.Fatalf("assign output = %+v", out)
	}
	if len(bodies) != 1 {
		t.Fatalf("address registrations = %d, want 1", len(bodies))
	}
	if _, ok := bodies[0]["reachability"]; ok {
		t.Fatalf("unexpected reachability write: %v", bodies[0]["reachability"])
	}
	address, _, err := world.Registry.GetNamespaceAddressAt(world.Context, world.Stack.RegistryURL, world.Domain, "alice")
	if err != nil || address.DIDAW != subject.DIDAW || address.CurrentDIDKey != subject.DIDKey {
		t.Fatalf("registry address = %+v, %v", address, err)
	}
}

func TestIDNamespaceAssignAddressIdempotentMatchingDID(t *testing.T) {
	world := assignAddressWorld(t)
	subject := world.registerGlobalMember(t, "alice")

	out, err := executeIDNamespaceAssignAddress(world.Context, idNamespaceAssignAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		DIDAW:  subject.DIDAW,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "already_assigned" || out.Address != world.Domain+"/alice" {
		t.Fatalf("assign output = %+v, want already_assigned", out)
	}
}

func TestIDNamespaceAssignAddressConflictWithStaleAddressKey(t *testing.T) {
	world := assignAddressWorld(t)
	subject := world.registerGlobalMember(t, "alice")
	staleDID := didOf(newKey(t))
	// The registry derives an address's key from its did:aw's current key, so
	// it never answers a stale one; a registry mid-rotation, or another
	// registry, can.
	t.Setenv("AWID_REGISTRY_URL", world.frontRegistry(t, registryFault{Rewrite: func(response *http.Response) error {
		if response.Request.Method != http.MethodGet || !strings.HasSuffix(response.Request.URL.Path, "/addresses/alice") {
			return nil
		}
		return rewriteJSONBody(response, func(address map[string]any) { address["current_did_key"] = staleDID })
	}}))

	_, err := executeIDNamespaceAssignAddress(world.Context, idNamespaceAssignAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		DIDAW:  subject.DIDAW,
	})
	if err == nil {
		t.Fatal("expected error for stale address key")
	}
	if !strings.Contains(err.Error(), staleDID) || !strings.Contains(err.Error(), subject.DIDKey) {
		t.Fatalf("error should mention stale and current did:key, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressConflictWithDifferentDID(t *testing.T) {
	world := assignAddressWorld(t)
	holder := world.registerGlobalMember(t, "alice")
	subject := world.registerIdentity(t)

	_, err := executeIDNamespaceAssignAddress(world.Context, idNamespaceAssignAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		DIDAW:  subject.DIDAW,
	})
	if err == nil {
		t.Fatal("expected error for DID mismatch")
	}
	if !strings.Contains(err.Error(), holder.DIDAW) {
		t.Fatalf("error should mention conflicting did_aw %s, got: %v", holder.DIDAW, err)
	}
}

func TestIDNamespaceAssignAddressEmptyDIDAW(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_REGISTRY_URL", "http://example.invalid")

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain: "aweb.ai",
		Name:   "alice",
		DIDAW:  "did:aw:",
	})
	if err == nil {
		t.Fatal("expected error for empty did:aw body")
	}
	if !strings.Contains(err.Error(), "did:aw") {
		t.Fatalf("error should mention did:aw, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressMissingControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// No registry exists here: a request would fail with its own error.
	t.Setenv("AWID_REGISTRY_URL", "http://example.invalid")

	_, err := executeIDNamespaceAssignAddress(context.Background(), idNamespaceAssignAddressOptions{
		Domain: "aweb.ai",
		Name:   "alice",
		DIDAW:  "did:aw:xyz",
	})
	if err == nil {
		t.Fatal("expected error for missing controller key")
	}
	if !strings.Contains(err.Error(), "controller key") {
		t.Fatalf("error should mention controller key, got: %v", err)
	}
}

func TestIDNamespaceAssignAddressControllerMismatch(t *testing.T) {
	world := assignAddressWorld(t)
	subject := world.registerIdentity(t)
	// This machine holds a key the registry does not name as controller.
	if err := awconfig.SaveControllerKey(world.Domain, newKey(t)); err != nil {
		t.Fatal(err)
	}
	origin, recording := world.recordRegistry(t)
	t.Setenv("AWID_REGISTRY_URL", origin)

	_, err := executeIDNamespaceAssignAddress(world.Context, idNamespaceAssignAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		DIDAW:  subject.DIDAW,
	})
	if err == nil {
		t.Fatal("expected error for controller key mismatch")
	}
	if !strings.Contains(err.Error(), "controller") {
		t.Fatalf("error should mention controller mismatch, got: %v", err)
	}
	for _, answer := range recording.Answers() {
		if answer.Method != http.MethodGet || answer.Path != "/v1/namespaces/"+world.Domain {
			t.Fatalf("the refusal reached past the namespace read: %+v", recording.Answers())
		}
	}
}
