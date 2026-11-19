package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// deleteAddressWorld is a real world with a registered "alice" address, seen
// from the machine holding the namespace controller key.
func deleteAddressWorld(t *testing.T) (*realCommandWorld, globalMember) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	world := newRealCommandWorld(t)
	member := world.registerGlobalMember(t, "alice")
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	return world, member
}

func TestIDNamespaceDeleteAddressHappyPath(t *testing.T) {
	world, _ := deleteAddressWorld(t)

	// The registry refuses unknown body fields, so its acceptance proves the
	// reason travels under the field it defines.
	out, err := executeIDNamespaceDeleteAddress(world.Context, idNamespaceDeleteAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
		Reason: "retry clean byot setup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" || out.Address != world.Domain+"/alice" || out.ControllerDID != didOf(world.NamespaceKey) {
		t.Fatalf("delete output = %+v", out)
	}
	_, _, err = world.Registry.GetNamespaceAddressAt(world.Context, world.Stack.RegistryURL, world.Domain, "alice")
	if code, ok := registryStatusCode(err); !ok || code != 404 {
		t.Fatalf("deleted address is still readable: %v", err)
	}
}

func TestIDNamespaceDeleteAddressRequiresLocalControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := executeIDNamespaceDeleteAddress(context.Background(), idNamespaceDeleteAddressOptions{
		Domain: "acme.com",
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "no controller key") {
		t.Fatalf("err=%v", err)
	}
}

func TestIDNamespaceDeleteAddressRejectsControllerMismatch(t *testing.T) {
	world, _ := deleteAddressWorld(t)
	// This machine holds a key the registry does not name as controller.
	if err := awconfig.SaveControllerKey(world.Domain, newKey(t)); err != nil {
		t.Fatal(err)
	}

	_, err := executeIDNamespaceDeleteAddress(world.Context, idNamespaceDeleteAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match registered controller") {
		t.Fatalf("err=%v", err)
	}
	if _, _, err := world.Registry.GetNamespaceAddressAt(world.Context, world.Stack.RegistryURL, world.Domain, "alice"); err != nil {
		t.Fatalf("refused delete removed the address: %v", err)
	}
}

func TestIDNamespaceDeleteAddressActiveCertificatesMessage(t *testing.T) {
	world, member := deleteAddressWorld(t)
	world.registerMemberCertificate(t, awid.TeamCertificateFields{
		MemberDIDKey: member.DIDKey, MemberDIDAW: member.DIDAW, MemberAddress: member.Address,
		Alias: "alice", IdentityScope: awid.IdentityModeGlobal,
	})

	_, err := executeIDNamespaceDeleteAddress(world.Context, idNamespaceDeleteAddressOptions{
		Domain: world.Domain,
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "revoke team membership certificates first") {
		t.Fatalf("err=%v", err)
	}
	if _, _, err := world.Registry.GetNamespaceAddressAt(world.Context, world.Stack.RegistryURL, world.Domain, "alice"); err != nil {
		t.Fatalf("refused delete removed the address: %v", err)
	}
}

func verifyRegistrySignatureForTest(t *testing.T, r *http.Request, pub ed25519.PublicKey, fields map[string]string) {
	t.Helper()

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.Split(auth, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("Authorization=%q", auth)
	}
	if parts[1] != awid.ComputeDIDKey(pub) {
		t.Fatalf("authorization DID=%s want %s", parts[1], awid.ComputeDIDKey(pub))
	}

	timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
	if timestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp")
	}
	canonical := coveringControllerPayloadForTest(t, r, timestamp, fields)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatalf("invalid signature for payload %s", canonical)
	}
}

// coveringControllerPayloadForTest is the covering-v2 payload a controller
// signs for fields (domain and operation, and the operation's claims) over
// exactly the request r at timestamp, checked against r's
// X-AWEB-Signed-Payload. r's body is restored for the handler to read.
func coveringControllerPayloadForTest(t *testing.T, r *http.Request, timestamp string, fields map[string]string) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		body = nil
	}
	claims := map[string]any{}
	for key, value := range fields {
		if key != "domain" && key != "operation" && key != "timestamp" {
			claims[key] = value
		}
	}
	payload, err := awid.ControllerRequestPayload("http://"+r.Host, r.Method, r.URL.EscapedPath(), body,
		timestamp, fields["domain"], fields["operation"], claims)
	if err != nil {
		t.Fatalf("covering payload: %v", err)
	}
	signed, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil || !bytes.Equal(signed, payload) {
		t.Fatalf("signed payload %s, want %s", signed, payload)
	}
	return string(payload)
}
