package awid

import (
	"crypto/ed25519"
	"testing"
)

func TestLocalTeamRouteSignedLabel(t *testing.T) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cert := testTeamCertificate(t, key, "alice")
	client, err := NewWithCertificate("http://localhost:9999", key, cert)
	if err != nil {
		t.Fatal(err)
	}
	client.SetAddress("acme.com/alice")
	for _, identity := range []bool{false, true} {
		if got := client.signedPayloadFrom(identity, false); got != cert.Team+"/alice" {
			t.Fatalf("local route label = %q, want full team %q", got, cert.Team+"/alice")
		}
	}
	// Ordinary team-local aliases remain readable by old same-server clients.
	if got := client.signedPayloadFrom(false, true); got != "alice" {
		t.Fatalf("same-team label = %q", got)
	}
	client.SetStableID("did:aw:global-test")
	if got := client.signedPayloadFrom(true, false); got != "acme.com/alice" {
		t.Fatalf("global address label = %q", got)
	}
}
