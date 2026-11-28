package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A removed member is refused by the healthy server within the documented
// revocation window, with no cache flush, and nothing it sent is delivered.
func TestRealServerRevokedMemberIsRefusedWithoutACacheFlush(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")
	if world.Stack.RevocationWindowSeconds <= 0 {
		t.Fatalf("fixture reported no revocation window: %+v", world.Stack)
	}

	// Bob's credential is accepted, which also fills the server's revocation cache.
	world.requireCommand(t, bob.Home, "mail", "send", "--to", "alice", "--subject", "before-revocation", "--body", "accepted")
	if inbox := world.requireCommand(t, alice.Home, "mail", "inbox"); !strings.Contains(inbox, "before-revocation") {
		t.Fatalf("bob's mail was not delivered before revocation: %s", inbox)
	}

	if err := world.Registry.RevokeCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", bob.Certificate.CertificateID, world.TeamKey); err != nil {
		t.Fatal(err)
	}
	// The successful removal is the anchor the window is measured from.
	revoked := time.Now()
	deadline := revoked.Add(time.Duration(world.Stack.RevocationWindowSeconds)*time.Second + 5*time.Second)

	var refusedSubjects []string
	for attempt := 1; ; attempt++ {
		subject := fmt.Sprintf("after-revocation-%d", attempt)
		out, err := world.runInIdentityHome(bob.Home, "mail", "send", "--to", "alice", "--subject", subject, "--body", "must not arrive")
		if err != nil {
			var refused cliErrorEnvelope
			if json.Unmarshal([]byte(out), &refused) != nil || refused.Error.HTTPStatus != 401 || refused.Error.Reason != "certificate_revoked" {
				t.Fatalf("revoked member got a refusal other than certificate_revoked: %v\n%s", err, out)
			}
			refusedSubjects = append(refusedSubjects, subject)
			t.Logf("refused %s after revocation, attempt %d", time.Since(revoked).Round(time.Second), attempt)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("revoked member was still accepted %s after removal (window %ds)", time.Since(revoked).Round(time.Second), world.Stack.RevocationWindowSeconds)
		}
		time.Sleep(5 * time.Second)
	}

	inbox := world.requireCommand(t, alice.Home, "mail", "inbox")
	for _, subject := range refusedSubjects {
		if strings.Contains(inbox, subject) {
			t.Fatalf("a refused send was delivered: %s\n%s", subject, inbox)
		}
	}
}
