package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// awaitRevocationRefusal polls attempt until it reports the member refused, and
// counts that refusal only when the attempt completed by the deadline. Each
// attempt gets the budget that remains, and so does each pause between them.
func awaitRevocationRefusal(
	deadline time.Time,
	now func() time.Time,
	sleep func(time.Duration),
	attempt func(n int, remaining time.Duration) (refused bool, err error),
) (int, error) {
	for n := 1; ; n++ {
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return n - 1, fmt.Errorf("still accepted at the deadline after %d attempt(s)", n-1)
		}
		refused, err := attempt(n, remaining)
		if err != nil {
			return n, err
		}
		if late := now().Sub(deadline); late > 0 {
			return n, fmt.Errorf("attempt %d completed %s after the deadline", n, late)
		}
		if refused {
			return n, nil
		}
		if remaining = deadline.Sub(now()); remaining > 0 {
			sleep(min(5*time.Second, remaining))
		}
	}
}

// fakeClock advances only when slept or when an attempt takes time.
type fakeClock struct{ at time.Time }

func (c *fakeClock) now() time.Time        { return c.at }
func (c *fakeClock) sleep(d time.Duration) { c.at = c.at.Add(d) }
func (c *fakeClock) spend(d time.Duration) { c.at = c.at.Add(d) }

func TestRevocationRefusalCountsOnlyWithinTheDeadline(t *testing.T) {
	start := time.Unix(0, 0)
	for name, tc := range map[string]struct {
		attemptTakes time.Duration
		refuseAt     int
		wantErr      string
	}{
		"refused within the window":         {time.Second, 3, ""},
		"correct refusal arriving too late": {20100 * time.Millisecond, 1, "after the deadline"},
		"never refused":                     {time.Second, 1000, "still accepted at the deadline"},
	} {
		t.Run(name, func(t *testing.T) {
			clock := &fakeClock{at: start}
			var budgets []time.Duration
			_, err := awaitRevocationRefusal(start.Add(20*time.Second), clock.now, clock.sleep,
				func(n int, remaining time.Duration) (bool, error) {
					budgets = append(budgets, remaining)
					clock.spend(tc.attemptTakes)
					return n >= tc.refuseAt, nil
				})
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			for _, budget := range budgets {
				if budget <= 0 || budget > 20*time.Second {
					t.Fatalf("an attempt got budget %s outside the window", budget)
				}
			}
		})
	}
}

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

	var refusedSubject string
	attempts, err := awaitRevocationRefusal(deadline, time.Now, time.Sleep, func(n int, remaining time.Duration) (bool, error) {
		subject := fmt.Sprintf("after-revocation-%d", n)
		ctx, cancel := context.WithTimeout(world.Context, remaining)
		defer cancel()
		out, err := world.runInIdentityHomeContext(ctx, bob.Home, "mail", "send", "--to", "alice", "--subject", subject, "--body", "must not arrive")
		if err == nil {
			return false, nil
		}
		var refused cliErrorEnvelope
		if json.Unmarshal([]byte(out), &refused) != nil || refused.Error.HTTPStatus != 401 || refused.Error.Reason != "certificate_revoked" {
			return false, fmt.Errorf("revoked member got a refusal other than certificate_revoked: %v\n%s", err, out)
		}
		refusedSubject = subject
		return true, nil
	})
	if err != nil {
		t.Fatalf("revocation window %ds: %v", world.Stack.RevocationWindowSeconds, err)
	}
	t.Logf("refused %s after revocation, attempt %d", time.Since(revoked).Round(time.Second), attempts)

	if inbox := world.requireCommand(t, alice.Home, "mail", "inbox"); strings.Contains(inbox, refusedSubject) {
		t.Fatalf("a refused send was delivered: %s\n%s", refusedSubject, inbox)
	}
}
