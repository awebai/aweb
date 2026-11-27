package wake

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

// A home whose registration file goes bad keeps its last-good runner, and so
// keeps owning that runner's receive bindings: a later registration of the
// same binding stays refused, and one event is delivered once.
func TestRetainedRunnerKeepsItsBindingOwnership(t *testing.T) {
	for name, broken := range map[string]func(home, identityHome string) []byte{
		"unreadable": func(string, string) []byte { return []byte("{invalid") },
		"invalid": func(home, identityHome string) []byte {
			return []byte(`{"home":"` + home + `","identity_home":"` + identityHome + `","delivery":"session","backend":"bogus"}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := tempStore(t)
			home1 := tempHome(t, "one")
			home2 := tempHome(t, "two")
			identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
			writeWakeTestTeamState(t, identityHome, "team:one")
			for i, home := range []string{home1, home2} {
				if err := store.SaveRegistration(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession, RegisteredAt: at(i)}); err != nil {
					t.Fatal(err)
				}
			}
			broker := newBrokerForUnit(t, store, newClock().now)
			broker.Reconcile()
			before, _ := broker.instanceRunner(home2)
			if before.snapshot().ConflictHome != home1 {
				t.Fatal("fixture must begin with a correctly refused duplicate")
			}
			if err := os.WriteFile(store.registryPath(HomeKey(home1)), broken(home1, identityHome), 0o600); err != nil {
				t.Fatal(err)
			}

			broker.Reconcile()

			first, ok := broker.instanceRunner(home1)
			if !ok {
				t.Fatal("last-good owner was not retained")
			}
			second, ok := broker.instanceRunner(home2)
			if !ok {
				t.Fatal("second registration vanished")
			}
			if got := second.snapshot().ConflictHome; got != home1 {
				t.Fatalf("second ConflictHome=%q, want it still refused in favour of %s", got, home1)
			}
			broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"})
			if len(first.events) != 1 || len(second.events) != 0 {
				t.Fatalf("dispatch queues: first=%d second=%d, want the event delivered to the retained owner only", len(first.events), len(second.events))
			}
		})
	}
}
