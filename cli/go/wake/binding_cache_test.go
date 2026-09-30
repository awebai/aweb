package wake

import (
	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/wake/session"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRetainedBindingDispatchDoesNotReadIdentityFiles(t *testing.T) {
	for _, team := range []string{"", "team:one"} {
		t.Run(team, func(t *testing.T) {
			store := tempStore(t)
			home := tempHome(t, "terminal")
			identity := filepath.Join(home, ".aw")
			if team != "" {
				writeWakeTestTeamState(t, identity, team)
			}
			broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
			if err != nil {
				t.Fatal(err)
			}
			if err := broker.Register(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
				t.Fatal(err)
			}
			runner, ok := broker.instanceRunner(home)
			if !ok {
				t.Fatal("missing runner")
			}
			// The accepted registration must survive the same filesystem outage that
			// caused reconciliation to retain it. Dispatch and pruning must be pure reads.
			oldRead := wakeReadFile
			reads := 0
			wakeReadFile = func(string) ([]byte, error) { reads++; return nil, syscall.EMFILE }
			defer func() { wakeReadFile = oldRead }()
			if err := os.Rename(identity, identity+"-unavailable"); err != nil {
				t.Fatal(err)
			}
			broker.dispatchStream(identity+"\x00"+team, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "retained"})
			if len(runner.events) != 1 {
				t.Fatalf("retained registration lost event; queued=%d reads=%d", len(runner.events), reads)
			}
			if got := runner.receiveBindings(); len(got) != 1 || got[0].TeamID != team {
				t.Fatalf("last-good binding lost: %#v", got)
			}
			if reads != 0 {
				t.Fatalf("dispatch re-read identity files %d times", reads)
			}
		})
	}
}

func TestChildOfferKeepsRegistrationTeamEvenWhenEmpty(t *testing.T) {
	home := tempHome(t, "identity")
	identity := filepath.Join(home, ".aw")
	child := &ChannelCoreChild{in: make(chan childLine, 1)}
	writeWakeTestTeamState(t, identity, "team:new")
	child.Offer(ReceiveIdentity{IdentityHome: identity, TeamID: ""}, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "pinned"})
	got := <-child.in
	if got.BindingID != identity+"|" {
		t.Fatalf("offer re-resolved registration team: %q", got.BindingID)
	}
}
