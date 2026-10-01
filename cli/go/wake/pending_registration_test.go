package wake

import (
	"path/filepath"
	"testing"

	"github.com/awebai/aw/wake/session"
)

func TestPendingRebindIgnoresIdenticalReconcile(t *testing.T) {
	broker, err := NewBroker(Config{Store: tempStore(t), Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	home := tempHome(t, "terminal")
	original := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(original); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	// Model a running child whose stop has not finished. The first update is
	// already consumed, but its binding has not yet been published.
	runner.cancel = func() {}
	rebound := original
	rebound.IdentityHome = filepath.Join(tempHome(t, "new-identity"), ".aw")
	if err := broker.Register(rebound); err != nil {
		t.Fatal(err)
	}
	<-runner.updates
	broker.Reconcile()
	if len(runner.updates) != 0 {
		t.Fatal("reconcile queued the in-flight binding a second time")
	}
	if runner.reg.IdentityHome != original.IdentityHome || runner.generation != 0 || !runner.hasPendingRegistration() {
		t.Fatal("duplicate reconcile published a binding before the old child stopped")
	}
}

func TestPendingRebindCanReturnToAppliedBinding(t *testing.T) {
	broker, err := NewBroker(Config{Store: tempStore(t), Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	home := tempHome(t, "terminal")
	original := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(original); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	runner.cancel = func() {}
	rebound := original
	rebound.IdentityHome = filepath.Join(tempHome(t, "new-identity"), ".aw")
	if err := broker.Register(rebound); err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(original); err != nil {
		t.Fatal(err)
	}
	queued := <-runner.updates
	if queued.IdentityHome != original.IdentityHome || runner.pendingReg.IdentityHome != original.IdentityHome {
		t.Fatal("latest registration did not replace the pending rebind")
	}
	if runner.generation != 0 {
		t.Fatal("queued registration advanced generation before application")
	}
}
