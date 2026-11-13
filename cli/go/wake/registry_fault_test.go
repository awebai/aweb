package wake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/wake/session"
)

// writeUnreadableRegistrations puts two registry files the broker cannot use
// beside the good ones: one that is not JSON, and one whose home is relative.
func writeUnreadableRegistrations(t *testing.T, store *Store) []string {
	t.Helper()
	dir := filepath.Join(store.Dir(), "registry.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	notJSON := filepath.Join(dir, "0000000000000000000000000000000000000000000000000000000000000001.json")
	if err := os.WriteFile(notJSON, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	relative := filepath.Join(dir, "0000000000000000000000000000000000000000000000000000000000000002.json")
	if err := os.WriteFile(relative, []byte(`{"home":"relative/home","identity_home":"relative/home/.aw","delivery":"session"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{notJSON, relative}
}

func assertFaultsReported(t *testing.T, faults []RegistrationFault, paths []string) {
	t.Helper()
	if len(faults) != len(paths) {
		t.Fatalf("faults=%#v, want one per unreadable file %v", faults, paths)
	}
	for i, path := range paths {
		if faults[i].Path != path || strings.TrimSpace(faults[i].Error) == "" {
			t.Fatalf("fault %d=%#v, want path %s with its error", i, faults[i], path)
		}
	}
}

func TestReconcileSkipsUnreadableRegistrationsAndWakesTheRest(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "good")
	if err := store.SaveRegistration(Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession, Backend: "tmux", RegisteredAt: at(0)}); err != nil {
		t.Fatal(err)
	}
	bad := writeUnreadableRegistrations(t, store)
	logs := &logCapture{}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), Log: logs.log})
	if err != nil {
		t.Fatal(err)
	}

	broker.Reconcile()

	if _, ok := broker.instanceRunner(home); !ok {
		t.Fatalf("an unreadable registry file stopped the readable home:\n%s", logs.all())
	}
	assertFaultsReported(t, broker.Status().RegistrationFaults, bad)
	for _, path := range bad {
		if !strings.Contains(logs.all(), "registration unreadable path="+path) {
			t.Fatalf("unreadable file %s was not logged:\n%s", path, logs.all())
		}
	}
}

func TestRegisterSucceedsBesideUnreadableRegistrations(t *testing.T) {
	store := tempStore(t)
	writeUnreadableRegistrations(t, store)
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	home := tempHome(t, "good")
	if err := broker.Register(Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}); err != nil {
		t.Fatalf("an unreadable registry file refused another home's registration: %v", err)
	}
}

func TestStatusFromStoreReportsUnreadableRegistrations(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "good")
	if err := store.SaveRegistration(Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession, Backend: "tmux", RegisteredAt: at(0)}); err != nil {
		t.Fatal(err)
	}
	bad := writeUnreadableRegistrations(t, store)

	status, err := StatusFromStore(store, 128)
	if err != nil {
		t.Fatalf("an unreadable registry file failed status: %v", err)
	}
	if len(status.Instances) != 1 || status.Instances[0].Home != home {
		t.Fatalf("instances=%#v, want the readable home", status.Instances)
	}
	assertFaultsReported(t, status.RegistrationFaults, bad)
}
