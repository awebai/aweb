package wake

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/wake/session"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: at(0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) log(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func writeWakeTestTeamState(t *testing.T, identityHome, teamID string) {
	t.Helper()
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(identityHome, "teams.yaml"), []byte("active_team: "+teamID+"\nmemberships:\n  - team_id: "+teamID+"\n    alias: test\n    cert_path: cert.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newBrokerForUnit(t *testing.T, store *Store, now func() time.Time) *Broker {
	t.Helper()
	logs := &logCapture{}
	broker, err := NewBroker(Config{
		Store:         store,
		Session:       session.NewFake(session.Inspection{}),
		Now:           now,
		Log:           logs.log,
		PendingExpiry: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

func TestReconcileRetainsRunnerOnRegistrationReadError(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "one")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	logs := &logCapture{}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	if _, ok := broker.instanceRunner(home); !ok {
		t.Fatal("runner missing before transient error")
	}
	if err := store.SaveRegistration(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession, RegisteredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	origReadFile := wakeReadFile
	wakeReadFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "teams.yaml") {
			return nil, &os.PathError{Op: "open", Path: path, Err: syscall.EIO}
		}
		return origReadFile(path)
	}
	defer func() { wakeReadFile = origReadFile }()

	broker.Reconcile()
	if _, ok := broker.instanceRunner(home); !ok {
		t.Fatal("transient team read error removed runner")
	}
	if _, ok, err := store.LoadRegistration(home); err != nil || !ok {
		t.Fatalf("registration not retained after transient read: ok=%v err=%v", ok, err)
	}
	st := broker.Status().Instances[0]
	if !strings.Contains(st.LastError, "input/output error") {
		t.Fatalf("status LastError=%q, want read error", st.LastError)
	}
}

func TestReconcileRetainsRunnerWhenExistingRegistrationFileIsInvalid(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "one")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	logs := &logCapture{}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	key := HomeKey(home)
	if err := os.WriteFile(store.registryPath(key), []byte(`{"home":"","identity_home":"`+identityHome+`","delivery":"session"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	broker.Reconcile()
	if _, ok := broker.instanceRunner(home); !ok {
		t.Fatal("invalid existing registration file removed runner")
	}
	if !strings.Contains(logs.all(), "reconcile failed") {
		t.Fatalf("list/validation failure was not logged: %s", logs.all())
	}
}

func TestRegisterRejectsDuplicateEffectiveBinding(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home1 := tempHome(t, "one")
	home2 := tempHome(t, "two")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	broker := newBrokerForUnit(t, store, clk.now)
	if err := broker.Register(Registration{Home: home1, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	err := broker.Register(Registration{Home: home2, Delivery: DeliverySession, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{{IdentityHome: identityHome, TeamID: "team:one", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true}}})
	if err == nil || !strings.Contains(err.Error(), home1) || !strings.Contains(err.Error(), "already owned") {
		t.Fatalf("duplicate binding error=%v, want owner %s", err, home1)
	}
}

func TestRegisterAllowsSameRootDifferentTeams(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home := tempHome(t, "one")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	broker := newBrokerForUnit(t, store, clk.now)
	err := broker.Register(Registration{Home: home, Delivery: DeliverySession, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{
		{IdentityHome: identityHome, TeamID: "team:one", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}},
		{IdentityHome: identityHome, TeamID: "team:two", DeliveryOwner: ReceiveOwnerSessionHints, EventClasses: []string{EventClassMail}},
	}})
	if err != nil {
		t.Fatalf("same root under different teams should be allowed: %v", err)
	}
}

func TestRegisterPinsBlankTeamToEffectiveTeam(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home := tempHome(t, "one")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	broker := newBrokerForUnit(t, store, clk.now)
	if err := broker.Register(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	stored, ok, err := store.LoadRegistration(home)
	if err != nil || !ok {
		t.Fatalf("load registration ok=%v err=%v", ok, err)
	}
	bindings := stored.ReceiveBindings()
	if len(bindings) != 1 || bindings[0].TeamID != "team:one" {
		t.Fatalf("bindings=%#v, want blank team pinned to team:one", bindings)
	}
	writeWakeTestTeamState(t, identityHome, "team:two")
	if got, err := bindingKey(identityHome, bindings[0].TeamID); err != nil || !strings.Contains(got, "team:one") {
		t.Fatalf("binding key after active switch = %q err=%v, want pinned team:one", got, err)
	}
}

func TestRegisterRejectsBlankTeamDuplicateOfEffectiveTeam(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home1 := tempHome(t, "one")
	home2 := tempHome(t, "two")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:active")
	broker := newBrokerForUnit(t, store, clk.now)
	if err := broker.Register(Registration{Home: home1, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	err := broker.Register(Registration{Home: home2, Delivery: DeliverySession, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{{IdentityHome: identityHome, TeamID: "team:active", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true}}})
	if err == nil || !strings.Contains(err.Error(), home1) {
		t.Fatalf("blank/default duplicate error=%v, want owner %s", err, home1)
	}
}

func TestLoadedDuplicateBindingReportsConflictAndReceivesNoDelivery(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home1 := tempHome(t, "one")
	home2 := tempHome(t, "two")
	identityHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	if err := store.SaveRegistration(Registration{Home: home1, IdentityHome: identityHome, Delivery: DeliverySession, RegisteredAt: at(0)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRegistration(Registration{Home: home2, Delivery: DeliverySession, RuntimeDelivery: RuntimeDeliveryExternalSession, ReceiveIdentities: []ReceiveIdentity{{IdentityHome: identityHome, TeamID: "team:one", DeliveryOwner: ReceiveOwnerSessionHints, Controls: true}}, RegisteredAt: at(1)}); err != nil {
		t.Fatal(err)
	}
	broker := newBrokerForUnit(t, store, clk.now)
	broker.Reconcile()
	status := broker.Status()
	conflicts := map[string]string{}
	for _, inst := range status.Instances {
		conflicts[inst.Home] = inst.ConflictHome
	}
	if conflicts[home1] != "" || conflicts[home2] != home1 {
		t.Fatalf("conflicts=%#v, want %s to own and %s to conflict", conflicts, home1, home2)
	}
	broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"})
	if got := len(broker.instances[HomeKey(home1)].events); got != 1 {
		t.Fatalf("winner events=%d want 1", got)
	}
	if got := len(broker.instances[HomeKey(home2)].events); got != 0 {
		t.Fatalf("conflict loser events=%d want 0", got)
	}
}

func TestDispatchSkipsTransportOnlyEvents(t *testing.T) {
	store := tempStore(t)
	clk := newClock()
	home := tempHome(t, "one")
	identityHome := filepath.Join(home, ".aw")
	writeWakeTestTeamState(t, identityHome, "team:one")
	broker := newBrokerForUnit(t, store, clk.now)
	if err := broker.Register(Registration{Home: home, IdentityHome: identityHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	runner := broker.instances[HomeKey(home)]
	broker.dispatch(identityHome, awid.AgentEvent{Type: awid.AgentEventChannelReconnected})
	if got := len(runner.events); got != 0 {
		t.Fatalf("transport-only event queued=%d", got)
	}
}
