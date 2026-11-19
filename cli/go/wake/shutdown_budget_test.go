package wake

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/awebai/aw/wake/session"
)

// TestBrokerShutdownStopsChildrenTogether: the container supervisor gives the
// broker a fixed budget to stop, so stopping a team must cost one child's exit
// time, not the sum over the team.
func TestBrokerShutdownStopsChildrenTogether(t *testing.T) {
	const homes = 3
	const childExit = time.Second
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// Each child takes childExit to exit after SIGTERM.
	writeFakeNode(t, root, "#!/bin/sh\ntrap 'sleep 1; exit 0' TERM\nprintf '{\"type\":\"status\",\"ready\":true,\"readiness_state\":\"idle\"}\\n'\nwhile :; do sleep 0.05; done\n")
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	server := mailServer(t, "shutdown")
	registered := []string{}
	for i := 0; i < homes; i++ {
		dir := filepath.Join(root, "agent-"+strconv.Itoa(i))
		home := filepath.Join(dir, "home")
		if err := os.MkdirAll(home, 0o700); err != nil {
			t.Fatal(err)
		}
		grantHome := writeGrantHome(t, dir, server.URL, []string{"events.read", "mail.read"})
		if err := store.SaveRegistration(Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession, RegisteredAt: at(i)}); err != nil {
			t.Fatal(err)
		}
		registered = append(registered, home)
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log, Reconcile: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_ = broker.Run(ctx)
	}()
	for _, home := range registered {
		waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Phase == PhaseActive })
	}

	began := time.Now()
	cancel()
	select {
	case <-stopped:
	case <-time.After(time.Duration(homes+2) * childExit):
		t.Fatal("broker did not stop")
	}
	took := time.Since(began)
	if took < childExit {
		t.Fatalf("broker stopped in %s, before its children could exit (%s each)", took, childExit)
	}
	if took >= 2*childExit {
		t.Fatalf("broker took %s to stop %d children that exit in %s each: they were stopped one after another", took, homes, childExit)
	}
}
