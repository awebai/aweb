package wake

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

func TestInstanceSetPausedBeforeStartAndAfterStopReturns(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store)})
	if err != nil {
		t.Fatal(err)
	}
	runner := newInstanceRunner(broker, Registration{Home: filepath.Join(t.TempDir(), "terminal")}, InstanceState{Home: filepath.Join(t.TempDir(), "terminal")})
	runner.setPaused(true, "test-before-start")
	if !runner.state.Paused {
		t.Fatal("pause before start was not stored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	runner.start(ctx)
	waitForCond(t, "runner started", func() bool { runner.mu.Lock(); defer runner.mu.Unlock(); return runner.cancel != nil })
	cancel()
	runner.stop()
	done := make(chan struct{})
	go func() { runner.setPaused(false, "test-after-stop"); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("setPaused hung after runner stop")
	}
}

func TestBrokerDerivesLiveStateFromChannelCoreReadinessForDowngrade(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFakeNode(t, root, "#!/bin/sh\nprintf '{\"type\":\"status\",\"ready\":true,\"readiness_state\":\"idle\"}\\n'\nwhile IFS= read -r line; do :; done\n")
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	server := mailServer(t, "live-state")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	registeredAt := time.Now().UTC().Add(-31 * time.Minute)
	reg := Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession, RegisteredAt: registeredAt}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log})
	defer cancel()
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.Phase == PhaseActive && !inst.LastInspectAt.IsZero() && inst.LastState == "idle"
	})
	var state InstanceState
	waitForCond(t, "persisted child liveness", func() bool {
		var err error
		state, err = store.LoadInstance(home)
		return err == nil && !state.FirstPresentAt.IsZero() && !state.LastInspectAt.IsZero() && state.LastState == "idle"
	})
	if state.FirstPresentAt.Sub(registeredAt) <= 0 {
		t.Fatalf("first_present_at=%s should be newer than registered_at=%s", state.FirstPresentAt, registeredAt)
	}
	wouldExpireUnder13614 := state.FirstPresentAt.IsZero() && time.Since(registeredAt) > DefaultPendingExpiry
	if wouldExpireUnder13614 {
		t.Fatal("new state would be expired by 1.36.14 pending-expiry rule")
	}
}

func TestBrokerRestoresPauseBeforeChildDelivery(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "paused mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	reg := Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession, RegisteredAt: time.Now().UTC()}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInstance(InstanceState{Home: home, Paused: true}); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	defer cancel()
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Paused && inst.ChannelCore.TraceStage == "lane_job_failed" && strings.Contains(inst.ChannelCore.LastError, "paused")
	})
	assertFileNotContains(t, inputPath, "paused mail")
	if err := broker.SetPaused(home, false); err != nil {
		t.Fatal(err)
	}
	// No readiness queue retains this event; a normal subsequent offer retries it.
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return !inst.ChannelCore.Paused })
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "mail-1", ConversationID: "conv-1"})
	waitForFileContains(t, inputPath, "paused mail")
	data, _ := os.ReadFile(inputPath)
	if got := strings.Count(string(data), "paused mail"); got != 1 {
		t.Fatalf("input count=%d want 1: %q", got, data)
	}
}

func TestBrokerInitialSnapshotWaitsForAppliedRebind(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	oldServer := mailServer(t, "removed snapshot mail")
	newServer := mailServer(t, "applied snapshot mail")
	oldHome := writeGrantHome(t, filepath.Join(root, "old"), oldServer.URL, []string{"events.read", "mail.read", "mail.send"})
	newHome := writeGrantHome(t, filepath.Join(root, "new"), newServer.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	var broker *Broker
	openedNew := make(chan struct{}, 1)
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log, OpenStream: func(identityHome, teamID string) (run.EventStreamOpener, error) {
		if identityHome != newHome {
			return func(context.Context, time.Time) (awid.EventSource, error) {
				return &oneEventSource{event: awid.AgentEvent{Type: awid.AgentEventChannelReconnected}}, nil
			}, nil
		}
		inst := instanceByHome(t, broker, home)
		runner := broker.instances[HomeKey(home)]
		runner.mu.Lock()
		generation := runner.generation
		runner.mu.Unlock()
		if inst.IdentityHome != newHome || generation < 1 {
			t.Fatalf("new stream opened before applied transition: generation=%d inst=%#v", generation, inst)
		}
		openedNew <- struct{}{}
		return func(context.Context, time.Time) (awid.EventSource, error) {
			return &oneEventSource{event: awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "snapshot-new", ConversationID: "conv-new"}}, nil
		}, nil
	}})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: oldHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	if err := broker.Register(Registration{Home: home, IdentityHome: newHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-openedNew:
	case <-time.After(2 * time.Second):
		t.Fatalf("new stream was not opened after applied transition; logs=%s", logs.all())
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Generation >= 1 && inst.ChannelCore.TraceStage == "lane_job_completed" && inst.ChannelCore.TraceMessageID == "snapshot-new"
	})
	waitForFileContains(t, inputPath, "applied snapshot mail")
	assertFileNotContains(t, inputPath, "removed snapshot mail")
	data, _ := os.ReadFile(inputPath)
	if got := strings.Count(string(data), "applied snapshot mail"); got != 1 {
		t.Fatalf("applied snapshot input count=%d want 1: %q", got, data)
	}
}

func TestBrokerBindingChangeRestartsChild(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	oldServer := mailServer(t, "old mail")
	newServer := mailServer(t, "new mail")
	oldHome := writeGrantHome(t, filepath.Join(root, "old"), oldServer.URL, []string{"events.read", "mail.read", "mail.send"})
	newHome := writeGrantHome(t, filepath.Join(root, "new"), newServer.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: oldHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	if err := broker.Register(Registration{Home: home, IdentityHome: newHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.IdentityHome == newHome && inst.ChannelCore.Running && inst.ChannelCore.Generation >= 1
	})
	broker.dispatch(oldHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "old", ConversationID: "old-conv"})
	waitForCond(t, "removed binding diagnostic", func() bool { return strings.Contains(logs.all(), "reason=no_registered_binding") })
	assertFileNotContains(t, inputPath, "old mail")
	broker.dispatch(newHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "new", ConversationID: "new-conv"})
	waitForFileContains(t, inputPath, "new mail")
	assertFileNotContains(t, inputPath, "old mail")
}

func TestBrokerPauseDuringChildCreationReachesNewChild(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "creation pause mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	if err := broker.SetPaused(home, true); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "creation-pause", ConversationID: "conv"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Paused && inst.ChannelCore.TraceStage == "lane_job_failed" && strings.Contains(inst.ChannelCore.LastError, "paused")
	})
	assertFileNotContains(t, inputPath, "creation pause mail")
	if err := broker.SetPaused(home, false); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return !inst.ChannelCore.Paused })
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "creation-pause", ConversationID: "conv"})
	waitForFileContains(t, inputPath, "creation pause mail")
}

func TestBrokerIgnoresStaleInactiveGeneration(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	oldServer := mailServer(t, "old inactive mail")
	newServer := mailServer(t, "new inactive mail")
	oldHome := writeGrantHome(t, filepath.Join(root, "old"), oldServer.URL, []string{"events.read", "mail.read", "mail.send"})
	newHome := writeGrantHome(t, filepath.Join(root, "new"), newServer.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: oldHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	if err := broker.Register(Registration{Home: home, IdentityHome: newHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running && inst.ChannelCore.Generation >= 1 })
	runner := broker.instances[HomeKey(home)]
	runner.inactive <- inactiveSignal{generation: 0, state: "stopped"}
	broker.dispatch(newHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "new-inactive", ConversationID: "conv"})
	waitForFileContains(t, inputPath, "new inactive mail")
	if inst := instanceByHome(t, broker, home); inst.Phase == PhaseInactive {
		t.Fatalf("stale inactive generation made new registration inactive: %#v", inst)
	}
	if !strings.Contains(logs.all(), "inactive ignored") {
		t.Fatalf("missing stale inactive diagnostic: %s", logs.all())
	}
}

func TestBrokerDeregisterStopsBeforeDeletingState(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "deregister mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	existed, err := broker.Deregister(home)
	if err != nil || !existed {
		t.Fatalf("deregister existed=%v err=%v", existed, err)
	}
	statePath := store.instancePath(HomeKey(home))
	assertNoFileAfter(t, statePath, 300*time.Millisecond)
	cancel()
	assertNoFileAfter(t, statePath, 300*time.Millisecond)
	existed, err = broker.Deregister(home)
	if err != nil || existed {
		t.Fatalf("second deregister existed=%v err=%v, want idempotent false/nil", existed, err)
	}
}

func TestBrokerDeregisterThenSameHomeRegisterStartsFreshAndDelivers(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "reactivated mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log})
	defer cancel()
	reg := Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	writeStoppedOATS(t, root, inputPath)
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "inactive-first", ConversationID: "conv"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Phase == PhaseInactive && !inst.ChannelCore.Running })
	if existed, err := broker.Deregister(home); err != nil || !existed {
		t.Fatalf("deregister existed=%v err=%v", existed, err)
	}
	writeFakeOATS(t, root, inputPath)
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Running && !inst.Paused && inst.Phase == PhaseActive
	})
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "reactivated", ConversationID: "conv"})
	waitForFileContains(t, inputPath, "reactivated mail")
}

func TestBrokerExplicitRegisterReactivatesInactiveHome(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "explicit reactivate mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: (&logCapture{}).log})
	defer cancel()
	reg := Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	writeStoppedOATS(t, root, inputPath)
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "inactive-first", ConversationID: "conv"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Phase == PhaseInactive && !inst.ChannelCore.Running })
	writeFakeOATS(t, root, inputPath)
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Running && inst.Phase == PhaseActive && inst.LastState == "idle" && inst.LastError == ""
	})
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "explicit-reactivated", ConversationID: "conv"})
	waitForFileContains(t, inputPath, "explicit reactivate mail")
}

func TestBrokerExplicitRegisterFencesStaleInactiveCallback(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "stale inactive fenced mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	defer cancel()
	reg := Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	runner := broker.instances[HomeKey(home)]
	runner.mu.Lock()
	oldGeneration := runner.generation
	runner.mu.Unlock()
	runner.inactive <- inactiveSignal{generation: oldGeneration, state: "stopped"}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Phase == PhaseInactive && !inst.ChannelCore.Running })
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool {
		return inst.ChannelCore.Running && inst.ChannelCore.Generation > oldGeneration
	})
	runner.inactive <- inactiveSignal{generation: oldGeneration, state: "stopped"}
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "after-stale-inactive", ConversationID: "conv"})
	waitForFileContains(t, inputPath, "stale inactive fenced mail")
	if inst := instanceByHome(t, broker, home); inst.Phase == PhaseInactive {
		t.Fatalf("stale inactive generation made reactivated registration inactive: %#v", inst)
	}
	if !strings.Contains(logs.all(), "inactive ignored") {
		t.Fatalf("missing stale inactive diagnostic: %s", logs.all())
	}
}

func TestBrokerDeregisterSerializesConcurrentReconcile(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	home := tempHome(t, "terminal")
	idHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, idHome, "team:one")
	reg := Registration{Home: home, IdentityHome: idHome, Delivery: DeliverySession, RegisteredAt: time.Now().UTC()}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store)})
	if err != nil {
		t.Fatal(err)
	}
	runner := newInstanceRunner(broker, reg, InstanceState{Home: home})
	cancelCalled := make(chan struct{})
	releaseStop := make(chan struct{})
	runner.cancel = func() {
		close(cancelCalled)
		<-releaseStop
		close(runner.done)
	}
	broker.mu.Lock()
	broker.instances[HomeKey(home)] = runner
	broker.mu.Unlock()
	deregisterDone := make(chan error, 1)
	go func() {
		existed, err := broker.Deregister(home)
		if err == nil && !existed {
			err = errors.New("deregister reported missing registration")
		}
		deregisterDone <- err
	}()
	select {
	case <-cancelCalled:
	case <-time.After(time.Second):
		t.Fatal("deregister did not reach runner stop")
	}
	statusDone := make(chan struct{})
	go func() { _ = broker.Status(); close(statusDone) }()
	select {
	case <-statusDone:
	case <-time.After(time.Second):
		t.Fatal("deregister held b.mu while waiting for runner stop")
	}
	reconcileDone := make(chan struct{})
	go func() { broker.Reconcile(); close(reconcileDone) }()
	select {
	case <-reconcileDone:
		t.Fatal("concurrent reconcile completed while deregister stop/delete was in progress")
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseStop)
	select {
	case err := <-deregisterDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deregister did not complete")
	}
	select {
	case <-reconcileDone:
	case <-time.After(time.Second):
		t.Fatal("reconcile did not complete after deregister released")
	}
	broker.mu.Lock()
	_, running := broker.instances[HomeKey(home)]
	broker.mu.Unlock()
	if running {
		t.Fatal("concurrent reconcile recreated runner during deregister")
	}
	if _, ok, err := store.LoadRegistration(home); err != nil || ok {
		t.Fatalf("registration after deregister ok=%v err=%v", ok, err)
	}
	assertNoFileAfter(t, store.instancePath(HomeKey(home)), 50*time.Millisecond)
}

func TestRegisterInStoreFallbackResetsLifecyclePreservesPause(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	home := tempHome(t, "terminal")
	idHome := filepath.Join(tempHome(t, "identity"), ".aw")
	writeWakeTestTeamState(t, idHome, "team:one")
	if err := store.SaveInstance(InstanceState{Home: home, Paused: true, Inactive: true, FirstPresentAt: time.Now(), LastInspectAt: time.Now(), LastState: "stopped", LastError: "boom", UnreadCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterInStore(store, Registration{Home: home, IdentityHome: idHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Paused || state.Inactive || !state.FirstPresentAt.IsZero() || !state.LastInspectAt.IsZero() || state.LastState != "" || state.LastError != "" || state.UnreadCount != 0 {
		t.Fatalf("fallback state=%#v, want pause preserved and lifecycle reset", state)
	}
	if existed, err := store.DeleteRegistration(home); err != nil || !existed {
		t.Fatalf("delete registration existed=%v err=%v", existed, err)
	}
	if err := RegisterInStore(store, Registration{Home: home, IdentityHome: idHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	state, err = store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if state.Paused || state.Inactive {
		t.Fatalf("fresh fallback state=%#v, want unpaused active lifecycle", state)
	}
}

func TestBrokerInactiveStopsChildAndDropsLaterEvents(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.txt")
	writeFakeOATS(t, root, inputPath)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	server := mailServer(t, "inactive mail")
	grantHome := writeGrantHome(t, root, server.URL, []string{"events.read", "mail.read", "mail.send"})
	home := filepath.Join(root, "terminal")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	logs := &logCapture{}
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store), Log: logs.log})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: grantHome, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Running })
	writeStoppedOATS(t, root, inputPath)
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "inactive-1", ConversationID: "conv"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Phase == PhaseInactive && !inst.ChannelCore.Running })
	assertFileNotContains(t, inputPath, "inactive mail")
	before := instanceByHome(t, broker, home).Evicted
	broker.dispatch(grantHome, awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "inactive-2", ConversationID: "conv"})
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.Evicted > before })
	waitForCond(t, "inactive drop diagnostic", func() bool {
		return strings.Contains(logs.all(), "reason=inactive") || strings.Contains(logs.all(), "reason=no_registered_binding")
	})
	assertFileNotContains(t, inputPath, "inactive mail")
}

func TestChannelCoreStatusSnapshotIsRaceSafe(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFakeNode(t, root, "#!/bin/sh\nwhile :; do printf '{\"type\":\"status\",\"binding_id\":\"b1\",\"error\":\"boom\"}\\n'; printf '{\"type\":\"status\",\"binding_id\":\"b1\",\"trace_stage\":\"lane_job_completed\",\"trace_message_id\":\"m1\"}\\n'; done\n")
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	child := NewChannelCoreRunner(store).StartChild(context.Background(), Registration{Home: filepath.Join(root, "terminal")}, channelCoreChildConfig{})
	defer child.Stop()
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		_, _ = json.Marshal(child.Status())
	}
	waitForStatus(t, child, func(st ChannelCoreStatus) bool { return st.TraceStage == "lane_job_completed" })
}

func mailServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages/inbox":
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []map[string]any{{
				"message_id": r.URL.Query().Get("message_id"), "conversation_id": "conv", "from_agent_id": "agent-bob", "from_alias": "bob", "subject": "hello", "body": body, "priority": "normal", "created_at": "2026-01-01T00:00:00Z",
			}}})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/messages/") && strings.HasSuffix(r.URL.Path, "/ack"):
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeStoppedOATS(t *testing.T, root, inputPath string) string {
	t.Helper()
	path := filepath.Join(root, "oats")
	script := "#!/bin/sh\nif [ \"$1 $2\" = \"session inspect\" ]; then printf '{\"ok\":true,\"result\":{\"present\":true,\"state\":\"stopped\"}}\\n'; exit 0; fi\nif [ \"$1 $2\" = \"session input\" ]; then cat >> " + shellQuoteForTest(inputPath) + "; printf '{\"ok\":true,\"result\":{\"submitted\":true}}\\n'; exit 0; fi\nprintf '{\"ok\":false,\"error\":{\"message\":\"bad oats\"}}\\n'; exit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitForInstance(t *testing.T, broker *Broker, home string, cond func(InstanceStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last Status
	for time.Now().Before(deadline) {
		last = broker.Status()
		for _, inst := range last.Instances {
			if inst.Home == home && cond(inst) {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for instance status; last=%#v", last)
}

func instanceByHome(t *testing.T, broker *Broker, home string) InstanceStatus {
	t.Helper()
	for _, inst := range broker.Status().Instances {
		if inst.Home == home {
			return inst
		}
	}
	t.Fatalf("instance %s not found", home)
	return InstanceStatus{}
}

func assertNoFileAfter(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		_, err := os.Stat(path)
		if os.IsNotExist(err) && time.Now().After(deadline) {
			return
		}
		if err == nil && time.Now().After(deadline) {
			t.Fatalf("%s exists after %s", path, d)
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertFileNotContains(t *testing.T, path, needle string) {
	t.Helper()
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), needle) {
		t.Fatalf("%s unexpectedly contains %q: %q", path, needle, string(data))
	}
}
