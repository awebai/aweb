package wake

import (
	"context"
	"encoding/json"
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
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Paused && inst.ChannelCore.LastError == "" })
	assertFileNotContains(t, inputPath, "paused mail")
	if err := broker.SetPaused(home, false); err != nil {
		t.Fatal(err)
	}
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
		if inst.IdentityHome != newHome || inst.ChannelCore.Generation < 1 {
			t.Fatalf("new stream opened before applied transition: inst=%#v", inst)
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
	waitForInstance(t, broker, home, func(inst InstanceStatus) bool { return inst.ChannelCore.Paused && inst.ChannelCore.LastError == "" })
	assertFileNotContains(t, inputPath, "creation pause mail")
	if err := broker.SetPaused(home, false); err != nil {
		t.Fatal(err)
	}
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
	writeStoppedOATS(t, root, inputPath)
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

func assertFileNotContains(t *testing.T, path, needle string) {
	t.Helper()
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), needle) {
		t.Fatalf("%s unexpectedly contains %q: %q", path, needle, string(data))
	}
}
