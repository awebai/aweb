package wake

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

func TestCallReportsTheDaemonIsDownRatherThanFailing(t *testing.T) {
	store := tempStore(t)
	_, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus})
	if !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("err=%v want ErrDaemonDown; the CLI needs this to choose the file fallback", err)
	}
}

// TestControlSocketDrivesTheRunningDaemon.
func TestControlSocketDrivesTheRunningDaemon(t *testing.T) {
	store := shortTempStore(t)
	home := tempHome(t, "instance")
	oats := session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateBusy, RawState: "working"})
	logs := &logCapture{}

	broker, _ := liveBroker(t, Config{
		Store:      store,
		Session:    oats,
		Log:        logs.log,
		OpenStream: func(string) (run.EventStreamOpener, error) { return nil, errors.New("no stream in this test") },
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- ServeControl(ctx, broker) }()
	waitFor(t, "the control socket to accept", func() bool {
		select {
		case err := <-served:
			t.Fatalf("ServeControl exited: %v", err)
		default:
		}
		_, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus})
		return err == nil
	})

	reg := Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, Backend: "tmux"}
	if _, err := Call(store.SocketPath(), ControlRequest{Op: OpRegister, Registration: &reg}); err != nil {
		t.Fatalf("register over the socket: %v", err)
	}
	waitFor(t, "the registration to appear in status", func() bool {
		resp, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus})
		return err == nil && resp.Status != nil && len(resp.Status.Instances) == 1
	})

	if _, err := Call(store.SocketPath(), ControlRequest{Op: OpPause, Home: home}); err != nil {
		t.Fatalf("pause over the socket: %v", err)
	}
	waitFor(t, "pause to be durable", func() bool {
		state, err := store.LoadInstance(home)
		return err == nil && state.Paused
	})
	if _, err := Call(store.SocketPath(), ControlRequest{Op: OpResume, Home: home}); err != nil {
		t.Fatalf("resume over the socket: %v", err)
	}
	waitFor(t, "resume to be durable", func() bool {
		state, err := store.LoadInstance(home)
		return err == nil && !state.Paused
	})

	resp, err := Call(store.SocketPath(), ControlRequest{Op: OpDeregister, Home: home})
	if err != nil || !resp.Existed {
		t.Fatalf("deregister over the socket: existed=%t err=%v", resp.Existed, err)
	}
	if _, ok, _ := store.LoadRegistration(home); ok {
		t.Fatal("deregister left the registration file behind")
	}

	// The exclusivity check applies over the socket too.
	bad := Registration{Home: home, IdentityHome: home + "/.aw", Delivery: "channel"}
	if _, err := Call(store.SocketPath(), ControlRequest{Op: OpRegister, Registration: &bad}); err == nil {
		t.Fatal("a registration without delivery=session was accepted over the socket")
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("ServeControl: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeControl did not stop")
	}
}

// TestFallbackFilesAreReconciledByTheDaemon is the hook's safety net: a spawn
// hook must not fail because the broker happens to be restarting, so the
// command writes the registration file directly and the daemon picks it up.
func TestFallbackFilesAreReconciledByTheDaemon(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "instance")

	// The daemon is down; the command writes the file itself.
	reg := Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, Backend: "herdr"}
	if err := reg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	if err := SetPausedInStore(store, home, true); err != nil {
		t.Fatal(err)
	}

	// A registration file that never passed the exclusivity check — however it
	// got there — is refused by the daemon rather than trusted because a file
	// exists.
	rogue := tempHome(t, "rogue")
	if err := store.SaveRegistration(Registration{Home: rogue, IdentityHome: rogue + "/.aw", Delivery: "channel"}); err != nil {
		t.Fatal(err)
	}

	logs := &logCapture{}
	oats := session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateIdle, RawState: "idle"})
	broker, _ := liveBroker(t, Config{
		Store:      store,
		Session:    oats,
		Log:        logs.log,
		OpenStream: func(string) (run.EventStreamOpener, error) { return nil, errors.New("no stream in this test") },
	})

	waitFor(t, "the daemon to reconcile the fallback file", func() bool {
		for _, inst := range broker.Status().Instances {
			if inst.Home == home {
				return true
			}
		}
		return false
	})

	status := broker.Status()
	if len(status.Instances) != 1 {
		t.Fatalf("the daemon adopted a registration it should have refused: %#v", status.Instances)
	}
	if !status.Instances[0].Paused {
		t.Fatal("durable pause written by the fallback path was lost")
	}
	if !strings.Contains(logs.all(), "registration refused") {
		t.Fatalf("the refusal was not reported:\n%s", logs.all())
	}
	if !strings.Contains(logs.all(), "registered home=") {
		t.Fatalf("no log line at the registered transition:\n%s", logs.all())
	}
}

// TestStatusFromStoreAnswersWithTheDaemonDown.
func TestStatusFromStoreAnswersWithTheDaemonDown(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "instance")
	if err := store.SaveRegistration(Registration{
		Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, Backend: "tmux", RegisteredAt: at(0),
	}); err != nil {
		t.Fatal(err)
	}
	state := InstanceState{Home: home, Paused: true, Evicted: 7, LastState: "working"}
	state.AddHint(Hint{Kind: KindMail, MessageID: "m1", At: at(0)}, DefaultHintCap)
	if err := store.SaveInstance(state); err != nil {
		t.Fatal(err)
	}

	status, err := StatusFromStore(store, 128)
	if err != nil {
		t.Fatal(err)
	}
	if status.DaemonRunning {
		t.Fatal("no daemon is running")
	}
	if len(status.Instances) != 1 {
		t.Fatalf("instances=%#v", status.Instances)
	}
	got := status.Instances[0]
	if got.Phase != PhasePending || !got.Paused || got.PendingHints != 1 || got.Evicted != 7 {
		t.Fatalf("status lost per-home state: %#v", got)
	}
}
