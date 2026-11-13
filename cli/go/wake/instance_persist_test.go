package wake

import (
	"context"

	"github.com/awebai/aw/wake/session"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInstancePersistenceCannotOverwriteNewerPause(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "terminal")
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	runner := newInstanceRunner(broker, Registration{Home: home}, InstanceState{Home: home})
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	var writes atomic.Int32
	wakeBeforeCommit = func(path string) {
		if strings.Contains(path, "instances.d") && writes.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	defer func() { wakeBeforeCommit = nil }()
	go func() { runner.persist(); close(firstDone) }()
	<-entered
	runner.mu.Lock()
	runner.state.Paused = true
	runner.mu.Unlock()
	go func() { runner.persist(); close(secondDone) }()
	// Release the old write only after the new write could have overtaken it.
	// With serialization the second writer waits and lands last.
	select {
	case <-secondDone:
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-firstDone
	<-secondDone
	state, err := store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Paused {
		t.Fatal("older persistence write overwrote the newer pause")
	}
}

// The channel-core child's status lines carry delivery control (snapshot
// requests, accepted input) on the same reader as terminal liveness. Recording
// liveness must not hold that reader behind a durable state write.
func TestChildLivenessDoesNotWaitForStateWrite(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "terminal")
	broker, err := NewBroker(Config{Store: store, Session: session.NewFake(session.Inspection{})})
	if err != nil {
		t.Fatal(err)
	}
	runner := newInstanceRunner(broker, Registration{Home: home}, InstanceState{Home: home})
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	wakeBeforeCommit = func(path string) {
		if strings.Contains(path, "instances.d") {
			entered <- struct{}{}
			<-release
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	runner.start(ctx)
	defer func() {
		cancel()
		runner.stop()
		wakeBeforeCommit = nil
	}()

	recorded := make(chan struct{})
	go func() {
		runner.recordChildLiveness(0, time.Now().UTC(), "shell", "")
		close(recorded)
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("liveness was never written")
	}
	select {
	case <-recorded:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("recording liveness waited for the state write")
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, err := store.LoadInstance(home)
		if err != nil {
			t.Fatal(err)
		}
		if state.LastState == "shell" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("liveness never reached the store: %#v", state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
