package wake

import (
	"github.com/awebai/aw/wake/session"
	"os"
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
	originalRename := wakeRename
	wakeRename = func(old, new string) error {
		if strings.Contains(new, "instances.d") && writes.Add(1) == 1 {
			close(entered)
			<-release
		}
		return os.Rename(old, new)
	}
	defer func() { wakeRename = originalRename }()
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
