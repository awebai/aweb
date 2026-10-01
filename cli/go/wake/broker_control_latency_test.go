package wake

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/run"
)

// Hold a real registry snapshot read after obtaining its old bytes. Controls
// must finish before this pass resumes, and the old snapshot must not undo them.
func TestBrokerControlsDuringSlowReconcile(t *testing.T) {
	for _, operation := range []string{"register", "deregister", "reregister", "replace"} {
		t.Run(operation, func(t *testing.T) {
			store := tempStore(t)
			broker := newBrokerForUnit(t, store, time.Now)
			broker.cfg.OpenStream = func(string, string) (run.EventStreamOpener, error) { return nil, nil }
			home := tempHome(t, "existing")
			identity := filepath.Join(home, ".aw")
			writeWakeTestTeamState(t, identity, "team:one")
			reg := Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}
			if err := broker.Register(reg); err != nil {
				t.Fatal(err)
			}

			// A fallback registration not changed by the control must still apply.
			unrelatedHome := tempHome(t, "unrelated")
			unrelatedIdentity := filepath.Join(unrelatedHome, ".aw")
			writeWakeTestTeamState(t, unrelatedIdentity, "team:one")
			if err := store.SaveRegistration(Registration{Home: unrelatedHome, IdentityHome: unrelatedIdentity, Delivery: DeliverySession}); err != nil {
				t.Fatal(err)
			}

			entered, release, reconciled := make(chan struct{}), make(chan struct{}), make(chan struct{})
			original := wakeReadFile
			var blocked atomic.Bool
			wakeReadFile = func(path string) ([]byte, error) {
				data, err := original(path)
				if path == store.registryPath(HomeKey(home)) && blocked.CompareAndSwap(false, true) {
					close(entered)
					<-release
				}
				return data, err
			}
			controlDone := make(chan error, 1)
			var releaseOnce sync.Once
			resume := func() { releaseOnce.Do(func() { close(release) }) }
			controlStarted := false
			defer func() {
				resume()
				<-reconciled
				if controlStarted {
					<-controlDone
				}
				wakeReadFile = original
			}()
			go func() { broker.Reconcile(); close(reconciled) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("reconcile did not reach slow snapshot")
			}

			target := reg
			if operation == "register" {
				target.Home = tempHome(t, "new")
				target.IdentityHome = filepath.Join(target.Home, ".aw")
				writeWakeTestTeamState(t, target.IdentityHome, "team:one")
			}
			if operation == "reregister" {
				target.IdentityHome = filepath.Join(tempHome(t, "replacement-identity"), ".aw")
				writeWakeTestTeamState(t, target.IdentityHome, "team:one")
			}
			if operation == "replace" {
				target.Home = tempHome(t, "new-owner")
			}
			start := time.Now()
			result := make(chan error, 1)
			controlStarted = true
			go func() {
				var err error
				if operation == "deregister" || operation == "replace" {
					_, err = broker.Deregister(home)
				}
				if err == nil && operation != "deregister" {
					err = broker.Register(target)
				}
				result <- err
				controlDone <- err
			}()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s completed in %s while reconcile remained blocked", operation, time.Since(start))
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("%s blocked behind slow reconcile", operation)
			}
			if operation != "deregister" {
				runner, ok := broker.instanceRunner(target.Home)
				if !ok || !runner.allStreamsAdmitted() {
					t.Fatal("new home did not admit its stream before reconcile resumed")
				}
			}
			// Resume the snapshot and prove that its old view cannot undo the control.
			resume()
			<-reconciled
			wantPresent := operation != "deregister"
			if _, present, err := store.LoadRegistration(target.Home); err != nil || present != wantPresent {
				t.Fatalf("durable registration present=%v want=%v err=%v", present, wantPresent, err)
			}
			if _, present := broker.instanceRunner(target.Home); present != wantPresent {
				t.Fatalf("runner present=%v want=%v after stale reconcile", present, wantPresent)
			}
			key, err := bindingKey(target.IdentityHome, "team:one")
			if err != nil {
				t.Fatal(err)
			}
			broker.mu.Lock()
			_, streamPresent := broker.streams[key]
			broker.mu.Unlock()
			if streamPresent != wantPresent {
				t.Fatalf("stream present=%v want=%v", streamPresent, wantPresent)
			}
			if untouched, ok := broker.instanceRunner(unrelatedHome); !ok || !untouched.allStreamsAdmitted() {
				t.Fatal("control mutation prevented unrelated snapshot entry from applying")
			}
			if operation == "reregister" {
				runner, _ := broker.instanceRunner(home)
				if got := runner.registrationSnapshot().IdentityHome; got != target.IdentityHome {
					t.Fatalf("stale snapshot restored identity %s", got)
				}
			}
			if operation == "replace" {
				if _, present := broker.instanceRunner(home); present {
					t.Fatal("old owner resurrected after binding transfer")
				}
			}
			if !wantPresent {
				if _, err := os.Stat(store.instancePath(HomeKey(target.Home))); !os.IsNotExist(err) {
					t.Fatalf("deregistered state resurrected: %v", err)
				}
			}
		})
	}
}

func TestDeferredAdmissionDoesNotReviveRemovedRunner(t *testing.T) {
	store := tempStore(t)
	broker := newBrokerForUnit(t, store, time.Now)
	broker.cfg.OpenStream = func(string, string) (run.EventStreamOpener, error) { return nil, nil }
	home := tempHome(t, "removed")
	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	removed, _ := broker.instanceRunner(home)
	if _, err := broker.Deregister(home); err != nil {
		t.Fatal(err)
	}
	// Simulate the delayed callback from a binding update completing after stop.
	broker.admitCurrentRunnerStreams(removed)
	if streams := broker.Status().Streams; len(streams) != 0 {
		t.Fatalf("removed runner reopened streams: %+v", streams)
	}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	current, _ := broker.instanceRunner(home)
	if current == removed {
		t.Fatal("re-registration reused stopped runner")
	}
	// The old runner must not claim a stream belonging to its replacement.
	removed.mu.Lock()
	removed.admitted = map[string]bool{}
	removed.mu.Unlock()
	broker.admitCurrentRunnerStreams(removed)
	if removed.allStreamsAdmitted() {
		t.Fatal("removed runner admitted against replacement")
	}
	if !current.allStreamsAdmitted() {
		t.Fatal("replacement lost stream admission")
	}
}

func TestRegisterReplacesBindingAtStreamBound(t *testing.T) {
	store := tempStore(t)
	broker := newBrokerForUnit(t, store, time.Now)
	broker.cfg.MaxStreams = 1
	broker.cfg.OpenStream = func(string, string) (run.EventStreamOpener, error) { return nil, nil }
	home := tempHome(t, "terminal")
	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	reg.IdentityHome = filepath.Join(tempHome(t, "replacement"), ".aw")
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	if !runner.allStreamsAdmitted() {
		t.Fatal("binding replacement waited for next reconcile at stream bound")
	}
	streams := broker.Status().Streams
	if len(streams) != 1 || streams[0].IdentityHome != reg.IdentityHome {
		t.Fatalf("replacement streams=%+v", streams)
	}
}

func TestRegisterRefusesBindingStillOwnedByLiveRunner(t *testing.T) {
	store := tempStore(t)
	broker := newBrokerForUnit(t, store, time.Now)
	home := tempHome(t, "existing")
	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	// A file-only removal has not yet stopped the live consumer. A single-home
	// register must not admit a second owner while the next sweep is pending.
	if _, err := store.DeleteRegistration(home); err != nil {
		t.Fatal(err)
	}
	reg.Home = tempHome(t, "new-owner")
	if err := broker.Register(reg); err == nil {
		t.Fatal("admitted a duplicate of a still-running binding")
	}
	if _, err := broker.Deregister(home); err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(reg); err != nil {
		t.Fatalf("binding still refused after old owner stopped: %v", err)
	}
}
