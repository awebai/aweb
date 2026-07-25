package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// Two rotate-key processes for one stable identity share pending state. Hold the
// first process at the registry so the second process is concurrent; more than
// one pending key proves the pending check and the complete rotation transaction
// are not serialized across processes.
func TestConcurrentRotationsClaimOnlyOneState(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)

	// Hold every rotation PUT open so a process that reaches the registry stays
	// in flight and cannot finish and tidy up while its rival is still running.
	var mu sync.Mutex
	gate := make(chan struct{})
	arrivals := make(chan struct{}, 2)
	currentGate := func() chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		return gate
	}
	currentArrivals := func() chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		return arrivals
	}
	// Opened once per attempt and left open until the next attempt arms it, so a
	// PUT arriving after the release is not trapped behind a fresh gate.
	openGate := func() {
		mu.Lock()
		defer mu.Unlock()
		select {
		case <-gate: // already open
		default:
			close(gate)
		}
	}
	armGate := func() {
		mu.Lock()
		defer mu.Unlock()
		gate = make(chan struct{})
		arrivals = make(chan struct{}, 2)
	}
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(_ *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		currentArrivals() <- struct{}{}
		<-currentGate()
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	const attempts = 4
	invalidClaims := 0
	for attempt := 0; attempt < attempts; attempt++ {
		armGate()
		dir := filepath.Join(tmp, "wt")
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

		start := func() *exec.Cmd {
			cmd := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
			cmd.Env = testCommandEnv(dir)
			cmd.Dir = dir
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			return cmd
		}
		first, second := start(), start()
		wait := func(cmd *exec.Cmd) <-chan error {
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			return done
		}
		firstDone, secondDone := wait(first), wait(second)

		// Wait until one process reaches the registry, then give its rival time
		// to contend for the same transaction. This avoids treating slow process
		// startup as proof that no duplicate claim was made.
		select {
		case <-currentArrivals():
		case <-time.After(5 * time.Second):
			t.Fatal("neither rotation reached the registry")
		}
		time.Sleep(200 * time.Millisecond)

		// Count the distinct replacement keys sitting in the pending directory.
		// One rotation must produce exactly one, and the other process must wait
		// rather than reject the in-flight transaction from outside its lock.
		keys := pendingRotationKeyCount(t, filepath.Join(dir, ".aw", "rotation", "pending"))
		firstFinished := rotationCommandFinished(t, "first", firstDone)
		secondFinished := rotationCommandFinished(t, "second", secondDone)

		openGate()
		if !firstFinished {
			_ = <-firstDone
		}
		if !secondFinished {
			_ = <-secondDone
		}
		_, putCalls := fixture.snapshot()
		if want := (attempt + 1) * 2; putCalls != want {
			t.Errorf("attempt %d: registry rotation calls=%d, want %d after serialized cleanup", attempt, putCalls, want)
		}

		if keys != 1 {
			invalidClaims++
			t.Logf("attempt %d: %d replacement keys claimed one rotation", attempt, keys)
		}
	}

	if invalidClaims != 0 {
		t.Errorf("%d of %d attempts did not have exactly one process claim the rotation", invalidClaims, attempts)
	}
}

func rotationCommandFinished(t *testing.T, name string, done <-chan error) bool {
	t.Helper()
	select {
	case err := <-done:
		t.Errorf("%s rotation exited before the active transaction completed: %v", name, err)
		return true
	default:
		return false
	}
}

func pendingRotationKeyCount(t *testing.T, pendingDir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(pendingDir, "*.signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}
