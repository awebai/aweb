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

// Repro for default-aajc.12 against the CURRENT code.
//
// id rotate-key checks that no pending rotation exists and then creates key
// material and pending state, with no lock and no atomic claim. Two processes
// in one worktree can both pass the check, generate DIFFERENT replacement keys,
// and write the same pending-state path — the second silently replacing the
// first. Pending state is keyed only by stable_id and carries no owner, so
// removePendingRotationState deletes whichever operation's record is present.
//
// The unguarded window runs from loadPendingRotationState returning nil to
// savePendingRotationState landing: MkdirAll, keygen, and the keypair write.
// This measures how reachable that window actually is rather than assuming it.
func TestReproConcurrentRotationsClaimTheSameState(t *testing.T) {
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
	currentGate := func() chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		return gate
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
	}
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(_ *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		<-currentGate()
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	const attempts = 4
	doubleClaims := 0
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

		// Let both pass the pending check and write their claim, then count the
		// distinct replacement keys sitting in the pending directory. One
		// rotation must produce exactly one.
		time.Sleep(200 * time.Millisecond)
		keys := pendingRotationKeyCount(t, filepath.Join(dir, ".aw", "rotation", "pending"))

		openGate()
		_ = first.Wait()
		_ = second.Wait()

		if keys > 1 {
			doubleClaims++
			t.Logf("attempt %d: %d replacement keys claimed one rotation", attempt, keys)
		}
	}

	if doubleClaims == 0 {
		t.Logf("no double claim in %d attempts: the check-then-act is unguarded but the window is narrow", attempts)
		return
	}
	t.Errorf("REPRO: %d of %d attempts had two processes claim the same rotation, each with its own replacement key",
		doubleClaims, attempts)
}

func pendingRotationKeyCount(t *testing.T, pendingDir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(pendingDir, "*.signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}
