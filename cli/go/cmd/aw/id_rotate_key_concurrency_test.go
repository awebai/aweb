package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
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
			openGate()
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

func TestConcurrentRotationReloadsWinnerStateBeforeNextTransaction(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)

	arrived := make(chan struct{}, 1)
	gate := make(chan struct{})
	type secondTransactionState struct {
		winnerDID string
		oldDID    string
	}
	secondState := make(chan secondTransactionState, 1)
	rotationDir := ""
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(f *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		if f.putCalls == 1 {
			arrived <- struct{}{}
			<-gate
			f.currentDID = f.proposedDID
			w.WriteHeader(http.StatusOK)
			return
		}
		state := secondTransactionState{winnerDID: f.currentDID}
		pending, err := loadPendingRotationState(rotationDir, stableID)
		if err != nil {
			f.t.Error(err)
		} else if pending == nil {
			f.t.Error("second registry PUT has no pending rotation state")
		} else {
			state.oldDID = pending.OldDID
		}
		secondState <- state
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	dir := filepath.Join(tmp, "wt")
	rotationDir = filepath.Join(dir, ".aw", "rotation")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

	first := startRotationCommand(t, ctx, bin, dir)
	second := startRotationCommand(t, ctx, bin, dir)

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		close(gate)
		t.Fatal("neither rotation reached the registry")
	}
	time.Sleep(200 * time.Millisecond)
	firstFinished := rotationCommandFinished(t, "first", first.done)
	secondFinished := rotationCommandFinished(t, "second", second.done)
	close(gate)

	var firstErr, secondErr error
	if !firstFinished {
		firstErr = <-first.done
	}
	if !secondFinished {
		secondErr = <-second.done
	}
	if (firstErr == nil) == (secondErr == nil) {
		t.Fatalf("rotation errors=(%v, %v), want one applied rotation and one clean conflict\nfirst:\n%s\nsecond:\n%s", firstErr, secondErr, first.output, second.output)
	}
	_, putCalls := fixture.snapshot()
	if putCalls != 2 {
		t.Errorf("registry rotation calls=%d, want 2 after the waiter reloads the winner state", putCalls)
	}
	select {
	case state := <-secondState:
		if state.oldDID != state.winnerDID {
			t.Errorf("second transaction old_did=%q, want winner did %q", state.oldDID, state.winnerDID)
		}
	case <-time.After(time.Second):
		t.Error("second transaction did not reach the registry with pending state")
	}

	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Errorf("pending state retained after serialized success and conflict: %+v", pending)
	}
	if keys := pendingRotationKeyCount(t, filepath.Join(rotationDir, "pending")); keys != 0 {
		t.Errorf("pending replacement keys=%d, want 0 after serialized cleanup", keys)
	}
}

func TestConcurrentRotationRefusesIdentityChangedWhileWaiting(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	otherPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherStableID := awid.ComputeStableID(otherPublic)

	arrived := make(chan struct{}, 1)
	gate := make(chan struct{})
	var serverMu sync.Mutex
	oldPutCalls := 0
	otherIdentityRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": stableID, "current_did_key": oldDID,
				"created_at": "2026-07-24T00:00:00Z", "updated_at": "2026-07-24T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": stableID, "current_did_key": oldDID,
				"log_head": map[string]any{
					"seq": 1, "operation": "register_did", "new_did_key": oldDID,
					"entry_hash": strings.Repeat("a", 64), "state_hash": strings.Repeat("b", 64),
					"authorized_by": oldDID, "signature": "test", "timestamp": "2026-07-24T00:00:00Z",
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/did/"+stableID:
			serverMu.Lock()
			oldPutCalls++
			serverMu.Unlock()
			arrived <- struct{}{}
			<-gate
			http.Error(w, "rotation rejected", http.StatusConflict)
		case strings.HasPrefix(r.URL.Path, "/v1/did/"+otherStableID):
			serverMu.Lock()
			otherIdentityRequests++
			serverMu.Unlock()
			http.Error(w, "changed identity unavailable", http.StatusInternalServerError)
		default:
			t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	dir := filepath.Join(tmp, "wt")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, server.URL, oldPrivate)

	first := startRotationCommand(t, ctx, bin, dir)
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		close(gate)
		t.Fatal("first rotation did not reach the registry")
	}
	waiter := startRotationCommand(t, ctx, bin, dir)
	time.Sleep(200 * time.Millisecond)
	firstFinished := rotationCommandFinished(t, "first", first.done)
	waiterFinished := rotationCommandFinished(t, "waiting", waiter.done)

	identity := loadIdentityForTest(t, dir)
	identity.StableID = otherStableID
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(dir, ".aw", "identity.yaml"), identity); err != nil {
		close(gate)
		t.Fatal(err)
	}
	close(gate)

	var firstErr, waiterErr error
	if !firstFinished {
		firstErr = <-first.done
	}
	if !waiterFinished {
		waiterErr = <-waiter.done
	}
	if firstErr == nil || waiterErr == nil {
		t.Fatalf("rotation errors=(%v, %v), want both commands to refuse\nfirst:\n%s\nwaiter:\n%s", firstErr, waiterErr, first.output, waiter.output)
	}
	if !strings.Contains(waiter.output.String(), "active identity changed while waiting for the rotation lock") {
		t.Errorf("waiter did not report changed lock scope:\n%s", waiter.output)
	}
	serverMu.Lock()
	gotOldPutCalls, gotOtherRequests := oldPutCalls, otherIdentityRequests
	serverMu.Unlock()
	if gotOldPutCalls != 1 {
		t.Errorf("old identity rotation calls=%d, want 1", gotOldPutCalls)
	}
	if gotOtherRequests != 0 {
		t.Errorf("changed identity registry requests=%d, want 0 outside its lock", gotOtherRequests)
	}

	rotationDir := filepath.Join(dir, ".aw", "rotation")
	for _, id := range []string{stableID, otherStableID} {
		if pending, err := loadPendingRotationState(rotationDir, id); err != nil {
			t.Fatal(err)
		} else if pending != nil {
			t.Errorf("pending state retained for %s: %+v", id, pending)
		}
	}
	if keys := pendingRotationKeyCount(t, filepath.Join(rotationDir, "pending")); keys != 0 {
		t.Errorf("pending replacement keys=%d, want 0 after scope refusal", keys)
	}
}

func TestConcurrentWaiterRecoversAppliedRotationAfterLostResponse(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	thirdPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	thirdDID := awid.ComputeDIDKey(thirdPublic)
	stableID := awid.ComputeStableID(oldPublic)

	putArrived := make(chan struct{})
	releasePut := make(chan struct{})
	allowRecovery := make(chan struct{})
	var mu sync.Mutex
	committedDID := ""
	putCalls := 0
	postPutKeyReads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		committed := committedDID
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/full":
			current := oldDID
			if committed != "" {
				current = committed
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": stableID, "current_did_key": current,
				"created_at": "2026-07-24T00:00:00Z", "updated_at": "2026-07-24T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+stableID+"/key":
			mu.Lock()
			if committedDID != "" {
				postPutKeyReads++
			}
			readNumber := postPutKeyReads
			current := committedDID
			mu.Unlock()
			if readNumber == 1 {
				// The first process has lost the successful response and cannot
				// establish the authoritative outcome, so it must preserve state.
				current = thirdDID
			} else if readNumber > 1 {
				<-allowRecovery
			}
			if current == "" {
				current = oldDID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw": stableID, "current_did_key": current,
				"log_head": map[string]any{
					"seq": 1, "operation": "register_did", "new_did_key": oldDID,
					"entry_hash": strings.Repeat("a", 64), "state_hash": strings.Repeat("b", 64),
					"authorized_by": oldDID, "signature": "test", "timestamp": "2026-07-24T00:00:00Z",
				},
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/did/"+stableID:
			var request map[string]any
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Error(err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			mu.Lock()
			putCalls++
			call := putCalls
			if call == 1 {
				committedDID, _ = request["new_did_key"].(string)
			}
			mu.Unlock()
			if call != 1 {
				http.Error(w, "rotation definitely not applied", http.StatusConflict)
				return
			}
			close(putArrived)
			<-releasePut
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		default:
			t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, server.URL, oldPrivate)

	first := startRotationCommand(t, ctx, bin, dir)
	select {
	case <-putArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("first rotation did not reach the registry")
	}
	waiter := startRotationCommand(t, ctx, bin, dir)
	time.Sleep(200 * time.Millisecond)
	close(releasePut)
	firstErr := <-first.done
	if firstErr == nil || !strings.Contains(first.output.String(), "outcome unknown") {
		t.Fatalf("first rotation error=%v, want preserved unknown outcome\n%s", firstErr, first.output)
	}
	close(allowRecovery)
	if waiterErr := <-waiter.done; waiterErr != nil {
		t.Fatalf("waiting rotation did not recover the committed operation: %v\n%s", waiterErr, waiter.output)
	}
	for _, want := range []string{"\"status\": \"finalized\"", "\"rerun_required\": true"} {
		if !strings.Contains(waiter.output.String(), want) {
			t.Fatalf("waiter output missing %q:\n%s", want, waiter.output)
		}
	}
	mu.Lock()
	gotCommitted, gotPutCalls := committedDID, putCalls
	mu.Unlock()
	if gotPutCalls != 1 {
		t.Fatalf("rotation PUT calls=%d, want only the applied first operation", gotPutCalls)
	}
	identity := loadIdentityForTest(t, dir)
	if identity.DID != gotCommitted {
		t.Fatalf("local identity did=%q, want recovered registry key %q", identity.DID, gotCommitted)
	}
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Fatalf("pending state remains after waiter recovery: %+v", pending)
	}
}

type runningRotationCommand struct {
	done   <-chan error
	output *bytes.Buffer
}

func startRotationCommand(t *testing.T, ctx context.Context, bin, dir string) runningRotationCommand {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	cmd.Env = testCommandEnv(dir)
	cmd.Dir = dir
	output := new(bytes.Buffer)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return runningRotationCommand{done: done, output: output}
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
