package main

import (
	"context"
	"crypto/ed25519"
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

type cliRotationRegistryFixture struct {
	t           *testing.T
	server      *httptest.Server
	stableID    string
	oldDID      string
	mu          sync.Mutex
	currentDID  string
	proposedDID string
	putCalls    int
	onPut       func(*cliRotationRegistryFixture, http.ResponseWriter, map[string]any)
}

func newCLIRotationRegistryFixture(
	t *testing.T,
	stableID string,
	oldDID string,
	onPut func(*cliRotationRegistryFixture, http.ResponseWriter, map[string]any),
) *cliRotationRegistryFixture {
	t.Helper()
	fixture := &cliRotationRegistryFixture{t: t, stableID: stableID, oldDID: oldDID, currentDID: oldDID, onPut: onPut}
	fixture.server = httptest.NewServer(http.HandlerFunc(fixture.handle))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (f *cliRotationRegistryFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+f.stableID+"/full":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did_aw":          f.stableID,
			"current_did_key": f.currentDID,
			"created_at":      "2026-07-24T00:00:00Z",
			"updated_at":      "2026-07-24T00:00:00Z",
		})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+f.stableID+"/key":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did_aw":          f.stableID,
			"current_did_key": f.currentDID,
			"log_head": map[string]any{
				"seq":           1,
				"operation":     "register_did",
				"new_did_key":   f.oldDID,
				"entry_hash":    strings.Repeat("a", 64),
				"state_hash":    strings.Repeat("b", 64),
				"authorized_by": f.oldDID,
				"signature":     "test",
				"timestamp":     "2026-07-24T00:00:00Z",
			},
		})
	case r.Method == http.MethodPut && r.URL.Path == "/v1/did/"+f.stableID:
		f.putCalls++
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.proposedDID, _ = request["new_did_key"].(string)
		f.onPut(f, w, request)
	default:
		f.t.Errorf("unexpected registry request: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}
}

func (f *cliRotationRegistryFixture) dropResponse(w http.ResponseWriter) {
	connection, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		f.t.Error(err)
		return
	}
	_ = connection.Close()
}

func (f *cliRotationRegistryFixture) snapshot() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proposedDID, f.putCalls
}

func runRotateKeyCommand(ctx context.Context, bin, dir string) ([]byte, error) {
	run := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	run.Env = testCommandEnv(dir)
	run.Dir = dir
	return run.CombinedOutput()
}

func TestAwIDRotateKeyFinalizesAppliedRotationAfterResponseDrop(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(f *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		if f.putCalls == 1 {
			f.currentDID = f.proposedDID
			f.dropResponse(w)
			return
		}
		http.Error(w, "rotation sequence conflict", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

	out, err := runRotateKeyCommand(ctx, bin, tmp)
	if err != nil {
		t.Fatalf("id rotate-key failed after committed response drop: %v\n%s", err, out)
	}
	proposedDID, putCalls := fixture.snapshot()
	if putCalls != 1 {
		t.Fatalf("rotation PUT calls=%d, want 1", putCalls)
	}
	identity := loadIdentityForTest(t, tmp)
	if identity.DID != proposedDID {
		t.Fatalf("identity did=%q, want applied replacement %q", identity.DID, proposedDID)
	}
	activeKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(activeKey.Public().(ed25519.PublicKey)); got != proposedDID {
		t.Fatalf("active key did=%q, want applied replacement %q", got, proposedDID)
	}
	if pending, err := loadPendingRotationState(filepath.Join(tmp, ".aw", "rotation"), stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Fatalf("pending state still present after reconciled success: %+v", pending)
	}
}

func TestAwIDRotateKeyDiscardsPendingKeyOnlyWhenRegistryProvesNotApplied(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(_ *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

	out, err := runRotateKeyCommand(ctx, bin, tmp)
	if err == nil {
		t.Fatalf("expected definitely-not-applied error\n%s", out)
	}
	if !strings.Contains(string(out), "definitely not applied") {
		t.Fatalf("unexpected error output:\n%s", out)
	}
	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Fatalf("pending state retained after definitely-not-applied outcome: %+v", pending)
	}
	proposedDID, _ := fixture.snapshot()
	privatePath, publicPath := pendingRotationKeyPaths(rotationDir, proposedDID)
	for _, path := range []string{privatePath, publicPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unused pending key material was not discarded at %s: %v", path, err)
		}
	}
}

func TestAwIDRotateKeyPreservesPendingKeyWhenRegistryOutcomeIsUnknown(t *testing.T) {
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(f *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		if f.putCalls == 1 {
			f.dropResponse(w)
			return
		}
		http.Error(w, "rotation rejected", http.StatusConflict)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, tmp, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

	out, err := runRotateKeyCommand(ctx, bin, tmp)
	if err == nil {
		t.Fatalf("expected outcome-unknown error\n%s", out)
	}

	rotationDir := filepath.Join(tmp, ".aw", "rotation")
	statePath := pendingRotationStatePath(rotationDir, stableID)
	for _, want := range []string{"outcome unknown", "replacement signing key retained", statePath} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("error output missing %q:\n%s", want, out)
		}
	}
	pending, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("pending rotation state was deleted after an ambiguous outcome")
	}
	proposedDID, _ := fixture.snapshot()
	if pending.NewDID != proposedDID {
		t.Fatalf("pending new_did=%q, want %q", pending.NewDID, proposedDID)
	}
	if _, err := os.Stat(pending.PendingKey); err != nil {
		t.Fatalf("pending replacement private key was not preserved: %v", err)
	}
	if _, err := os.Stat(awid.PublicKeyPath(pending.PendingKey)); err != nil {
		t.Fatalf("pending replacement public key was not preserved: %v", err)
	}
	activeKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(tmp))
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(activeKey.Public().(ed25519.PublicKey)); got != oldDID {
		t.Fatalf("active key changed to %q after unknown outcome, want old key %q", got, oldDID)
	}

	// A fresh process must see the same recovery state and must not submit a new rotation.
	restartOut, restartErr := runRotateKeyCommand(ctx, bin, tmp)
	if restartErr == nil {
		t.Fatalf("expected pending-rotation refusal after restart\n%s", restartOut)
	}
	if !strings.Contains(string(restartOut), statePath) {
		t.Fatalf("restart error missing recovery state path:\n%s", restartOut)
	}
	_, putCalls := fixture.snapshot()
	if putCalls != 2 {
		t.Fatalf("rotation PUT calls=%d, want 2 across process restart", putCalls)
	}
}
