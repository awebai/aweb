package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestPendingRotationStateCannotBeOverwrittenOrRemovedByAnotherOperation(t *testing.T) {
	rotationDir := filepath.Join(t.TempDir(), "rotation")
	first := &pendingRotationState{
		OperationID: "11111111-1111-4111-8111-111111111111",
		StableID:    "did:aw:first",
		OldDID:      "did:key:old",
		NewDID:      "did:key:new",
		PendingKey:  filepath.Join(rotationDir, "pending", "first.signing.key"),
	}
	if err := savePendingRotationState(rotationDir, first); err != nil {
		t.Fatal(err)
	}
	second := *first
	second.OperationID = "22222222-2222-4222-8222-222222222222"
	if err := savePendingRotationState(rotationDir, &second); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error=%v, want existing-operation refusal", err)
	}
	if err := removePendingRotationStateOwned(rotationDir, first.StableID, second.OperationID); err == nil || !strings.Contains(err.Error(), "owned by operation") {
		t.Fatalf("foreign removal error=%v, want ownership refusal", err)
	}
	got, err := loadPendingRotationState(rotationDir, first.StableID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.OperationID != first.OperationID {
		t.Fatalf("pending state after foreign operations=%+v, want first operation", got)
	}
}

func TestAwIDRotateKeyRecoverReconcilesAuthoritativeState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	for _, tc := range []struct {
		name          string
		registryState string
		wantStatus    string
		wantPending   bool
		wantActiveNew bool
	}{
		{name: "applied", registryState: "new", wantStatus: "finalized", wantActiveNew: true},
		{name: "not applied", registryState: "old", wantStatus: "rolled_back"},
		{name: "unexpected key", registryState: "third", wantStatus: "unknown_preserved", wantPending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldPub, oldPriv, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			newPub, newPriv, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			thirdPub, _, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			oldDID := awid.ComputeDIDKey(oldPub)
			newDID := awid.ComputeDIDKey(newPub)
			stableID := awid.ComputeStableID(oldPub)
			current := map[string]string{"old": oldDID, "new": newDID, "third": awid.ComputeDIDKey(thirdPub)}[tc.registryState]
			fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(_ *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
				t.Error("recover submitted a new rotation")
				http.Error(w, "unexpected", http.StatusInternalServerError)
			})
			fixture.currentDID = current

			dir := filepath.Join(tmp, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPriv)
			operationID := "11111111-1111-4111-8111-111111111111"
			rotationDir := filepath.Join(dir, ".aw", "rotation")
			pendingKey, err := savePendingRotationKeypair(rotationDir, operationID, newPub, newPriv)
			if err != nil {
				t.Fatal(err)
			}
			if err := savePendingRotationState(rotationDir, &pendingRotationState{
				OperationID: operationID,
				StableID:    stableID, OldDID: oldDID, NewDID: newDID,
				RegistryURL: fixture.server.URL, PendingKey: pendingKey,
			}); err != nil {
				t.Fatal(err)
			}

			out := runRotationRecoveryCommand(t, ctx, bin, dir, "recover")
			if out.Status != tc.wantStatus {
				t.Fatalf("recover status=%q, want %q", out.Status, tc.wantStatus)
			}
			pending, err := loadPendingRotationState(rotationDir, stableID)
			if err != nil {
				t.Fatal(err)
			}
			if (pending != nil) != tc.wantPending {
				t.Fatalf("pending=%+v, want present=%v", pending, tc.wantPending)
			}
			active, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			gotActive := awid.ComputeDIDKey(active.Public().(ed25519.PublicKey))
			wantActive := oldDID
			if tc.wantActiveNew {
				wantActive = newDID
			}
			if gotActive != wantActive {
				t.Fatalf("active did=%q, want %q", gotActive, wantActive)
			}
			if !tc.wantPending {
				repeated := runRotationRecoveryCommand(t, ctx, bin, dir, "recover")
				if repeated.Status != "no_pending" {
					t.Fatalf("repeated recover status=%q, want no_pending", repeated.Status)
				}
			}
		})
	}
}

func TestAwIDRotateKeyWithPendingStateRecoversAndRequiresRerun(t *testing.T) {
	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	newDID := awid.ComputeDIDKey(newPub)
	stableID := awid.ComputeStableID(oldPub)
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(_ *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		t.Error("plain rotate submitted a new operation after recovery")
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	fixture.currentDID = newDID

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPriv)
	operationID := "11111111-1111-4111-8111-111111111111"
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	pendingKey, err := savePendingRotationKeypair(rotationDir, operationID, newPub, newPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePendingRotationState(rotationDir, &pendingRotationState{
		OperationID: operationID, StableID: stableID, OldDID: oldDID, NewDID: newDID,
		RegistryURL: fixture.server.URL, PendingKey: pendingKey,
	}); err != nil {
		t.Fatal(err)
	}

	out := runRotationRecoveryCommand(t, ctx, bin, dir)
	if out.Status != "finalized" || !out.RerunRequired {
		t.Fatalf("plain rotate recovery=%+v, want finalized with rerun required", out)
	}
	if _, calls := fixture.snapshot(); calls != 0 {
		t.Fatalf("rotation PUT calls=%d, want 0", calls)
	}
}

func TestAwIDRotateKeyStatusIsReadOnlyAndDistinguishesActiveOperation(t *testing.T) {
	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, "https://registry.invalid", oldPriv)
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	lockPath := pendingRotationStatePath(rotationDir, stableID) + ".lock"
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("fresh rotation lock unexpectedly exists: %v", err)
	}
	out := runRotationRecoveryCommand(t, ctx, bin, dir, "status")
	if out.Status != "no_pending" {
		t.Fatalf("fresh status=%q, want no_pending", out.Status)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("read-only status created a lock file: %v", err)
	}

	lock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	// Leave enough budget for process startup under the package's parallel CLI
	// tests; a blocking lock mutation still times out because the holder is only
	// released after this subprocess returns.
	statusCtx, statusCancel := context.WithTimeout(ctx, 15*time.Second)
	defer statusCancel()
	out = runRotationRecoveryCommand(t, statusCtx, bin, dir, "status")
	if out.Status != "operation_in_progress" {
		t.Fatalf("locked status=%q, want operation_in_progress", out.Status)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	out = runRotationRecoveryCommand(t, ctx, bin, dir, "status")
	if out.Status != "no_pending" {
		t.Fatalf("unlocked status=%q, want no_pending", out.Status)
	}
}

func TestAwIDRotateKeyStatusRejectsCorruptStateWithoutChangingIt(t *testing.T) {
	oldPub, oldPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPub)
	stableID := awid.ComputeStableID(oldPub)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, "https://registry.invalid", oldPriv)
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	statePath := pendingRotationStatePath(rotationDir, stableID)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("operation_id: [partial")
	if err := os.WriteFile(statePath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, bin, "id", "rotate-key", "status", "--json")
	cmd.Env = testCommandEnv(dir)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "decode pending rotation state") {
		t.Fatalf("corrupt-state status error=%v\n%s", err, out)
	}
	got, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(corrupt) {
		t.Fatalf("status changed corrupt state: %q", got)
	}
}

func runRotationRecoveryCommand(t *testing.T, ctx context.Context, bin, dir string, action ...string) idRotationRecoveryOutput {
	t.Helper()
	args := []string{"id", "rotate-key"}
	args = append(args, action...)
	args = append(args, "--json")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = testCommandEnv(dir)
	cmd.Dir = dir
	data, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw %s failed: %v\n%s", strings.Join(args, " "), err, data)
	}
	var out idRotationRecoveryOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode recovery output: %v\n%s", err, data)
	}
	return out
}
