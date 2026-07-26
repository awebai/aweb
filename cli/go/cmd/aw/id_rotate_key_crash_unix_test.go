//go:build !windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const rotationCrashTestProtocol = "aweb-internal-rotation-crash-test-v1"

type rotationCrashRegistryMode string

const (
	rotationRegistrySuccess      rotationCrashRegistryMode = "success"
	rotationRegistryReject       rotationCrashRegistryMode = "reject"
	rotationRegistryBlockOld     rotationCrashRegistryMode = "block-old"
	rotationRegistryBlockApplied rotationCrashRegistryMode = "block-applied"
)

type rotationCrashCase struct {
	name                 string
	point                string
	pathContains         string
	registryMode         rotationCrashRegistryMode
	wantRecovery         string
	wantState            bool
	wantPendingPrivate   bool
	wantPendingPublic    bool
	wantActivePrivateNew bool
	wantActivePublicNew  bool
	wantIdentityNew      bool
	wantArchivePrivate   bool
	wantArchivePublic    bool
	wantRegistryNew      bool
	mustPreserveNew      bool
}

type rotationCrashRegistryState struct {
	mu      sync.Mutex
	mode    rotationCrashRegistryMode
	ready   chan struct{}
	release chan struct{}
	applied int
}

func (s *rotationCrashRegistryState) currentMode() rotationCrashRegistryMode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

func (s *rotationCrashRegistryState) setMode(mode rotationCrashRegistryMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
}

func (s *rotationCrashRegistryState) recordApply() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied++
}

func (s *rotationCrashRegistryState) appliedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

func TestAwIDRotationCrashMatrixRecoversConsistently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	cases := []rotationCrashCase{
		{name: "A no committed operation state", point: "after-key-generation", registryMode: rotationRegistrySuccess, wantRecovery: "no_pending"},
		{name: "B ownership state only", point: "after-pending-state-commit", registryMode: rotationRegistrySuccess, wantRecovery: "rolled_back", wantState: true},
		{name: "C ownership state and private key", point: "after-keypair-private-commit", pathContains: "/rotation/pending/", registryMode: rotationRegistrySuccess, wantRecovery: "rolled_back", wantState: true, wantPendingPrivate: true},
		{name: "D complete pending key pair before request", point: "after-keypair-public-commit", pathContains: "/rotation/pending/", registryMode: rotationRegistrySuccess, wantRecovery: "rolled_back", wantState: true, wantPendingPrivate: true, wantPendingPublic: true},
		{name: "E request in flight registry old", registryMode: rotationRegistryBlockOld, wantRecovery: "rolled_back", wantState: true, wantPendingPrivate: true, wantPendingPublic: true, mustPreserveNew: true},
		{name: "F request applied response withheld", registryMode: rotationRegistryBlockApplied, wantRecovery: "finalized", wantState: true, wantPendingPrivate: true, wantPendingPublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "G1 archived private only", point: "after-keypair-private-commit", pathContains: "/rotated/", registryMode: rotationRegistrySuccess, wantRecovery: "finalized", wantState: true, wantPendingPrivate: true, wantPendingPublic: true, wantArchivePrivate: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "G2 complete archived pair", point: "after-keypair-public-commit", pathContains: "/rotated/", registryMode: rotationRegistrySuccess, wantRecovery: "finalized", wantState: true, wantPendingPrivate: true, wantPendingPublic: true, wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "H split active key pair", point: "after-active-private-rename", registryMode: rotationRegistrySuccess, wantRecovery: "finalized", wantState: true, wantPendingPublic: true, wantActivePrivateNew: true, wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "I active pair with old identity", point: "after-active-public-rename", registryMode: rotationRegistrySuccess, wantRecovery: "finalized", wantState: true, wantActivePrivateNew: true, wantActivePublicNew: true, wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "J active pair and identity with pending state", point: "after-identity-state-commit", registryMode: rotationRegistrySuccess, wantRecovery: "finalized", wantState: true, wantActivePrivateNew: true, wantActivePublicNew: true, wantIdentityNew: true, wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "K applied operation complete", point: "after-pending-state-removal", registryMode: rotationRegistrySuccess, wantRecovery: "no_pending", wantActivePrivateNew: true, wantActivePublicNew: true, wantIdentityNew: true, wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true, mustPreserveNew: true},
		{name: "L rollback private removed", point: "after-pending-private-removal", pathContains: "/rotation/pending/", registryMode: rotationRegistryReject, wantRecovery: "rolled_back", wantState: true, wantPendingPublic: true},
		{name: "M rollback key pair removed", point: "after-pending-public-removal", pathContains: "/rotation/pending/", registryMode: rotationRegistryReject, wantRecovery: "rolled_back", wantState: true},
		{name: "N rollback complete", point: "after-pending-state-removal", registryMode: rotationRegistryReject, wantRecovery: "no_pending"},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			runRotationCrashCase(t, ctx, bin, root, testCase)
		})
	}
}

func TestAwIDRotationRecoveryRepairsPublicKeyBeforePendingPublicCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture, registryState := newRotationCrashRegistry(t, stableID, oldDID, rotationRegistrySuccess)
	dir := filepath.Join(root, "split-recovery-crash")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)
	foreign := seedForeignRotationOperation(t, dir)

	killRotationAtCheckpoint(t, ctx, bin, dir, "after-active-private-rename", "")
	assertRotationCrashState(t, dir, stableID, oldDID, fixture, rotationCrashCase{
		wantState: true, wantPendingPublic: true, wantActivePrivateNew: true,
		wantArchivePrivate: true, wantArchivePublic: true, wantRegistryNew: true,
	})
	activePath := awconfig.WorktreeSigningKeyPath(dir)
	activePrivate, err := awid.LoadSigningKey(activePath)
	if err != nil {
		t.Fatal(err)
	}
	activeTemp := filepath.Join(filepath.Dir(activePath), ".tmp.owned-active-rotation")
	if err := awid.SaveSigningKey(activeTemp, activePrivate); err != nil {
		t.Fatal(err)
	}
	archivePrivate, _ := archivedRotationKeyPaths(activePath, oldDID)
	archiveOldPrivate, err := awid.LoadSigningKey(archivePrivate)
	if err != nil {
		t.Fatal(err)
	}
	archiveTemp := filepath.Join(filepath.Dir(archivePrivate), ".tmp.owned-archive-rotation")
	if err := awid.SaveSigningKey(archiveTemp, archiveOldPrivate); err != nil {
		t.Fatal(err)
	}
	activeTempBytes := readFileForCrashTest(t, activeTemp)
	archiveTempBytes := readFileForCrashTest(t, archiveTemp)
	if got, want := pathSigningKeyDID(activeTemp), crashRegistryProposedDID(fixture); got != want {
		t.Fatalf("promoted-key temp did=%q, want operation new DID %q", got, want)
	}
	if got := pathSigningKeyDID(archiveTemp); got != oldDID {
		t.Fatalf("archived-key temp did=%q, want operation old DID %q", got, oldDID)
	}

	killRotationCommandAtCheckpoint(t, ctx, bin, dir, "after-pending-public-removal", "/rotation/pending/", "recover")

	rotationDir := filepath.Join(dir, ".aw", "rotation")
	pending, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("recovery removed operation state before the public-cleanup checkpoint")
	}
	assertCrashPathExists(t, pending.PendingKey, false)
	assertCrashPathExists(t, awid.PublicKeyPath(pending.PendingKey), false)
	assertSigningKeyDID(t, activePath, pending.NewDID)
	assertPublicKeyDID(t, awid.PublicKeyPath(activePath), pending.NewDID)
	if got := readFileForCrashTest(t, activeTemp); !bytes.Equal(got, activeTempBytes) {
		t.Fatal("recovery changed promoted-key temp before its cleanup phase")
	}
	if got := readFileForCrashTest(t, archiveTemp); !bytes.Equal(got, archiveTempBytes) {
		t.Fatal("recovery changed archived-key temp before its cleanup phase")
	}
	if identity := loadIdentityForTest(t, dir); identity.DID != pending.NewDID {
		t.Fatalf("identity did=%q, want %q", identity.DID, pending.NewDID)
	}
	assertForeignRotationOperation(t, foreign)

	recovered := runRotationRecoveryCommand(t, ctx, bin, dir, "recover")
	if recovered.Status != "finalized" {
		t.Fatalf("second recovery status=%q, want finalized", recovered.Status)
	}
	assertCompletedRotation(t, dir, stableID, oldDID, fixture, registryState, foreign)
	assertCrashPathExists(t, activeTemp, false)
	assertCrashPathExists(t, archiveTemp, false)
}

func TestAwIDRotationRecoveryRemovesOwnedPrivateKeyTempResidue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture, registryState := newRotationCrashRegistry(t, stableID, oldDID, rotationRegistrySuccess)
	dir := filepath.Join(root, "private-temp-residue")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)
	foreign := seedForeignRotationOperation(t, dir)

	killRotationAtCheckpoint(t, ctx, bin, dir, "after-private-key-temp-sync", "/rotation/pending/")
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	pending, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if pending == nil {
		t.Fatal("private-key write crash did not retain owned operation state")
	}
	matches, err := filepath.Glob(filepath.Join(rotationDir, "pending", ".tmp.*"))
	if err != nil {
		t.Fatal(err)
	}
	var ownedTemp string
	for _, match := range matches {
		if match != foreign.tempPath {
			if ownedTemp != "" {
				t.Fatalf("multiple rotation-owned private-key temps: %s and %s", ownedTemp, match)
			}
			ownedTemp = match
		}
	}
	if ownedTemp == "" {
		t.Fatal("SIGKILL did not leave the representative private-key temp residue")
	}
	if got := pathSigningKeyDID(ownedTemp); got != pending.NewDID {
		t.Fatalf("orphan temp private key did=%q, want operation new DID %q", got, pending.NewDID)
	}
	assertForeignRotationOperation(t, foreign)

	recovered := runRotationRecoveryCommand(t, ctx, bin, dir, "recover")
	if recovered.Status != "rolled_back" {
		t.Fatalf("temp-residue recovery status=%q, want rolled_back", recovered.Status)
	}
	assertNoOwnedRotationFiles(t, rotationDir, foreign)
	assertForeignRotationOperation(t, foreign)
	out, err := runRotateKeyCommand(ctx, bin, dir)
	if err != nil {
		t.Fatalf("rotation after temp-residue recovery failed: %v\n%s", err, out)
	}
	assertCompletedRotation(t, dir, stableID, oldDID, fixture, registryState, foreign)
}

func TestAwIDRotationCrashCheckpointIsInertWithoutCompleteCapability(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)

	cases := []struct {
		name      string
		unset     string
		overrides map[string]string
	}{
		{name: "missing protocol", unset: "AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL"},
		{name: "wrong protocol", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL": "wrong-version"}},
		{name: "wrong checkpoint", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_POINT": "not-a-checkpoint"}},
		{name: "missing ready fd", unset: "AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD"},
		{name: "malformed ready fd", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD": "not-a-fd"}},
		{name: "non-inherited ready fd", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD": "2"}},
		{name: "missing control fd", unset: "AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD"},
		{name: "malformed control fd", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD": "not-a-fd"}},
		{name: "non-inherited control fd", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD": "2"}},
		{name: "same descriptors", overrides: map[string]string{"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD": "3"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			oldPublic, oldPrivate, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			oldDID := awid.ComputeDIDKey(oldPublic)
			stableID := awid.ComputeStableID(oldPublic)
			fixture, registryState := newRotationCrashRegistry(t, stableID, oldDID, rotationRegistrySuccess)
			dir := filepath.Join(root, strings.ReplaceAll(testCase.name, " ", "-"))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)

			readyReader, readyWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			controlReader, controlWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyReader.Close()
			defer controlWriter.Close()
			cmd := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
			cmd.Dir = dir
			cmd.ExtraFiles = []*os.File{readyWriter, controlReader}
			capability := map[string]string{
				"AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL":   rotationCrashTestProtocol,
				"AWEB_INTERNAL_ROTATION_CRASH_TEST_POINT":      "after-key-generation",
				"AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD":   "3",
				"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD": "4",
			}
			delete(capability, testCase.unset)
			for key, value := range testCase.overrides {
				capability[key] = value
			}
			cmd.Env = rotationCrashCapabilityEnv(testCommandEnv(dir), capability)
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = readyWriter.Close()
			_ = controlReader.Close()
			if err := readyReader.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var marker [1]byte
			count, readErr := readyReader.Read(marker[:])
			if count != 0 || readErr != io.EOF {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatalf("incomplete checkpoint capability wrote or blocked: count=%d err=%v", count, readErr)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("rotation with incomplete checkpoint capability failed: %v\n%s", err, output.String())
			}
			assertCompletedRotation(t, dir, stableID, oldDID, fixture, registryState, nil)
		})
	}
}

func rotationCrashCapabilityEnv(base []string, capability map[string]string) []string {
	keys := map[string]bool{
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL":      true,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_POINT":         true,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD":      true,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD":    true,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_PATH_CONTAINS": true,
	}
	env := make([]string, 0, len(base)+len(capability))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !keys[key] {
			env = append(env, entry)
		}
	}
	for key, value := range capability {
		env = append(env, key+"="+value)
	}
	return env
}

func runRotationCrashCase(t *testing.T, ctx context.Context, bin, root string, testCase rotationCrashCase) {
	t.Helper()
	oldPublic, oldPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldDID := awid.ComputeDIDKey(oldPublic)
	stableID := awid.ComputeStableID(oldPublic)
	fixture, registryState := newRotationCrashRegistry(t, stableID, oldDID, testCase.registryMode)
	dir, err := os.MkdirTemp(root, "rotation-crash-")
	if err != nil {
		t.Fatal(err)
	}
	writeStandaloneSelfCustodyIdentity(t, dir, "acme.com/alice", oldDID, stableID, fixture.server.URL, oldPrivate)
	foreign := seedForeignRotationOperation(t, dir)

	if testCase.registryMode == rotationRegistryBlockOld || testCase.registryMode == rotationRegistryBlockApplied {
		killRotationAtRegistryWindow(t, ctx, bin, dir, registryState)
	} else {
		killRotationAtCheckpoint(t, ctx, bin, dir, testCase.point, testCase.pathContains)
	}

	assertRotationCrashState(t, dir, stableID, oldDID, fixture, testCase)
	assertForeignRotationOperation(t, foreign)

	recovered := runRotationRecoveryCommand(t, ctx, bin, dir, "recover")
	if recovered.Status != testCase.wantRecovery {
		t.Fatalf("post-crash recovery status=%q, want %q", recovered.Status, testCase.wantRecovery)
	}
	assertForeignRotationOperation(t, foreign)

	registryState.setMode(rotationRegistrySuccess)
	if registryState.appliedCount() == 0 {
		out, err := runRotateKeyCommand(ctx, bin, dir)
		if err != nil {
			t.Fatalf("rotation after crash recovery failed: %v\n%s", err, out)
		}
	}
	assertCompletedRotation(t, dir, stableID, oldDID, fixture, registryState, foreign)
}

func newRotationCrashRegistry(t *testing.T, stableID, oldDID string, mode rotationCrashRegistryMode) (*cliRotationRegistryFixture, *rotationCrashRegistryState) {
	t.Helper()
	state := &rotationCrashRegistryState{
		mode: mode, ready: make(chan struct{}, 1), release: make(chan struct{}),
	}
	fixture := newCLIRotationRegistryFixture(t, stableID, oldDID, func(f *cliRotationRegistryFixture, w http.ResponseWriter, _ map[string]any) {
		switch state.currentMode() {
		case rotationRegistryReject:
			http.Error(w, "rotation rejected", http.StatusConflict)
		case rotationRegistryBlockOld:
			state.ready <- struct{}{}
			<-state.release
			http.Error(w, "rotation interrupted", http.StatusConflict)
		case rotationRegistryBlockApplied:
			f.currentDID = f.proposedDID
			state.recordApply()
			state.ready <- struct{}{}
			<-state.release
			f.dropResponse(w)
		default:
			f.currentDID = f.proposedDID
			state.recordApply()
			_ = json.NewEncoder(w).Encode(awid.DIDMapping{
				DIDAW: stableID, CurrentDIDKey: f.proposedDID,
				CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
			})
		}
	})
	return fixture, state
}

func killRotationAtRegistryWindow(t *testing.T, ctx context.Context, bin, dir string, state *rotationCrashRegistryState) {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, "id", "rotate-key", "--json")
	cmd.Dir = dir
	cmd.Env = testCommandEnv(dir)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-state.ready:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("rotation did not reach registry crash window\n%s", output.String())
	}
	signalRotationSIGKILL(t, cmd)
	close(state.release)
	waitForRotationSIGKILL(t, cmd)
}

func killRotationAtCheckpoint(t *testing.T, ctx context.Context, bin, dir, point, pathContains string) {
	t.Helper()
	killRotationCommandAtCheckpoint(t, ctx, bin, dir, point, pathContains)
}

func killRotationCommandAtCheckpoint(t *testing.T, ctx context.Context, bin, dir, point, pathContains string, action ...string) {
	t.Helper()
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyReader.Close()
	defer controlWriter.Close()

	args := append([]string{"id", "rotate-key"}, action...)
	args = append(args, "--json")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.ExtraFiles = []*os.File{readyWriter, controlReader}
	cmd.Env = rotationCrashCapabilityEnv(testCommandEnv(dir), map[string]string{
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_PROTOCOL":      rotationCrashTestProtocol,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_POINT":         point,
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_READY_FD":      "3",
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_CONTROL_FD":    "4",
		"AWEB_INTERNAL_ROTATION_CRASH_TEST_PATH_CONTAINS": pathContains,
	})
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = readyWriter.Close()
	_ = controlReader.Close()

	if err := readyReader.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	gotPoint, err := bufio.NewReader(readyReader).ReadString('\n')
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("rotation exited before crash checkpoint %q: %v\n%s", point, err, output.String())
	}
	if strings.TrimSpace(gotPoint) != point {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("crash checkpoint=%q, want %q", strings.TrimSpace(gotPoint), point)
	}
	signalRotationSIGKILL(t, cmd)
	waitForRotationSIGKILL(t, cmd)
}

func signalRotationSIGKILL(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
}

func waitForRotationSIGKILL(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Wait(); err == nil {
		t.Fatal("SIGKILLed rotation exited successfully")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("rotation exit status=%v, want SIGKILL", cmd.ProcessState.Sys())
	}
}

func assertRotationCrashState(t *testing.T, dir, stableID, oldDID string, fixture *cliRotationRegistryFixture, want rotationCrashCase) {
	t.Helper()
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	pending, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if (pending != nil) != want.wantState {
		t.Fatalf("pending state=%+v, want present=%v", pending, want.wantState)
	}
	newDID := crashRegistryProposedDID(fixture)
	if pending != nil {
		newDID = pending.NewDID
		assertCrashPathExists(t, pending.PendingKey, want.wantPendingPrivate)
		assertCrashPathExists(t, awid.PublicKeyPath(pending.PendingKey), want.wantPendingPublic)
	}
	activePath := awconfig.WorktreeSigningKeyPath(dir)
	assertSigningKeyDID(t, activePath, chooseDID(want.wantActivePrivateNew, oldDID, newDID))
	assertPublicKeyDID(t, awid.PublicKeyPath(activePath), chooseDID(want.wantActivePublicNew, oldDID, newDID))
	identity := loadIdentityForTest(t, dir)
	if identity.DID != chooseDID(want.wantIdentityNew, oldDID, newDID) {
		t.Fatalf("identity did=%q", identity.DID)
	}
	archivePrivate, archivePublic := archivedRotationKeyPaths(activePath, oldDID)
	assertCrashPathExists(t, archivePrivate, want.wantArchivePrivate)
	assertCrashPathExists(t, archivePublic, want.wantArchivePublic)
	registryDID := crashRegistryCurrentDID(fixture)
	if registryDID != chooseDID(want.wantRegistryNew, oldDID, newDID) {
		t.Fatalf("registry did=%q", registryDID)
	}
	if want.mustPreserveNew && newDID != "" {
		pendingHasNew := pending != nil && pathSigningKeyDID(pending.PendingKey) == newDID
		activeHasNew := pathSigningKeyDID(activePath) == newDID
		if !pendingHasNew && !activeHasNew {
			t.Fatalf("new private key %s was not preserved", newDID)
		}
	}
}

func assertCompletedRotation(t *testing.T, dir, stableID, oldDID string, fixture *cliRotationRegistryFixture, registryState *rotationCrashRegistryState, foreign *foreignRotationOperation) {
	t.Helper()
	applied := registryState.appliedCount()
	if applied != 1 {
		t.Fatalf("authoritative registry applies=%d, want 1", applied)
	}
	registryDID := crashRegistryCurrentDID(fixture)
	identity := loadIdentityForTest(t, dir)
	if identity.DID != registryDID {
		t.Fatalf("identity did=%q, registry did=%q", identity.DID, registryDID)
	}
	activePath := awconfig.WorktreeSigningKeyPath(dir)
	assertSigningKeyDID(t, activePath, registryDID)
	assertPublicKeyDID(t, awid.PublicKeyPath(activePath), registryDID)
	archivePrivate, archivePublic := archivedRotationKeyPaths(activePath, oldDID)
	assertCrashPathExists(t, archivePrivate, true)
	assertCrashPathExists(t, archivePublic, true)
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	if pending, err := loadPendingRotationState(rotationDir, stableID); err != nil {
		t.Fatal(err)
	} else if pending != nil {
		t.Fatalf("pending rotation state remains: %+v", pending)
	}
	assertNoOwnedRotationFiles(t, rotationDir, foreign)
	if foreign != nil {
		assertForeignRotationOperation(t, foreign)
	}
}

func crashRegistryCurrentDID(fixture *cliRotationRegistryFixture) string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.currentDID
}

func crashRegistryProposedDID(fixture *cliRotationRegistryFixture) string {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.proposedDID
}

func chooseDID(useNew bool, oldDID, newDID string) string {
	if useNew {
		return newDID
	}
	return oldDID
}

func assertSigningKeyDID(t *testing.T, path, want string) {
	t.Helper()
	key, err := awid.LoadSigningKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != want {
		t.Fatalf("private key %s did=%q, want %q", path, got, want)
	}
}

func assertPublicKeyDID(t *testing.T, path, want string) {
	t.Helper()
	key, err := awid.LoadPublicKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := awid.ComputeDIDKey(key); got != want {
		t.Fatalf("public key %s did=%q, want %q", path, got, want)
	}
}

func pathSigningKeyDID(path string) string {
	key, err := awid.LoadSigningKey(path)
	if err != nil {
		return ""
	}
	return awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
}

func assertCrashPathExists(t *testing.T, path string, want bool) {
	t.Helper()
	_, err := os.Stat(path)
	if want && err != nil {
		t.Fatalf("expected path %s: %v", path, err)
	}
	if !want && !os.IsNotExist(err) {
		t.Fatalf("unexpected path %s: %v", path, err)
	}
}

func archivedRotationKeyPaths(activePath, oldDID string) (string, string) {
	base := filepath.Join(filepath.Dir(activePath), "rotated", pendingFileBase(oldDID))
	return base + ".key", base + ".pub"
}

type foreignRotationOperation struct {
	rotationDir string
	stableID    string
	state       []byte
	privatePath string
	private     []byte
	publicPath  string
	public      []byte
	tempPath    string
	temp        []byte
}

func seedForeignRotationOperation(t *testing.T, dir string) *foreignRotationOperation {
	t.Helper()
	rotationDir := filepath.Join(dir, ".aw", "rotation")
	operationID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	stableID := "did:aw:foreign-operation"
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privatePath, err := savePendingRotationKeypair(rotationDir, operationID, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	state := &pendingRotationState{
		OperationID: operationID, StableID: stableID,
		OldDID: "did:key:foreign-old", NewDID: awid.ComputeDIDKey(pub),
		PendingKey: privatePath,
	}
	if err := savePendingRotationState(rotationDir, state); err != nil {
		t.Fatal(err)
	}
	statePath := pendingRotationStatePath(rotationDir, stableID)
	tempPath := filepath.Join(rotationDir, "pending", ".tmp.foreign-"+operationID)
	if err := awid.SaveSigningKey(tempPath, priv); err != nil {
		t.Fatal(err)
	}
	return &foreignRotationOperation{
		rotationDir: rotationDir, stableID: stableID,
		state:       readFileForCrashTest(t, statePath),
		privatePath: privatePath, private: readFileForCrashTest(t, privatePath),
		publicPath: awid.PublicKeyPath(privatePath), public: readFileForCrashTest(t, awid.PublicKeyPath(privatePath)),
		tempPath: tempPath, temp: readFileForCrashTest(t, tempPath),
	}
}

func assertForeignRotationOperation(t *testing.T, foreign *foreignRotationOperation) {
	t.Helper()
	if foreign == nil {
		return
	}
	statePath := pendingRotationStatePath(foreign.rotationDir, foreign.stableID)
	for path, want := range map[string][]byte{
		statePath: foreign.state, foreign.privatePath: foreign.private, foreign.publicPath: foreign.public,
		foreign.tempPath: foreign.temp,
	} {
		if got := readFileForCrashTest(t, path); !bytes.Equal(got, want) {
			t.Fatalf("foreign operation file changed at %s", path)
		}
	}
}

func assertNoOwnedRotationFiles(t *testing.T, rotationDir string, foreign *foreignRotationOperation) {
	t.Helper()
	allowed := map[string]bool{}
	if foreign != nil {
		allowed[foreign.privatePath] = true
		allowed[foreign.publicPath] = true
		allowed[foreign.tempPath] = true
	}
	pendingDir := filepath.Join(rotationDir, "pending")
	patterns := []string{
		filepath.Join(pendingDir, "*.signing.key"),
		filepath.Join(pendingDir, "*.signing.pub"),
		filepath.Join(pendingDir, ".tmp.*"),
		filepath.Join(filepath.Dir(rotationDir), ".tmp.*"),
		filepath.Join(filepath.Dir(rotationDir), "rotated", ".tmp.*"),
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			if !allowed[match] {
				t.Fatalf("completed operation key file remains: %s", match)
			}
		}
	}
}

func readFileForCrashTest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
