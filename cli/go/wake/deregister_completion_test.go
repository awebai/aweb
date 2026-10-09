package wake

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/wake/session"
)

// Exercises the actual CLI, control socket, started owner and child. Holding the
// owner's cancellation lets the transport deadline expire before actual stop.
func TestManagedDeregisterCLIRejectsPendingStop(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	build := exec.Command("go", "build", "-o", bin, "../cmd/aw")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	store := shortTempStore(t)
	home := tempHome(t, "receiver")
	identity := filepath.Join(home, ".aw")
	writeWakeTestTeamState(t, identity, "team:one")
	writeFakeNode(t, root, "#!/bin/sh\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nwhile IFS= read -r line; do :; done\n")
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	broker, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store)})
	defer cancel()
	if err := broker.Register(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, broker, home, func(s InstanceStatus) bool { return s.ChannelCore.Running })
	expected := broker.Status().Instances[0].ManagedReceiver
	if expected == nil {
		t.Fatal("live status did not export accepted receiver")
	}
	expectPath := filepath.Join(root, "expected.json")
	data, _ := json.Marshal(expected)
	if err := os.WriteFile(expectPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	runner, _ := broker.instanceRunner(home)
	runner.mu.Lock()
	child := runner.child
	originalCancel := runner.cancel
	entered, release := make(chan struct{}), make(chan struct{})
	runner.cancel = func() { close(entered); <-release; originalCancel() }
	runner.mu.Unlock()
	var once sync.Once
	resume := func() { once.Do(func() { close(release) }) }
	defer func() { resume(); runner.stop() }()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go ServeControl(ctx, broker)
	waitFor(t, "control ready", func() bool { _, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus}); return err == nil })
	cmd := exec.Command(bin, "wake", "deregister", "--home", home, "--state-dir", store.Dir(), "--json", "--require-managed-stop", "--expect-registration", expectPath)
	cmd.Env = append(os.Environ(), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() { out, err := cmd.CombinedOutput(); done <- result{out, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("CLI did not reach real managed stop")
	}
	if _, ok := broker.instanceRunner(home); ok {
		t.Fatal("expected stop-in-progress map absence")
	}
	var got result
	select {
	case got = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("CLI did not reach control timeout")
	}
	select {
	case <-child.done:
		t.Fatal("fixture did not retain live child")
	default:
	}
	if got.err == nil {
		t.Fatalf("CLI reported completion while managed stop remained pending: %s", strings.TrimSpace(string(got.out)))
	}
	if _, ok, err := store.LoadRegistration(home); err != nil || !ok {
		t.Fatalf("strict timeout fell back to deleting registration: ok=%v err=%v", ok, err)
	}
	if strings.Contains(string(got.out), "daemon is not running") {
		t.Fatalf("accepted unanswered request misclassified as daemon down: %s", got.out)
	}
	if !strings.Contains(string(got.out), "NOT confirmed") {
		t.Fatalf("missing explicit uncertainty: %s", got.out)
	}
}

func managedReceiverFixture(t *testing.T) (*Broker, *Store, ManagedReceiver, *ChannelCoreChild) {
	t.Helper()
	root := t.TempDir()
	pidPath := filepath.Join(root, "grandchild.pid")
	writeFakeNode(t, root, "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s' \"$!\" > "+shellQuoteForTest(pidPath)+"\nprintf '{\"type\":\"status\",\"ready\":true}\\n'\nwhile IFS= read -r line; do :; done\n")
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	store := shortTempStore(t)
	home := tempHome(t, "managed")
	identity := filepath.Join(home, ".aw")
	writeWakeTestTeamState(t, identity, "team:one")
	b, cancel := liveBroker(t, Config{Store: store, Session: session.NewFake(session.Inspection{}), ChannelCore: NewChannelCoreRunner(store)})
	t.Cleanup(cancel)
	if err := b.Register(Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	waitForInstance(t, b, home, func(s InstanceStatus) bool { return s.ChannelCore.Running })
	r, _ := b.instanceRunner(home)
	r.mu.Lock()
	c := r.child
	r.mu.Unlock()
	expected := b.Status().Instances[0].ManagedReceiver
	if expected == nil {
		t.Fatal("missing accepted snapshot")
	}
	return b, store, *expected, c
}

func TestManagedDeregisterCompletionAndWrongReceiver(t *testing.T) {
	b, store, expected, child := managedReceiverFixture(t)
	// These pending/file mismatches are synthetic, deliberately unaccepted state.
	// Drain any current sweep and keep the live broker from accepting them.
	// Do not hold reconcileMu: the stop path must acquire that lock itself.
	b.passMu.Lock()
	defer b.passMu.Unlock()
	home := expected.Registration.Home
	wrong := expected
	wrong.Generation++
	if r, err := b.DeregisterManaged(context.Background(), wrong); err == nil || r != nil {
		t.Fatal("wrong generation stopped receiver")
	}
	wrong = expected
	wrong.Registration = expected.Registration.clone()
	wrong.Registration.ReceiveIdentities[0].Label = "different snapshot"
	if r, err := b.DeregisterManaged(context.Background(), wrong); err == nil || r != nil {
		t.Fatal("different full snapshot stopped receiver")
	}
	if _, ok := b.instanceRunner(home); !ok {
		t.Fatal("mismatch removed owner")
	}
	if !child.Status().Running {
		t.Fatal("mismatch stopped child")
	}
	runner, _ := b.instanceRunner(home)
	runner.mu.Lock()
	pending := runner.reg.clone()
	runner.pendingReg = &pending
	runner.mu.Unlock()
	if r, err := b.DeregisterManaged(context.Background(), expected); err == nil || r != nil {
		t.Fatal("pending update accepted")
	}
	if b.Status().Instances[0].ManagedReceiver != nil {
		t.Fatal("pending receiver exported")
	}
	runner.mu.Lock()
	runner.pendingReg = nil
	runner.mu.Unlock()
	// A file-fallback update may not yet have reached the accepted owner.
	// It cannot be silently deleted by matching only the in-memory snapshot.
	stored := expected.Registration.clone()
	stored.ReceiveIdentities[0].Label = "not-yet-applied"
	if err := store.SaveRegistration(stored); err != nil {
		t.Fatal(err)
	}
	if receipt, err := b.DeregisterManaged(context.Background(), expected); err == nil || receipt != nil {
		t.Fatal("unapplied stored change accepted")
	}
	if !child.Status().Running {
		t.Fatal("stored mismatch stopped child")
	}
	if err := store.SaveRegistration(expected.Registration); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go ServeControl(ctx, b)
	waitFor(t, "control ready", func() bool { _, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus}); return err == nil })
	receipt, err := CallManagedStop(store.SocketPath(), expected)
	if err != nil {
		t.Fatal(err)
	}
	if !sameManagedReceiver(receipt.Receiver, expected) || !receipt.ManagedJoined {
		t.Fatalf("wrong receipt: %+v", receipt)
	}
	select {
	case <-child.done:
	default:
		t.Fatal("receipt before child join")
	}
	child.mu.Lock()
	groups := append([]int(nil), child.ownedProcessGroups...)
	child.mu.Unlock()
	if len(groups) == 0 {
		t.Fatal("test did not create real process group")
	}
	for _, pgid := range groups {
		gone, err := managedProcessGroupGone(pgid)
		if err != nil || !gone {
			t.Fatalf("receipt before group %d absence: %v", pgid, err)
		}
	}
	if _, ok, err := store.LoadRegistration(home); err != nil || ok {
		t.Fatalf("registration survives receipt: %v %v", ok, err)
	}
	if again, err := CallManagedStop(store.SocketPath(), expected); err == nil || again != nil {
		t.Fatal("missing owner manufactured repeat completion")
	}
}

// Force the race that the synthetic-mismatch test must exclude. A label is
// accepted synchronously without restarting the child or changing generation;
// restoring the file alone does not restore the accepted receiver snapshot.
func TestManagedDeregisterReconciledLabelMismatch(t *testing.T) {
	b, store, expected, child := managedReceiverFixture(t)
	home := expected.Registration.Home
	changed := expected.Registration.clone()
	changed.ReceiveIdentities[0].Label = "reconciled-label"
	if err := store.SaveRegistration(changed); err != nil {
		t.Fatal(err)
	}
	b.Reconcile() // Real snapshot/apply, not a timer-dependent race.
	b.passMu.Lock()
	defer b.passMu.Unlock()
	accepted := b.Status().Instances[0].ManagedReceiver
	if accepted == nil || accepted.Registration.ReceiveIdentities[0].Label != "reconciled-label" {
		t.Fatal("reconcile did not accept the changed label")
	}
	if accepted.Generation != expected.Generation || accepted.OwnerID != expected.OwnerID {
		t.Fatal("label-only update unexpectedly replaced receiver generation or owner")
	}
	if err := store.SaveRegistration(expected.Registration); err != nil {
		t.Fatal(err)
	}
	// Durable bytes now match the old expectation; the accepted snapshot does not.
	durable, exists, err := store.LoadRegistration(home)
	if err != nil || !exists || !sameManagedReceiver(ManagedReceiver{
		Registration: durable, Generation: expected.Generation, OwnerID: expected.OwnerID,
	}, expected) {
		t.Fatalf("failed to restore durable snapshot: exists=%v err=%v", exists, err)
	}
	receipt, err := b.DeregisterManaged(context.Background(), expected)
	if err == nil || receipt != nil || !strings.Contains(err.Error(), "accepted receiver changed") {
		t.Fatalf("stale accepted snapshot was not refused: receipt=%+v err=%v", receipt, err)
	}
	if _, ok := b.instanceRunner(home); !ok || !child.Status().Running {
		t.Fatal("refusal removed owner or stopped child")
	}
	if _, exists, err := store.LoadRegistration(home); err != nil || !exists {
		t.Fatalf("refusal removed registration: exists=%v err=%v", exists, err)
	}
}

func TestManagedDeregisterNoDaemonAndReceiptValidation(t *testing.T) {
	store := shortTempStore(t)
	home := tempHome(t, "offline")
	identity := filepath.Join(home, ".aw")
	writeWakeTestTeamState(t, identity, "team:one")
	reg := Registration{Home: home, IdentityHome: identity, Delivery: DeliverySession, RegisteredAt: time.Now().UTC()}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}
	reg, _, _ = store.LoadRegistration(home)
	expected := ManagedReceiver{Registration: reg, Generation: 0, OwnerID: "offline-expectation"}
	if receipt, err := CallManagedStop(store.SocketPath(), expected); err == nil || receipt != nil {
		t.Fatal("absent daemon certified completion")
	}
	if _, ok, _ := store.LoadRegistration(home); !ok {
		t.Fatal("absent daemon deleted registration")
	}
	status, err := StatusFromStore(store, 10)
	if err != nil || status.Instances[0].ManagedReceiver != nil {
		t.Fatal("store status invented managed snapshot")
	}
	for _, name := range []string{"legacy-ok", "wrong-receiver", "wrong-owner", "wrong-schema", "old-daemon", "lost-response", "unterminated-receipt"} {
		t.Run(name, func(t *testing.T) {
			ln, err := net.Listen("unix", store.SocketPath())
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				var req ControlRequest
				json.NewDecoder(conn).Decode(&req)
				if req.Op != OpDeregisterManaged {
					t.Errorf("wrong control op: %s", req.Op)
				}
				if name == "old-daemon" {
					json.NewEncoder(conn).Encode(ControlResponse{Error: "unknown control op"})
					return
				}
				if name == "lost-response" {
					return
				}
				reply := ControlResponse{OK: true, Existed: true}
				if name != "legacy-ok" {
					r := ManagedStopReceipt{Version: 1, Scope: "captured-managed-worker", Receiver: expected, ManagedJoined: true, CompletedAt: time.Now(), AcceptedInputDisposition: "not_certified"}
					if name == "wrong-receiver" {
						r.Receiver.Generation++
					} else if name == "wrong-owner" {
						r.Receiver.OwnerID = "another-owner"
					} else if name == "wrong-schema" {
						r.Version = 99
					}
					reply.ManagedStop = &r
				}
				if name == "unterminated-receipt" {
					data, _ := json.Marshal(reply)
					conn.Write(data)
					return
				}
				json.NewEncoder(conn).Encode(reply)
			}()
			if receipt, err := callManagedStop(store.SocketPath(), expected, time.Second); err == nil || receipt != nil {
				t.Fatalf("%s accepted", name)
			}
			<-done
			if _, ok, _ := store.LoadRegistration(home); !ok {
				t.Fatal("bad receipt invoked fallback")
			}
		})
	}
}

func TestManagedDeregisterLockDeadlineAndGroupUncertainty(t *testing.T) {
	b, store, expected, child := managedReceiverFixture(t)
	b.reconcileMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := b.DeregisterManaged(ctx, expected)
	cancel()
	b.reconcileMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), "admission") {
		t.Fatalf("lock wait not bounded: %v", err)
	}
	if _, ok, _ := store.LoadRegistration(expected.Registration.Home); !ok || !child.Status().Running {
		t.Fatal("lock timeout mutated receiver")
	}
	// Unknown observation is never promoted to positive completion, even when
	// the real child subsequently joins. No foreign process is signaled here.
	child.Stop()
	expired, stop := context.WithCancel(context.Background())
	stop()
	if err := child.confirmManagedStop(expired); err == nil {
		t.Fatal("canceled confirmation certified completion")
	}
}

func TestManagedDeregisterPausedAndInactiveEligibility(t *testing.T) {
	t.Run("paused-owned", func(t *testing.T) {
		b, _, expected, child := managedReceiverFixture(t)
		if err := b.SetPaused(expected.Registration.Home, true); err != nil {
			t.Fatal(err)
		}
		row := b.Status().Instances[0]
		if !row.Paused || row.ManagedReceiver == nil || !sameManagedReceiver(*row.ManagedReceiver, expected) {
			t.Fatal("pause lost owned snapshot")
		}
		if receipt, err := b.DeregisterManaged(context.Background(), expected); err != nil || receipt == nil {
			t.Fatalf("paused withdrawal: %v", err)
		}
		select {
		case <-child.done:
		default:
			t.Fatal("paused child not joined")
		}
	})
	t.Run("inactive-cleared", func(t *testing.T) {
		b, store, expected, child := managedReceiverFixture(t)
		r, _ := b.instanceRunner(expected.Registration.Home)
		r.inactive <- inactiveSignal{generation: expected.Generation, state: "stopped"}
		waitFor(t, "inactive child cleared", func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.child == nil })
		select {
		case <-child.done:
		default:
			t.Fatal("inactive control did not join child")
		}
		if b.Status().Instances[0].ManagedReceiver != nil {
			t.Fatal("cleared child exported as eligible")
		}
		if receipt, err := b.DeregisterManaged(context.Background(), expected); err == nil || receipt != nil {
			t.Fatal("cleared child manufactured historical success")
		}
		if _, ok, _ := store.LoadRegistration(expected.Registration.Home); !ok {
			t.Fatal("refusal deleted registration")
		}
	})
	t.Run("replacement-owner", func(t *testing.T) {
		b, store, expected, _ := managedReceiverFixture(t)
		wrong := expected
		wrong.OwnerID = "previous-daemon-owner"
		if receipt, err := b.DeregisterManaged(context.Background(), wrong); err == nil || receipt != nil {
			t.Fatal("old-owner snapshot matched replacement")
		}
		if _, ok, _ := store.LoadRegistration(expected.Registration.Home); !ok {
			t.Fatal("owner mismatch deleted registration")
		}
	})
}

// The public acquisition and positive command path use a real CLI and socket;
// no expected fields are reconstructed from disk or hidden runner state.
func TestManagedDeregisterCLIExportAndPositiveReceipt(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/aw").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	b, store, _, child := managedReceiverFixture(t)
	if err := b.SetPaused(b.Status().Instances[0].Home, true); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	go ServeControl(ctx, b)
	waitFor(t, "control ready", func() bool { _, err := Call(store.SocketPath(), ControlRequest{Op: OpStatus}); return err == nil })
	run := func(args ...string) ([]byte, error) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
		return cmd.CombinedOutput()
	}
	out, err := run("wake", "status", "--state-dir", store.Dir(), "--json")
	if err != nil {
		t.Fatalf("status: %v %s", err, out)
	}
	var status Status
	if err := json.Unmarshal(out, &status); err != nil {
		t.Fatal(err)
	}
	if len(status.Instances) != 1 || status.Instances[0].ManagedReceiver == nil || !status.Instances[0].Paused {
		t.Fatalf("missing paused live export: %s", out)
	}
	expected := *status.Instances[0].ManagedReceiver
	data, _ := json.Marshal(expected)
	file := filepath.Join(root, "receiver.json")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"wake", "deregister", "--home", expected.Registration.Home, "--state-dir", store.Dir(), "--require-managed-stop", "--expect-registration", file, "--json"}
	wrong := append([]string(nil), args...)
	wrong[3] = root
	if out, err := run(wrong...); err == nil || !strings.Contains(string(out), "E_WAKE_RECEIVER_MISMATCH") {
		t.Fatalf("wrong home: %v %s", err, out)
	}
	out, err = run(args...)
	if err != nil {
		t.Fatalf("withdrawal: %v %s", err, out)
	}
	var receipt ManagedStopReceipt
	if err := json.Unmarshal(out, &receipt); err != nil {
		t.Fatal(err)
	}
	if !sameManagedReceiver(receipt.Receiver, expected) || !receipt.ManagedJoined || receipt.AcceptedInputDisposition != "not_certified" {
		t.Fatalf("invalid public receipt: %s", out)
	}
	select {
	case <-child.done:
	default:
		t.Fatal("receipt before child join")
	}
	child.mu.Lock()
	groups := append([]int(nil), child.ownedProcessGroups...)
	child.mu.Unlock()
	for _, pid := range groups {
		gone, err := managedProcessGroupGone(pid)
		if err != nil || !gone {
			t.Fatalf("public receipt before group absence: %d %v", pid, err)
		}
	}
}

func TestManagedStopConfirmationRequiresOwnedGroupAbsence(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	configureChildProcess(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { killChildProcessGroup(cmd); cmd.Wait() }()
	done := make(chan struct{})
	close(done)
	child := &ChannelCoreChild{done: done, ownedProcessGroups: []int{cmd.Process.Pid}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := child.confirmManagedStop(ctx); err == nil {
		t.Fatal("joined supervisor with live owned group certified complete")
	}
	gone, err := managedProcessGroupGone(cmd.Process.Pid)
	if err != nil || gone {
		t.Fatal("fixture lost live owned group")
	}
}
