package wake

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(dir, "wake"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// shortTempStore puts the state directory under a short path. A unix socket
// path is bounded by sun_path (104 bytes on macOS), and t.TempDir() embeds the
// test's name, which alone can exceed it.
func shortTempStore(t *testing.T) *Store {
	t.Helper()
	dir, err := os.MkdirTemp("", "awwk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(resolved, "w"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func tempHome(t *testing.T, name string) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Join(home, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

// TestRegistrationRefusedWithoutDeliverySession is the exclusivity check of §6:
// two presentation surfaces on one identity double every wake, and the check
// reads the explicit field rather than inferring the mode.
func TestRegistrationRefusedWithoutDeliverySession(t *testing.T) {
	home := tempHome(t, "instance")
	identityHome := filepath.Join(home, ".aw")

	for _, delivery := range []string{"", "channel", "Session-ish", "sessions", "none"} {
		reg := Registration{Home: home, IdentityHome: identityHome, Delivery: delivery}
		err := reg.Validate()
		if err == nil {
			t.Fatalf("delivery %q was accepted", delivery)
		}
		if !strings.Contains(err.Error(), "session") || !strings.Contains(err.Error(), "doubles every wake") {
			t.Fatalf("refusal does not name the conflict: %v", err)
		}
	}

	// The one accepted value, case-insensitively, because the hook writes an
	// environment value and not a Go constant.
	for _, delivery := range []string{"session", "SESSION", " session "} {
		reg := Registration{Home: home, IdentityHome: identityHome, Delivery: delivery}
		if err := reg.Validate(); err != nil {
			t.Fatalf("delivery %q refused: %v", delivery, err)
		}
	}
}

func TestRegistrationRequiresAbsoluteHomes(t *testing.T) {
	cases := []Registration{
		{Home: "relative/home", IdentityHome: "/abs", Delivery: DeliverySession},
		{Home: "/abs", IdentityHome: "relative", Delivery: DeliverySession},
		{Home: "", IdentityHome: "/abs", Delivery: DeliverySession},
		{Home: "/abs", IdentityHome: "", Delivery: DeliverySession},
	}
	for _, reg := range cases {
		if err := reg.Validate(); err == nil {
			t.Errorf("accepted %#v", reg)
		}
	}
	bad := Registration{Home: "/a", IdentityHome: "/b", Delivery: DeliverySession, Backend: "carrier-pigeon"}
	if err := bad.Validate(); err == nil {
		t.Error("an unknown backend was accepted")
	}
}

func TestStoreRoundTripsRegistrationsAndCanonicalisesHomes(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "instance")

	reg := Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession, Backend: "tmux", RegisteredAt: at(0)}
	if err := store.SaveRegistration(reg); err != nil {
		t.Fatal(err)
	}

	// A different spelling of one home must not become a second registration.
	spelled := filepath.Join(home, ".", "..", filepath.Base(home))
	loaded, ok, err := store.LoadRegistration(spelled)
	if err != nil || !ok {
		t.Fatalf("ok=%t err=%v", ok, err)
	}
	if loaded.Home != home {
		t.Fatalf("home=%q want %q", loaded.Home, home)
	}

	all, err := store.ListRegistrations()
	if err != nil || len(all) != 1 {
		t.Fatalf("registrations=%v err=%v", all, err)
	}

	existed, err := store.DeleteRegistration(spelled)
	if err != nil || !existed {
		t.Fatalf("existed=%t err=%v", existed, err)
	}
	if all, _ := store.ListRegistrations(); len(all) != 0 {
		t.Fatalf("registrations survived deletion: %v", all)
	}
}

func TestStoreDropsTransientHintsOnDisk(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "instance")

	state := InstanceState{Home: home}
	state.AddHint(Hint{Kind: KindMail, MessageID: "m1", At: at(0)}, DefaultHintCap)
	state.AddHint(Hint{Kind: KindControl, SignalID: "s1", At: at(1), Transient: true}, DefaultHintCap)
	if err := store.SaveInstance(state); err != nil {
		t.Fatal(err)
	}

	reloaded, err := store.LoadInstance(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Pending) != 1 || reloaded.Pending[0].Kind != KindMail {
		t.Fatalf("a transient control signal was replayed from disk: %#v", reloaded.Pending)
	}
}

func TestStoreLayoutMatchesTheNote(t *testing.T) {
	store := tempStore(t)
	home := tempHome(t, "instance")
	if err := store.SaveRegistration(Registration{Home: home, IdentityHome: filepath.Join(home, ".aw"), Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveInstance(InstanceState{Home: home}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveStatus(Status{StateDir: store.Dir(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	key := HomeKey(home)
	for _, path := range []string{
		filepath.Join(store.Dir(), "registry.d", key+".json"),
		filepath.Join(store.Dir(), "instances.d", key+".json"),
		filepath.Join(store.Dir(), "status.json"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("missing %s: %v", path, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("%s mode=%o want 600", path, mode)
		}
	}
	if store.SocketPath() != filepath.Join(store.Dir(), "control.sock") {
		t.Errorf("socket path=%s", store.SocketPath())
	}
	if store.LockDir() != filepath.Join(store.Dir(), "lock") {
		t.Errorf("lock dir=%s", store.LockDir())
	}
}

func TestLockIsOneDaemonPerHostAndReclaimsAStaleOwner(t *testing.T) {
	store := tempStore(t)

	lock, err := AcquireLock(store.LockDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(store.LockDir()); err == nil {
		t.Fatal("a second daemon took the lock")
	} else if _, ok := err.(*ErrDaemonAlreadyRunning); !ok {
		t.Fatalf("err=%v want ErrDaemonAlreadyRunning", err)
	}
	if pid, alive := LockOwner(store.LockDir()); pid != os.Getpid() || !alive {
		t.Fatalf("owner pid=%d alive=%t", pid, alive)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	// A lock left by a process that no longer exists must be reclaimable: a
	// broker crash may not make a restart impossible, because restart is the
	// documented recovery (§6).
	if err := os.MkdirAll(store.LockDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.LockDir(), "pid"), []byte("4194303\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reclaimed, err := AcquireLock(store.LockDir())
	if err != nil {
		t.Fatalf("a stale lock blocked restart: %v", err)
	}
	_ = reclaimed.Release()
}
