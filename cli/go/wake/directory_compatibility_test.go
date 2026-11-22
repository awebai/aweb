//go:build !windows

package wake

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWakeSharedStateWarnsOnceWithoutRefusingCommands(t *testing.T) {
	for _, sub := range []string{"", "registry.d", "instances.d"} {
		t.Run(sub, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := NewStore(dir); err != nil {
				t.Fatal(err)
			}
			shared := filepath.Join(dir, sub)
			if err := os.Chmod(shared, 0o770); err != nil {
				t.Fatal(err)
			}
			var warning bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&warning)
			t.Cleanup(func() { log.SetOutput(previous) })
			store, err := NewStore(dir)
			if err != nil {
				t.Fatalf("released state operation refused shared layout: %v", err)
			}
			if _, err := store.ListRegistrations(); err != nil {
				t.Fatal(err)
			}
			if _, err := NewStore(dir); err != nil {
				t.Fatal(err)
			}
			if strings.Count(warning.String(), "Warning:") != 1 || !strings.Contains(warning.String(), "chmod go-w '"+shared+"'") {
				t.Fatalf("missing one actionable warning: %s", warning.String())
			}
			info, err := os.Stat(shared)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o770 {
				t.Fatal("inspection changed operator permissions")
			}
			snapshot, err := NewChannelCoreRunner(store).executableSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			if err := snapshot.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWakeControlDirectoryRequiresCurrentOwner(t *testing.T) {
	// An unprivileged test can inspect the root-owned filesystem root without
	// modifying it. A privileged test can make a foreign-owned fixture.
	dir := "/"
	if os.Geteuid() == 0 {
		dir = t.TempDir()
		if err := os.Chown(dir, 1, -1); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkWakeControlDirectory(dir, false); err == nil || !strings.Contains(err.Error(), "unsafe wake control directory") {
		t.Fatalf("foreign-owned wake state was not refused: %v", err)
	}
}

func TestWakeControlShortSocketDirectoryRequiresPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkWakeControlDirectory(dir, true); err != nil {
		t.Fatalf("private socket directory was refused: %v", err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := checkWakeControlDirectory(dir, true); err == nil || !strings.Contains(err.Error(), "unsafe wake control directory") {
		t.Fatalf("shared private runtime was not refused: %v", err)
	}
}

func TestRunnerDoesNotRefuseStorageManagedAncestor(t *testing.T) {
	mount := t.TempDir()
	if err := os.Chmod(mount, 0o770); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(mount, "home", ".config", "aw", "wake"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewChannelCoreRunner(store).executableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshot.close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunnerExecutionDirectoryOwnershipRule(t *testing.T) {
	current := uint32(os.Geteuid())
	for _, tc := range []struct {
		name   string
		owner  uint32
		mode   os.FileMode
		unsafe bool
	}{
		{name: "same UID private", owner: current, mode: 0o700},
		{name: "same UID read-only sharing", owner: current, mode: 0o755},
		{name: "root owned read-only sharing", owner: 0, mode: 0o755},
		{name: "another unprivileged owner", owner: current + 1, mode: 0o700, unsafe: true},
		{name: "group writable", owner: current, mode: 0o770, unsafe: true},
		{name: "others writable", owner: current, mode: 0o707, unsafe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := wakeDirectoryPermissions{Path: "/state/wake", Owner: tc.owner, Mode: tc.mode}
			if got := directory.writableByAnotherUser(); got != tc.unsafe {
				t.Fatalf("other user can replace cache: %t, want %t", got, tc.unsafe)
			}
			if tc.unsafe && directory.repairAdvice() == "" {
				t.Fatal("missing repair command")
			}
		})
	}
}

func TestRunnerTemporaryParentMustProtectPrivateEntries(t *testing.T) {
	parent := t.TempDir()
	if err := checkRunnerSnapshotParent(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkRunnerSnapshotParent(parent); err == nil || !strings.Contains(err.Error(), "Ask the system administrator") || !strings.Contains(err.Error(), "retry aw wake") {
		t.Fatalf("unprotected temporary parent: %v", err)
	}
	if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkRunnerSnapshotParent(parent); err != nil {
		t.Fatalf("sticky parent refuses protected entry: %v", err)
	}
	snapshot := t.TempDir()
	if err := os.Chmod(snapshot, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkRunnerSnapshotDirectory(snapshot); err == nil || !strings.Contains(err.Error(), "chmod go-w") || !strings.Contains(err.Error(), "retry aw wake") {
		t.Fatalf("writable execution directory: %v", err)
	}
}

func TestReadOnlyCacheDoesNotBlockPrivateExecution(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses read-only directory permissions")
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	root := filepath.Join(store.Dir(), "channel-core")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "runner.mjs")
	if err := os.WriteFile(cache, []byte("tampered read-only shared cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "runner.sha256"), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Error(err)
		}
	})
	var warning bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&warning)
	t.Cleanup(func() { log.SetOutput(previous) })
	snapshot, err := runner.executableSnapshot()
	if err != nil {
		t.Fatalf("read-only data cache blocked private execution: %v", err)
	}
	t.Cleanup(func() {
		if err := snapshot.close(); err != nil {
			t.Error(err)
		}
	})
	got, err := os.ReadFile(snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("private execution trusted corrupt read-only cache")
	}
	cached, err := os.ReadFile(cache)
	if err != nil || string(cached) != "tampered read-only shared cache" {
		t.Fatalf("read-only cache was changed: %v", err)
	}
	if !strings.Contains(warning.String(), "runner.sha256") || !strings.Contains(warning.String(), "retry aw wake") {
		t.Fatalf("missing cache recovery warning: %s", warning.String())
	}
}

func TestReadOnlyRootUsesWritableTemporaryVolume(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses read-only fixture permissions")
	}
	root := t.TempDir()
	readOnlyRoot := filepath.Join(root, "root")
	if err := os.Mkdir(readOnlyRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(readOnlyRoot, 0o700); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.MkdirTemp(readOnlyRoot, "must-not-write-"); !os.IsPermission(err) {
		t.Fatalf("root fixture is writable: %v", err)
	}
	writable := filepath.Join(root, "temporary-volume")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", writable)
	store, err := NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewChannelCoreRunner(store).executableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.close(); err != nil {
			t.Error(err)
		}
	})
	if filepath.Dir(snapshot.directory) != writable {
		t.Fatalf("runner ignored writable TMPDIR: %s", snapshot.directory)
	}
}

func TestRunnerStartupRemovesOnlyStaleUnheldOwnSnapshots(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	active, err := NewChannelCoreRunner(store).executableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := active.close(); err != nil {
			t.Error(err)
		}
	})
	stale := filepath.Join(parent, "aw-wake-runner-stale")
	recent := filepath.Join(parent, "aw-wake-runner-recent")
	unrelated := filepath.Join(parent, "other-directory")
	for _, path := range []string{stale, recent, unrelated} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-25 * time.Hour)
	for _, path := range []string{stale, unrelated, active.directory} {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	symlink := filepath.Join(parent, "aw-wake-runner-link")
	if err := os.Symlink(unrelated, symlink); err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewChannelCoreRunner(store).executableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot remains: %v", err)
	}
	for _, path := range []string{recent, unrelated, active.directory, symlink} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("removed live/recent/unrelated entry %s: %v", path, err)
		}
	}
}
