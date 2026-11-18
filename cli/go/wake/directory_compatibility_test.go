//go:build !windows

package wake

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
			_, err = NewChannelCoreRunner(store).bundlePath()
			if sub == "" {
				if err == nil || !strings.Contains(err.Error(), "chmod go-w '"+shared+"'") || !strings.Contains(err.Error(), "then retry aw wake") {
					t.Fatalf("unsafe executable-cache parent was not refused actionably: %v", err)
				}
			} else if err != nil {
				t.Fatalf("non-executable shared state blocked private runner: %v", err)
			}
		})
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
	if _, err := NewChannelCoreRunner(store).bundlePath(); err != nil {
		t.Fatalf("private runner beneath storage-managed mount: %v", err)
	}
}

func TestRunnerCacheOwnershipRule(t *testing.T) {
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
