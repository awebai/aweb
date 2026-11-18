package wake

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunnerCacheRepairsActualExecutable(t *testing.T) {
	for _, damage := range []string{"changed", "empty", "missing"} {
		t.Run(damage, func(t *testing.T) {
			store, err := NewStore(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			runner := NewChannelCoreRunner(store)
			path, err := runner.bundlePath()
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			legacySum := sha256.Sum256(want)
			// This marker is produced by a released aw; retaining it models upgrade.
			stamp := filepath.Join(filepath.Dir(path), "runner.sha256")
			if err := os.WriteFile(stamp, []byte(fmt.Sprintf("%x\n", legacySum)), 0600); err != nil {
				t.Fatal(err)
			}
			switch damage {
			case "changed":
				err = os.WriteFile(path, []byte("throw new Error('changed')"), 0600)
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			case "missing":
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = runner.bundlePath(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("runner not repaired with intact stamp: %v", err)
			}
			if _, err := os.Lstat(stamp); !os.IsNotExist(err) {
				t.Fatalf("legacy stamp could mislead an older aw after downgrade: %v", err)
			}
		})
	}
}

func TestRunnerCacheDoesNotWriteThroughSymlink(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	path, err := runner.bundlePath()
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "user-file")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.bundlePath(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "keep" {
		t.Fatalf("modified symlink target: %q %v", got, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("runner cache remains symlink: %v", err)
	}
}

func TestRunnerExecutesPrivateSnapshotOfSharedCache(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := NewChannelCoreRunner(store)
	cache, err := runner.bundlePath()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Dir(cache), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := runner.executableSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snapshot.close(); err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(snapshot.Path, store.Dir()+string(os.PathSeparator)) {
		t.Fatal("execution snapshot remains in shared state")
	}
	if err := os.WriteFile(cache, []byte("changed after verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(snapshot.Path)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("cache mutation changed execution bytes: %v", err)
	}
	if runtime.GOOS != "windows" {
		fileInfo, err := os.Stat(snapshot.Path)
		if err != nil {
			t.Fatal(err)
		}
		directoryInfo, err := os.Stat(snapshot.directory)
		if err != nil {
			t.Fatal(err)
		}
		if fileInfo.Mode().Perm() != 0o600 || directoryInfo.Mode().Perm() != 0o700 {
			t.Fatal("execution snapshot is not private")
		}
	}
	if err := snapshot.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(snapshot.directory); !os.IsNotExist(err) {
		t.Fatalf("snapshot cleanup: %v", err)
	}
}

func TestRunnerCountsInvalidChildOutput(t *testing.T) {
	child := &ChannelCoreChild{}
	done := make(chan struct{})
	child.readStatus(strings.NewReader("not JSON\n"), done, childStatusOptions{})
	data, err := json.Marshal(child.Status())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"invalid_output_lines":1`)) {
		t.Fatalf("discarded child protocol error is invisible: %s", data)
	}
}
