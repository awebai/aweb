package wake

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunnerNeverReadsOrRewritesLegacyCache(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(store.Dir(), "channel-core")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "user-file")
	if err := os.WriteFile(outside, []byte("untrusted legacy bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "runner.mjs")
	if err := os.Symlink(outside, cache); err != nil {
		t.Fatal(err)
	}
	stamp := filepath.Join(root, "runner.sha256")
	if err := os.WriteFile(stamp, []byte("legacy"), 0o600); err != nil {
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
	expected, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(snapshot.Path)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("execution trusted legacy cache: %v", err)
	}
	if _, err := os.Lstat(stamp); !os.IsNotExist(err) {
		t.Fatalf("legacy stamp survives downgrade: %v", err)
	}
	info, err := os.Lstat(cache)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("unused cache was rewritten: %v", err)
	}
	got, err = os.ReadFile(outside)
	if err != nil || string(got) != "untrusted legacy bytes" {
		t.Fatalf("changed cache symlink target: %v", err)
	}
}

func TestRunnerDoesNotCreateUnusedCache(t *testing.T) {
	store, err := NewStore(t.TempDir())
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
	if _, err := os.Stat(filepath.Join(store.Dir(), "channel-core")); !os.IsNotExist(err) {
		t.Fatalf("created unused persistent cache: %v", err)
	}
}

func TestRunnerExecutesPrivateSnapshotOfEmbeddedBytes(t *testing.T) {
	store, err := NewStore(t.TempDir())
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
	if strings.HasPrefix(snapshot.Path, store.Dir()+string(os.PathSeparator)) {
		t.Fatal("execution snapshot remains in shared state")
	}
	got, err := os.ReadFile(snapshot.Path)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, expected) {
		t.Fatal("execution bytes differ from embedded bundle")
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
