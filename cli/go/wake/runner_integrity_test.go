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

func TestRunnerRefusesSharedWritableCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(store.Dir(), "channel-core")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	_, err = NewChannelCoreRunner(store).bundlePath()
	if err == nil || !strings.Contains(err.Error(), "then retry aw wake.") {
		t.Fatalf("missing actionable unsafe cache refusal: %v", err)
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
