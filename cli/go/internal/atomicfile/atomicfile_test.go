package atomicfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func mustWriteFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func assertContent(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s holds %d bytes %q; want %d bytes %q", path, len(got), truncate(got), len(want), truncate(want))
	}
}

func truncate(data []byte) []byte {
	if len(data) > 40 {
		return data[:40]
	}
	return data
}

// assertOnlyEntries fails when dir holds anything besides the named entries,
// which is how a leftover temp file shows up.
func assertOnlyEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, entry := range entries {
		got = append(got, entry.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s holds %v; want exactly %v", dir, got, want)
	}
}

func TestWriteCreatesFileWithContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := Write(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertContent(t, path, []byte("secret\n"))
	assertOnlyEntries(t, dir, "signing.key")
}

func TestWriteEmptyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	if err := Write(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	assertContent(t, path, nil)
}

// The hook runs where a crash would leave the old file: the complete new
// content is already in the temp file and the destination is untouched.
func TestWriteKeepsOldContentUntilTheTempFileIsComplete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	mustWriteFile(t, path, []byte("old"), 0o600)
	replacement := bytes.Repeat([]byte("new content "), 4096)

	called := false
	err := Options{Mode: 0o600, BeforeCommit: func() {
		called = true
		assertContent(t, path, []byte("old"))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 2 {
			t.Fatalf("want the destination and one temp file, found %d entries", len(entries))
		}
		for _, entry := range entries {
			if entry.Name() == "state.json" {
				continue
			}
			if !strings.HasPrefix(entry.Name(), ".tmp.") {
				t.Fatalf("temp file is named %q; want a .tmp. prefix", entry.Name())
			}
			assertContent(t, filepath.Join(dir, entry.Name()), replacement)
		}
	}}.Write(path, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("BeforeCommit was not called")
	}
	assertContent(t, path, replacement)
	assertOnlyEntries(t, dir, "state.json")
}

func TestWriteFailureBeforeRenameLeavesDestinationAndNoTempFile(t *testing.T) {
	t.Run("rename refused by a non-empty directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "occupied")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, filepath.Join(path, "keep"), []byte("kept"), 0o600)

		err := Write(path, []byte("new"), 0o600)
		if err == nil {
			t.Fatal("write over a non-empty directory succeeded")
		}
		if !strings.Contains(err.Error(), path) {
			t.Fatalf("error does not name the destination %s: %v", path, err)
		}
		assertContent(t, filepath.Join(path, "keep"), []byte("kept"))
		assertOnlyEntries(t, dir, "occupied")
	})

	t.Run("temp name already taken", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "status.json")
		mustWriteFile(t, path, []byte("old"), 0o600)
		taken := filepath.Join(dir, ".tmp.taken")
		mustWriteFile(t, taken, []byte("not ours"), 0o600)

		tempName := taken
		err := Options{Mode: 0o600, TempName: &tempName}.Write(path, []byte("new"))
		if !errors.Is(err, os.ErrExist) {
			t.Fatalf("want an already-exists error, got %v", err)
		}
		if !strings.Contains(err.Error(), path) {
			t.Fatalf("error does not name the destination %s: %v", path, err)
		}
		assertContent(t, path, []byte("old"))
		assertContent(t, taken, []byte("not ours"))
		assertOnlyEntries(t, dir, ".tmp.taken", "status.json")
	})

	t.Run("missing parent directory", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "absent", "file")
		err := Write(path, []byte("new"), 0o600)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("want a not-exist error, got %v", err)
		}
		assertOnlyEntries(t, dir)
	})
}

func TestParentModeCreatesMissingDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "file")
	if err := (Options{Mode: 0o600, ParentMode: 0o700}).Write(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	assertContent(t, path, []byte("x"))
	assertOnlyEntries(t, filepath.Dir(path), "file")
}

func TestTempNameIsChosenOnceAndReused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	var tempName string
	var seen []string
	options := Options{Mode: 0o600, TempName: &tempName, BeforeCommit: func() {
		if _, err := os.Lstat(tempName); err != nil {
			t.Fatalf("the recorded temp name is not the file being written: %v", err)
		}
		seen = append(seen, tempName)
	}}
	for _, content := range []string{"one", "two", "three"} {
		if err := options.Write(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
		assertContent(t, path, []byte(content))
		assertOnlyEntries(t, dir, "status.json")
	}
	if len(seen) != 3 || seen[0] == "" || seen[0] != seen[1] || seen[1] != seen[2] {
		t.Fatalf("temp names across writes: %q; want one name reused", seen)
	}
	if filepath.Dir(tempName) != dir {
		t.Fatalf("temp file %s is not in the destination directory %s", tempName, dir)
	}
}

func TestWriteExclusiveCreatesAbsentDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	if err := WriteExclusive(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertContent(t, path, []byte("first"))
	assertOnlyEntries(t, dir, "signing.key")
}

func TestWriteExclusiveRefusesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	mustWriteFile(t, path, []byte("first"), 0o600)

	err := WriteExclusive(path, []byte("second"), 0o600)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("want an already-exists error, got %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error does not name the destination %s: %v", path, err)
	}
	assertContent(t, path, []byte("first"))
	assertOnlyEntries(t, dir, "signing.key")
}

func TestConcurrentWritersLeaveOneCompleteContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shared")
	const writers = 8
	contents := make([][]byte, writers)
	for i := range contents {
		contents[i] = bytes.Repeat([]byte{byte('a' + i)}, 1<<20)
	}
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range contents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = Write(path, contents[i], 0o600)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, content := range contents {
		if bytes.Equal(got, content) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("destination holds %d bytes that are no single writer's content", len(got))
	}
	assertOnlyEntries(t, dir, "shared")
}

func TestConcurrentExclusiveWritersAdmitExactlyOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	const writers = 8
	contents := make([][]byte, writers)
	for i := range contents {
		contents[i] = bytes.Repeat([]byte{byte('a' + i)}, 1<<16)
	}
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range contents {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = WriteExclusive(path, contents[i], 0o600)
		}()
	}
	wg.Wait()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil && winner >= 0:
			t.Fatalf("writers %d and %d both created the destination", winner, i)
		case err == nil:
			winner = i
		case !errors.Is(err, os.ErrExist):
			t.Errorf("writer %d: want an already-exists error, got %v", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no writer created the destination")
	}
	assertContent(t, path, contents[winner])
	assertOnlyEntries(t, dir, "signing.key")
}

func TestSyncDirAcceptsAnExistingDirectory(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("syncing an existing directory: %v", err)
	}
}
