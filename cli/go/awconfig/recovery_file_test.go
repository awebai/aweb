package awconfig

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRecoveryFilePreservesBytesAndUsesPrivateAtomicStorage(t *testing.T) {
	home := IdentityHome{Root: filepath.Join(t.TempDir(), "principal")}
	record := RecoveryFile{Home: home, Name: "partial-init.yaml"}
	original := []byte("version: 1\nresponse_json: '{\"api_key\":\"fixture\"}'\n")
	if err := record.Write(original); err != nil {
		t.Fatal(err)
	}
	path, err := record.Path()
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for file, want := range map[string]os.FileMode{path: 0o600, home.Root: 0o700} {
			info, err := os.Stat(file)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != want {
				t.Fatalf("mode %s=%o want=%o", file, info.Mode().Perm(), want)
			}
		}
	}
	loaded, err := record.Read()
	if err != nil || !bytes.Equal(loaded, original) {
		t.Fatalf("record bytes changed: %v", err)
	}
	if bounded, err := record.ReadBounded(int64(len(original))); err != nil || !bytes.Equal(bounded, original) {
		t.Fatalf("bounded record read: %v", err)
	}
	if _, err := record.ReadBounded(int64(len(original) - 1)); err == nil {
		t.Fatal("oversized recovery was accepted")
	}
	if err := record.Write([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	loaded, err = record.Read()
	if err != nil || string(loaded) != "replacement" {
		t.Fatalf("record replacement: %v", err)
	}
	if err := record.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := record.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := record.Read(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing record: %v", err)
	}
}

func TestRecoveryFileRequiresExplicitHomeAndRefusesSymlinkRecords(t *testing.T) {
	if _, err := (RecoveryFile{Name: "attempt.json"}).Path(); err == nil {
		t.Fatal("missing home fell back to cwd")
	}
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	home := IdentityHome{Root: t.TempDir()}
	target := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home.Root, "attempt.json")); err != nil {
		t.Fatal(err)
	}
	record := RecoveryFile{Home: home, Name: "attempt.json"}
	if err := record.Write([]byte("replacement")); err == nil {
		t.Fatal("recovery followed or replaced an unexpected symlink")
	}
	if _, err := record.Read(); err == nil {
		t.Fatal("recovery read through an unexpected symlink")
	}
	raw, err := os.ReadFile(target)
	if err != nil || string(raw) != "unchanged" {
		t.Fatalf("unrelated target changed: %v", err)
	}
}
