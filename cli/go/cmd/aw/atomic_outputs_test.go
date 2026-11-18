package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/a2a"
)

func TestHolderExportReplacesDestinationWithoutFollowingSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "previous.json")
	path := filepath.Join(dir, "export.json")
	if err := os.WriteFile(target, []byte("previous complete content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeHolderExport(path, testHolderExport()); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "previous complete content" {
		t.Fatalf("export changed the symlink target: %q, %v", data, err)
	}
	if _, err := readHolderExport(path); err != nil {
		t.Fatalf("replacement is not a complete export: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
		t.Fatalf("export mode = %v, want regular 0644", info.Mode())
	}
}

func TestTaskTokenReplacesDestinationWithoutFollowingSymlink(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir(".aw", 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(".aw", "previous.yaml")
	path := filepath.Join(".aw", "a2a-credentials.yaml")
	if err := os.WriteFile(target, []byte("credentials: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("previous.yaml", path); err != nil {
		t.Fatal(err)
	}
	saveA2ATaskTokenBestEffort("https://gateway.example/rpc", a2a.Task{
		ID: "task-1", Metadata: map[string]any{"task_bearer_token": "test-token"},
	})
	if data, err := os.ReadFile(target); err != nil || string(data) != "credentials: []\n" {
		t.Fatalf("task token changed the symlink target: %q, %v", data, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("task token mode = %v, want regular 0600", info.Mode())
	}
	if got := loadA2ATaskTokenBestEffortForDir(".", "https://gateway.example/card", "https://gateway.example/rpc", "task-1"); got != "test-token" {
		t.Fatalf("replacement token = %q, want test-token", got)
	}
}

func TestTaskTokenPreservesUnreadableCredentialsAndExplainsRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	const invalid = "credentials: [broken"
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := persistA2ATaskToken(path, a2aCredentialEntry{TaskID: "task-1", TaskToken: "test-token"}); err == nil {
		t.Fatal("invalid credentials were silently replaced")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != invalid {
		t.Fatalf("invalid credentials changed: %q, %v", data, err)
	}
	want := "Warning: could not persist task token: test failure. Keep the task token from this response and repair `.aw/a2a-credentials.yaml` before polling."
	if got := formatTaskTokenPersistenceError(errors.New("test failure")); got != want {
		t.Fatalf("recovery text = %q, want %q", got, want)
	}
}
