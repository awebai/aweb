package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readFileBounded is the shared bound behind the local file loaders (--body-file,
// --data-file, --playbook-file, --bundle-file, and the re-read plugin manifest).
func TestReadFileBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), 100), 0o600); err != nil {
		t.Fatal(err)
	}

	// Exactly max is accepted, not truncated.
	got, err := readFileBounded(path, 100)
	if err != nil || len(got) != 100 {
		t.Fatalf("exact-size read: err=%v len=%d", err, len(got))
	}

	// One byte over max is rejected, never returning a truncated prefix.
	if _, err := readFileBounded(path, 99); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversize read should be rejected, got: %v", err)
	}

	// A missing file still surfaces its error.
	if _, err := readFileBounded(filepath.Join(dir, "absent"), 100); err == nil {
		t.Fatal("missing file should error")
	}
}

// F2: the installed manifest is re-read from local disk on every invocation; a
// tampered or oversized manifest must not be buffered whole.
func TestExecuteInstalledManifestToolRejectsOversizeManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("AW_HOME", home)
	prev := maxManifestBytes
	maxManifestBytes = 1024
	t.Cleanup(func() { maxManifestBytes = prev })

	manifestPath := manifestPluginManifestPath(filepath.Join(home, "plugins"), "folio")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatal(err)
	}
	oversize := append([]byte(`{"name":"folio","junk":"`), bytes.Repeat([]byte("a"), int(maxManifestBytes)+4096)...)
	oversize = append(oversize, []byte(`"}`)...)
	if err := os.WriteFile(manifestPath, oversize, 0o600); err != nil {
		t.Fatal(err)
	}

	_, exists, err := executeInstalledManifestTool("folio", []string{"--help"})
	if err == nil {
		t.Fatal("expected oversize manifest to be rejected")
	}
	if !exists {
		t.Fatal("an oversize but present manifest must be reported as present (exists=true)")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected a size-limit rejection, got: %v", err)
	}
}

// F1: the id-request --body-file is local user input, but an oversized file must
// still be rejected rather than buffered whole.
func TestLoadOptionalRequestBodyRejectsOversizeBodyFile(t *testing.T) {
	prev := maxBodyFileBytes
	maxBodyFileBytes = 1024
	t.Cleanup(func() { maxBodyFileBytes = prev })

	path := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(maxBodyFileBytes)+4096), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadOptionalRequestBody("", path); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversize --body-file should be rejected, got: %v", err)
	}
}

// stdin: a piped --bundle-file "-" is bounded like a file so an unbounded pipe
// cannot exhaust memory.
func TestResolveRolesBundleRejectsOversizeStdin(t *testing.T) {
	prev := maxBodyFileBytes
	maxBodyFileBytes = 1024
	t.Cleanup(func() { maxBodyFileBytes = prev })

	oversize := strings.Repeat("a", int(maxBodyFileBytes)+4096)
	if _, err := resolveRolesBundle(strings.NewReader(oversize), "", "-"); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversize piped --bundle-file should be rejected, got: %v", err)
	}
}
