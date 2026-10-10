package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIKeyPartialQuarantinePreservesEachFile(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "selected", ".aw")
	if err := os.MkdirAll(selected, 0700); err != nil {
		t.Fatal(err)
	}
	path := apiKeyPartialInitPath(root, selected)
	var previous string
	for _, content := range []string{"first synthetic material", "second synthetic material"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		rejected, err := quarantineAPIKeyPartialInit(root, selected)
		if err != nil {
			t.Fatal(err)
		}
		if rejected == previous || filepath.Dir(rejected) != selected || !strings.HasSuffix(rejected, ".rejected") {
			t.Fatalf("bad destination %q", rejected)
		}
		data, err := os.ReadFile(rejected)
		if err != nil || string(data) != content {
			t.Fatal("quarantine changed contents")
		}
		if previous != "" {
			data, err := os.ReadFile(previous)
			if err != nil || string(data) != "first synthetic material" {
				t.Fatal("overwrote prior quarantine")
			}
		}
		previous = rejected
	}
	// Refuse even when a new active partial coexists; never implicitly select it.
	if err := os.WriteFile(path, []byte("unselected material"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := refuseRejectedAPIKeyPartialInit(path); err == nil || !strings.Contains(err.Error(), "partial_init_reconciliation_required") {
		t.Fatalf("missing reconciliation refusal: %v", err)
	}
}

func TestAPIKeyPartialQuarantineFailurePreservesSource(t *testing.T) {
	root := t.TempDir()
	path := apiKeyPartialInitPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "original")
	if err := os.WriteFile(target, []byte("synthetic private material"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantineAPIKeyPartialInit(root); err == nil {
		t.Fatal("symlink quarantine must refuse")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "synthetic private material" {
		t.Fatal("failed quarantine changed source")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("failed quarantine removed original entry")
	}
	files, err := filepath.Glob(path + ".*.rejected")
	if err != nil || len(files) != 0 {
		t.Fatal("failed quarantine left a false rejected receipt")
	}
}
