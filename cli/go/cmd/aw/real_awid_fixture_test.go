package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realAWIDFixture runs the repository's real service with disposable storage.
// It is test-only; neither a response mock nor a production registry fallback.
func realAWIDFixture(t *testing.T) string {
	t.Helper()
	script, err := filepath.Abs("../../../../scripts/test-egress/awid_fixture.py")
	if err != nil {
		t.Fatal(err)
	}
	// Tests isolate HOME, but uv must keep the parent's populated offline cache.
	cache := exec.Command("uv", "cache", "dir")
	cache.Env = awTestBinary.env
	cache.Dir = awTestBinary.sourceDir
	cacheDir, err := cache.Output()
	if err != nil {
		t.Fatalf("resolve parent uv cache: %v", err)
	}
	cmd := exec.Command("python3", script)
	cmd.Env = append(os.Environ(), "UV_CACHE_DIR="+strings.TrimSpace(string(cacheDir)))
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("real AWID fixture: %v", err)
		}
	})
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("real AWID fixture failed before publishing its loopback URL")
	}
	return scanner.Text()
}
