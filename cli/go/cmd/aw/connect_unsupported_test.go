package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnectBootstrapUnsupported(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "aw")
	buildAwBinary(t, ctx, bin)
	command := exec.CommandContext(ctx, bin, "connect", "--bootstrap-token", "obsolete-token",
		"--address", "example.test/agent", "--mock-url", "http://127.0.0.1:1")
	command.Dir = dir
	command.Env = idCreateCommandEnv(dir)
	out, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("obsolete bootstrap-token command succeeded")
	}
	want := "Bootstrap tokens are not supported; use a setup key from the dashboard or run `aw init --join-from`."
	if !strings.Contains(string(out), want) {
		t.Fatalf("missing actionable bootstrap-token refusal %q in:\n%s", want, out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("unsupported bootstrap created identity state: %v", err)
	}
}
