package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The package's tests run the same way on a developer's host as in the gate.
// These pin the harness properties that make that true.

func TestHarnessTempDirectoriesAreCanonical(t *testing.T) {
	// aw refuses identity homes, locks and custody paths under a symlinked
	// parent, and macOS's /tmp and /var are symlinks.
	dir := t.TempDir()
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dir != canonical {
		t.Fatalf("t.TempDir() = %q, which resolves to %q", dir, canonical)
	}
	if env := os.Getenv("TMPDIR"); env != "" {
		if resolved, err := filepath.EvalSymlinks(env); err != nil || resolved != filepath.Clean(env) {
			t.Fatalf("TMPDIR %q is not canonical (%q, %v)", env, resolved, err)
		}
	}
}

func TestHarnessScrubsAgentRuntimeMarkers(t *testing.T) {
	// The agent running the tests must not decide what a human-only command
	// does under test; a test that wants a marker sets it itself.
	for _, name := range agentRuntimeMarkers {
		if value, ok := os.LookupEnv(name); ok {
			t.Errorf("%s=%q leaked into the test process", name, value)
		}
		for _, entry := range awTestBinary.env {
			if strings.HasPrefix(entry, name+"=") {
				t.Errorf("%s leaked into the environment of child aw processes", name)
			}
		}
	}
}

func TestRealAWIDFixtureRunsOnTheGatesPython(t *testing.T) {
	// The fixture runs AWID with uv in the awid project. Without a pin, uv picks
	// the host's newest Python, which the locked dependencies may not build for.
	root := filepath.Join(awTestBinary.sourceDir, "..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "candidate-gate", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	gate := regexp.MustCompile(`(?m)^FROM python:(\d+\.\d+)`).FindSubmatch(dockerfile)
	if gate == nil {
		t.Fatal("candidate-gate/Dockerfile names no python base image")
	}
	pin, err := os.ReadFile(filepath.Join(root, "awid", ".python-version"))
	if err != nil {
		t.Fatalf("awid has no .python-version pin: %v", err)
	}
	if got := strings.TrimSpace(string(pin)); got != string(gate[1]) {
		t.Fatalf("awid/.python-version = %q, the gate runs Python %s", got, gate[1])
	}
	found := exec.Command("uv", "python", "find", "--project", filepath.Join(root, "awid"))
	found.Env = awTestBinary.env
	out, err := found.Output()
	if err != nil {
		t.Fatalf("uv cannot find the pinned Python for awid: %v", err)
	}
	version, err := exec.Command(strings.TrimSpace(string(out)), "-c",
		"import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(version)); got != string(gate[1]) {
		t.Fatalf("uv resolves Python %s for awid, the gate runs %s", got, gate[1])
	}
}
