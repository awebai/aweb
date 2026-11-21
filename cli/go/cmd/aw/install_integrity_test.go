package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPluginDispatchWarnsAndRunsChangedManagedExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell executable fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	directory := t.TempDir()
	binary := filepath.Join(directory, "aw")
	buildAwBinary(t, ctx, binary)
	home := filepath.Join(directory, "home")
	source := filepath.Join(directory, "aw-integrity-demo")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nprintf 'managed-ok'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	run := func(arguments ...string) (string, string, error) {
		command := exec.CommandContext(ctx, binary, arguments...)
		command.Dir = directory
		command.Env = append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		err := command.Run()
		return stdout.String(), stderr.String(), err
	}
	if output, stderr, err := run("plugin", "install", source); err != nil {
		t.Fatalf("install: %v %s %s", err, output, stderr)
	}
	if output, stderr, err := run("integrity-demo"); err != nil || output != "managed-ok" || stderr != "" {
		t.Fatalf("valid plugin: %v stdout=%q stderr=%q", err, output, stderr)
	}
	installed := filepath.Join(home, ".aw", "plugins", "aw-integrity-demo")
	if err := os.WriteFile(installed, []byte("#!/bin/sh\nprintf 'changed-ran'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	output, stderr, err := run("integrity-demo")
	if err != nil || output != "changed-ran" || !strings.Contains(stderr, "Warning: plugin \"integrity-demo\" no longer matches its installed digest") || !strings.Contains(stderr, "Reinstall it with aw plugin remove integrity-demo followed by aw plugin install") {
		t.Fatalf("modified plugin did not run with an actionable warning: %v stdout=%q stderr=%q", err, output, stderr)
	}
	// An explicitly placed legacy development executable has no managed digest.
	unmanaged := filepath.Join(home, ".aw", "plugins", "aw-local-demo")
	if err := os.WriteFile(unmanaged, []byte("#!/bin/sh\nprintf 'legacy-ok'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if output, stderr, err := run("local-demo"); err != nil || output != "legacy-ok" || stderr != "" {
		t.Fatalf("locally installed plugin: %v stdout=%q stderr=%q", err, output, stderr)
	}
}
