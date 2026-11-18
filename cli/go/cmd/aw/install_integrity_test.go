package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedPluginDispatchChecksInstalledBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, pluginExecutableName("demo"))
	if err := os.WriteFile(path, []byte("original"), 0700); err != nil {
		t.Fatal(err)
	}
	digest, err := installPluginSource(path, filepath.Join(t.TempDir(), "copy"))
	if err != nil {
		t.Fatal(err)
	}
	if err := savePluginProvenance(pluginProvenancePath(dir, "demo"), &pluginProvenance{Digest: digest}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := resolveTrustedExternalPluginInDir(externalPluginLocation{Directory: dir, Name: "demo"}); err != nil || !ok {
		t.Fatalf("valid install refused: %v", err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0700); err != nil {
		t.Fatal(err)
	}
	_, _, err = resolveTrustedExternalPluginInDir(externalPluginLocation{Directory: dir, Name: "demo"})
	if err == nil || !strings.Contains(err.Error(), "Reinstall it with aw plugin remove demo followed by aw plugin install") {
		t.Fatalf("missing actionable integrity refusal: %v", err)
	}
}

func TestPluginDispatchRefusesChangedManagedExecutable(t *testing.T) {
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
	run := func(arguments ...string) (string, error) {
		command := exec.CommandContext(ctx, binary, arguments...)
		command.Dir = directory
		command.Env = append(testCommandEnv(home), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
		output, err := command.CombinedOutput()
		return string(output), err
	}
	if output, err := run("plugin", "install", source); err != nil {
		t.Fatalf("install: %v %s", err, output)
	}
	if output, err := run("integrity-demo"); err != nil || !strings.Contains(output, "managed-ok") {
		t.Fatalf("valid plugin: %v %s", err, output)
	}
	installed := filepath.Join(home, ".aw", "plugins", "aw-integrity-demo")
	if err := os.WriteFile(installed, []byte("#!/bin/sh\nprintf 'changed-ran'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	output, err := run("integrity-demo")
	if err == nil || strings.Contains(output, "changed-ran") || !strings.Contains(output, "Reinstall it with aw plugin remove integrity-demo followed by aw plugin install") {
		t.Fatalf("modified plugin was not refused before execution: %v %s", err, output)
	}
	// An explicitly placed legacy development executable has no managed digest.
	unmanaged := filepath.Join(home, ".aw", "plugins", "aw-local-demo")
	if err := os.WriteFile(unmanaged, []byte("#!/bin/sh\nprintf 'legacy-ok'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if output, err := run("local-demo"); err != nil || !strings.Contains(output, "legacy-ok") {
		t.Fatalf("legacy development plugin: %v %s", err, output)
	}
}
