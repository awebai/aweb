package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPluginExternalDispatchUsesTrustedDirOnlyAndEnvContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	home := filepath.Join(tmp, "home")
	pluginsDir := filepath.Join(home, ".aw", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	trustedPlugin := filepath.Join(pluginsDir, "aw-hello")
	trustedScript := `#!/bin/sh
printf 'trusted args=%s\n' "$*"
printf 'AW_HELPER=%s\n' "$AW_HELPER"
printf 'AW_HOME=%s\n' "$AW_HOME"
printf 'AW_TEAM=%s\n' "$AW_TEAM"
printf 'AW_SERVER=%s\n' "$AW_SERVER"
printf 'AW_DID=%s\n' "$AW_DID"
`
	if err := os.WriteFile(trustedPlugin, []byte(trustedScript), 0o755); err != nil {
		t.Fatal(err)
	}

	pathDir := filepath.Join(tmp, "pathbin")
	if err := os.MkdirAll(pathDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pathOnlyPlugin := filepath.Join(pathDir, "aw-pathonly")
	if err := os.WriteFile(pathOnlyPlugin, []byte("#!/bin/sh\necho path-plugin-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	runTrusted := exec.CommandContext(ctx, bin, "hello", "one", "two")
	runTrusted.Dir = tmp
	runTrusted.Env = append(os.Environ(), "HOME="+home, "PATH="+pathDir+string(os.PathListSeparator)+os.Getenv("PATH"), "AW_NO_UPDATE_CHECK=1")
	trustedOut, err := runTrusted.CombinedOutput()
	if err != nil {
		t.Fatalf("trusted plugin dispatch failed: %v\n%s", err, string(trustedOut))
	}
	trustedText := string(trustedOut)
	for _, want := range []string{
		"trusted args=one two",
		"AW_HELPER=" + bin,
		"AW_HOME=" + filepath.Join(home, ".aw"),
		"AW_TEAM=",
		"AW_SERVER=",
		"AW_DID=",
	} {
		if !strings.Contains(trustedText, want) {
			t.Fatalf("trusted plugin output missing %q:\n%s", want, trustedText)
		}
	}

	runPathOnly := exec.CommandContext(ctx, bin, "pathonly")
	runPathOnly.Dir = tmp
	runPathOnly.Env = append(os.Environ(), "HOME="+home, "PATH="+pathDir+string(os.PathListSeparator)+os.Getenv("PATH"), "AW_NO_UPDATE_CHECK=1")
	pathOut, err := runPathOnly.CombinedOutput()
	if err == nil {
		t.Fatalf("PATH-only plugin unexpectedly ran:\n%s", string(pathOut))
	}
	if strings.Contains(string(pathOut), "path-plugin-ran") {
		t.Fatalf("external plugin resolved from PATH, want trusted dir only:\n%s", string(pathOut))
	}
	if !strings.Contains(string(pathOut), `unknown command "pathonly" for "aw"`) {
		t.Fatalf("PATH-only plugin should fall through to Cobra unknown command:\n%s", string(pathOut))
	}
}

func TestPluginManagementInstallListRemoveAndRejectBuiltins(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")

	source := filepath.Join(tmp, "aw-foo")
	if err := os.WriteFile(source, []byte("#!/bin/sh\necho foo\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	install := exec.CommandContext(ctx, bin, "plugin", "install", source)
	install.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := install.CombinedOutput(); err != nil {
		t.Fatalf("plugin install failed: %v\n%s", err, string(out))
	}
	installed := filepath.Join(home, ".aw", "plugins", "aw-foo")
	if info, err := os.Stat(installed); err != nil || info.Mode()&0o111 == 0 {
		t.Fatalf("installed plugin missing or not executable: info=%v err=%v", info, err)
	}

	installAgain := exec.CommandContext(ctx, bin, "plugin", "install", source)
	installAgain.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := installAgain.CombinedOutput(); err == nil || !strings.Contains(string(out), "already installed") {
		t.Fatalf("second install should reject name collision, err=%v out=%s", err, string(out))
	}

	list := exec.CommandContext(ctx, bin, "--json", "plugin", "list")
	list.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	listOut, err := list.CombinedOutput()
	if err != nil {
		t.Fatalf("plugin list failed: %v\n%s", err, string(listOut))
	}
	var listed struct {
		Plugins []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(extractJSON(t, listOut), &listed); err != nil {
		t.Fatalf("decode plugin list: %v\n%s", err, string(listOut))
	}
	if len(listed.Plugins) != 1 || listed.Plugins[0].Name != "foo" || listed.Plugins[0].Path != installed {
		t.Fatalf("unexpected plugin list: %#v", listed.Plugins)
	}

	remove := exec.CommandContext(ctx, bin, "plugin", "remove", "foo")
	remove.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	if out, err := remove.CombinedOutput(); err != nil {
		t.Fatalf("plugin remove failed: %v\n%s", err, string(out))
	}
	if _, err := os.Stat(installed); !os.IsNotExist(err) {
		t.Fatalf("plugin still exists after remove: %v", err)
	}

	for _, name := range []string{"aw-id", "aw-introspect"} {
		reservedSource := filepath.Join(tmp, name)
		if err := os.WriteFile(reservedSource, []byte("#!/bin/sh\necho reserved\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, bin, "plugin", "install", reservedSource)
		cmd.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("install of reserved plugin %s unexpectedly succeeded:\n%s", name, string(out))
		}
		if !strings.Contains(string(out), "reserved built-in command or alias") {
			t.Fatalf("reserved plugin error missing reason for %s:\n%s", name, string(out))
		}
	}
}

func TestPluginBuiltInCommandWinsOverTrustedPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script plugin fixture is unix-only")
	}
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(tmp, "home")
	pluginsDir := filepath.Join(home, ".aw", "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginsDir, "aw-version"), []byte("#!/bin/sh\necho plugin-version-ran\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(ctx, bin, "version")
	cmd.Env = append(os.Environ(), "HOME="+home, "AW_NO_UPDATE_CHECK=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw version failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if strings.Contains(text, "plugin-version-ran") {
		t.Fatalf("built-in version command was shadowed by plugin:\n%s", text)
	}
	if !strings.Contains(text, "aw dev") {
		t.Fatalf("expected built-in version output:\n%s", text)
	}
}
