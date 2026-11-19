package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeHookInstallPreservesUserBytes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".claude")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.json")
	original := []byte("{\n  \"number\": 9007199254740993, \"escaped\": \"\\u0041\",\n  \"hooks\": { \"PreToolUse\": [ ] }\n}\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	result := SetupClaudeHooks(root, skipHookConfirmation)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"number": 9007199254740993`, `"escaped": "\u0041"`, `"PreToolUse": [ ]`} {
		if !bytes.Contains(got, []byte(fragment)) {
			t.Errorf("lost user bytes %s: %s", fragment, got)
		}
	}
	beforeSecond := append([]byte(nil), got...)
	result = SetupClaudeHooks(root, skipHookConfirmation)
	if !result.AlreadyExists || result.Error != nil {
		t.Fatalf("second install: %+v", result)
	}
	got = readInstallFile(t, path)
	if !bytes.Equal(got, beforeSecond) {
		t.Fatal("second install changed settings")
	}
	cleanup := CleanupClaudeNotifyHook(root)
	if cleanup.Error != nil || cleanup.Removed != 1 {
		t.Fatalf("cleanup: %+v", cleanup)
	}
	got = readInstallFile(t, path)
	for _, fragment := range []string{`"number": 9007199254740993`, `"escaped": "\u0041"`, `"PreToolUse": [ ]`} {
		if !bytes.Contains(got, []byte(fragment)) {
			t.Errorf("cleanup lost user bytes %s: %s", fragment, got)
		}
	}
}

func TestNotifyCooldownIsPrivateState(t *testing.T) {
	dir := t.TempDir()
	stamp := notifyStampPath(notifyScope{Identity: "agent", StateDirectory: dir})
	if !strings.HasPrefix(stamp, dir+string(os.PathSeparator)) {
		t.Fatalf("stamp outside private config: %s", stamp)
	}
	touchNotifyStamp(stamp)
	info, err := os.Stat(stamp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("stamp mode: %o", info.Mode().Perm())
	}
}

func TestClaudeInstallRefusesAmbiguousAndPreservesCustomHooks(t *testing.T) {
	for _, original := range []string{`{"hooks":{},"hooks":{}}`, `{"hooks":[]}`, `{"hooks":{"PostToolUse":{}}}`} {
		root := t.TempDir()
		path := writeNotifySettings(t, root, original)
		result := SetupClaudeHooks(root, skipHookConfirmation)
		if result.Error == nil || !strings.Contains(result.Error.Error(), "Save the file and retry the command.") {
			t.Fatalf("missing actionable refusal: %+v", result)
		}
		got := readInstallFile(t, path)
		if string(got) != original {
			t.Fatal("changed refused settings")
		}
	}
	root := t.TempDir()
	original := `{"hooks":{"PostToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"aw notify"}]}]}}`
	path := writeNotifySettings(t, root, original)
	result := SetupClaudeHooks(root, skipHookConfirmation)
	if result.Error != nil || !result.Updated {
		t.Fatalf("install: %+v", result)
	}
	resultCleanup := CleanupClaudeNotifyHook(root)
	if resultCleanup.Error != nil || resultCleanup.Removed != 1 {
		t.Fatalf("cleanup: %+v", resultCleanup)
	}
	got := readInstallFile(t, path)
	if !bytes.Contains(got, []byte(`{"matcher":"Read","hooks":[{"type":"command","command":"aw notify"}]}`)) {
		t.Fatalf("removed custom matcher: %s", got)
	}
}

func TestClaudeLegacyMigrationStillAsksForConsent(t *testing.T) {
	root := t.TempDir()
	original := `{"hooks":{"PostToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"bdh :notify"}]}]}}`
	path := writeNotifySettings(t, root, original)
	input, err := os.CreateTemp(t.TempDir(), "answer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := input.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = previous })
	result := SetupClaudeHooks(root, requireHookConfirmation)
	if result.Error != nil || !result.Skipped {
		t.Fatalf("migration did not respect consent: %+v", result)
	}
	got := readInstallFile(t, path)
	if string(got) != original {
		t.Fatal("changed legacy hook after refusal")
	}
}

func readInstallFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
