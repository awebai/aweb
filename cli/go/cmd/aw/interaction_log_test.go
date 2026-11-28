package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestAppendInteractionLogForDirDedupesByMessageID(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}

	entry := &InteractionEntry{
		Timestamp: "2026-03-22T10:00:00Z",
		Kind:      interactionKindMailIn,
		MessageID: "m-1",
		From:      "rose",
		Text:      "please review the patch",
	}
	appendInteractionLogForDir(tmp, localLogPolicy{}, entry)
	appendInteractionLogForDir(tmp, localLogPolicy{}, entry)

	entries, err := readInteractionLog(interactionLogPath(tmp))
	if err != nil {
		t.Fatalf("readInteractionLog: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestInteractionLogUsesInstanceRootFromSubdirectoryDespiteIdentityHome(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "nested", "work")
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	externalIdentityHome := filepath.Join(t.TempDir(), "identity")
	t.Setenv(awconfig.IdentityHomeEnv, externalIdentityHome)
	want := filepath.Join(root, ".aw", interactionLogFileName)
	if got := interactionLogPath(subdir); got != want {
		t.Fatalf("interaction log path=%q want instance root %q", got, want)
	}
}

// readInteractionLog returns the plaintext entries of the log; sealed lines
// are for the owner and are skipped.
func readInteractionLog(path string) ([]InteractionEntry, error) {
	lines, err := readLocalLogLines(path, 0)
	if err != nil {
		return nil, err
	}
	var entries []InteractionEntry
	for _, line := range lines {
		if isSealedLogLine(line) {
			continue
		}
		var entry InteractionEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
