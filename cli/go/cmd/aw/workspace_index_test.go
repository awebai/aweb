package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestRecordMachineWorkspaceBestEffortWarnsWithoutFailing(t *testing.T) {
	oldRecord := recordMachineWorkspace
	recordMachineWorkspace = func(awconfig.MachineWorkspaceIndexEntry) error { return errors.New("disk full") }
	t.Cleanup(func() { recordMachineWorkspace = oldRecord })

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	recordMachineWorkspaceBestEffort(awconfig.MachineWorkspaceIndexEntry{Path: t.TempDir(), TeamID: "team:acme.com", Alias: "alice", ServerURL: "https://example"})
	_ = w.Close()
	out, _ := io.ReadAll(r)
	text := string(out)
	if !strings.Contains(text, "workspace enrollment succeeded") || !strings.Contains(text, "discovery-only") || !strings.Contains(text, "disk full") {
		t.Fatalf("warning did not explain non-authoritative cache failure:\n%s", text)
	}
}
