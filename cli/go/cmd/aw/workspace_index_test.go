package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestRecordMachineWorkspaceBestEffortWarnsWithoutFailing(t *testing.T) {
	oldRecord := recordMachineWorkspace
	recordMachineWorkspace = func(awconfig.MachineWorkspaceIndexEntry) error { return errors.New("disk full") }
	t.Cleanup(func() { recordMachineWorkspace = oldRecord })

	text := captureStderr(t, func() {
		recordMachineWorkspaceBestEffort(awconfig.MachineWorkspaceIndexEntry{Path: t.TempDir(), TeamID: "team:acme.com", Alias: "alice", ServerURL: "https://example"})
	})
	if !strings.Contains(text, "workspace enrollment succeeded") || !strings.Contains(text, "discovery-only") || !strings.Contains(text, "disk full") {
		t.Fatalf("warning did not explain non-authoritative cache failure:\n%s", text)
	}
}
