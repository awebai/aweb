package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
)

var recordMachineWorkspace = awconfig.RecordMachineWorkspace

func recordMachineWorkspaceBestEffort(entry awconfig.MachineWorkspaceIndexEntry) {
	entry.Path = strings.TrimSpace(entry.Path)
	entry.TeamID = strings.TrimSpace(entry.TeamID)
	entry.Alias = strings.TrimSpace(entry.Alias)
	entry.ServerURL = strings.TrimSpace(entry.ServerURL)
	if entry.Path == "" || entry.TeamID == "" {
		return
	}
	if err := recordMachineWorkspace(entry); err != nil {
		fmt.Fprintf(os.Stderr,
			"Warning: workspace enrollment succeeded, but aw could not update the local discovery index at ~/.config/aw/workspaces.yaml: %v\n"+
				"The index is discovery-only; authority still comes from workspace.yaml, teams.yaml, and certificates. To repair chooser discovery, make ~/.config/aw writable and rerun the successful connect/init command.\n",
			err,
		)
	}
}
