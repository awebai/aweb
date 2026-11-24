package awconfig

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// InspectWorktreeWorkspaceFrom reads the shared workspace field model for
// diagnostics. It normalizes fields and leaves semantic checks to the caller,
// so doctor can identify a broken membership without accepting it for commands.
// docs/support-tools.md:38-58 separates diagnosis from explicit repairs (:90-118).
func InspectWorktreeWorkspaceFrom(path string) (*WorktreeWorkspace, error) {
	raw, err := readInspectionYAML[worktreeWorkspaceYAML](path)
	if err != nil {
		return nil, err
	}
	workspace := raw.normalizedWorkspace()
	return &workspace, nil
}

// InspectTeamStateFrom reads the shared membership field model without
// validating the active-team relationship or creating a missing teams.yaml.
func InspectTeamStateFrom(path string) (*TeamState, error) {
	raw, err := readInspectionYAML[teamStateYAML](path)
	if err != nil {
		return nil, err
	}
	state := raw.normalizedTeamState()
	for _, membership := range state.Memberships {
		if err := membership.validateTeamKey(); err != nil {
			return nil, err
		}
	}
	return &state, nil
}

func readInspectionYAML[T any](path string) (T, error) {
	var raw T
	data, err := os.ReadFile(path)
	if err != nil {
		return raw, err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return raw, fmt.Errorf("inspect %s: %w. Fix the YAML syntax and use only supported fields, then rerun aw doctor.", path, err)
	}
	return raw, nil
}
