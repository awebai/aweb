package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// The host owner's activity opt-in (docs/agent-activity.md, "Host-owner
// opt-in"): one file in the identity root the emitter signs with. Publishing
// is on only for exactly `activity: status`; a missing, unreadable or
// different file is off. On an OATS host the provider rewrites the file at
// every launch, so a change made here lasts until the next launch there.

const activitySettingFile = "activity.yaml"

var activityCmd = &cobra.Command{
	Use:     "activity",
	Short:   "Turn this agent's live activity publishing on or off",
	GroupID: groupCoordination,
}

func init() {
	enable := &cobra.Command{Use: "enable", Short: "Publish this agent's live activity to the chats it serves", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runActivitySet(cmd, "status") }}
	disable := &cobra.Command{Use: "disable", Short: "Stop publishing this agent's live activity", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runActivitySet(cmd, "off") }}
	show := &cobra.Command{Use: "show", Short: "Show whether this agent publishes live activity", Args: cobra.NoArgs, RunE: runActivityShow}
	activityCmd.AddCommand(enable, disable, show)
	rootCmd.AddCommand(activityCmd)
}

// activityIdentityRoot is the identity root the emitter signs with: an
// identity home holding a signing key, or a grant home.
func activityIdentityRoot() (string, error) {
	wd, _ := os.Getwd()
	home, err := identityHomeForDir(wd)
	if err != nil {
		return "", err
	}
	for _, marker := range []string{"signing.key", "grant.yaml"} {
		if info, statErr := os.Stat(filepath.Join(home.Root, marker)); statErr == nil && info.Mode().IsRegular() {
			return home.Root, nil
		}
	}
	return "", fmt.Errorf("no aweb identity at %s: it has no signing.key or grant.yaml", home.Root)
}

// readActivitySetting applies the emitters' rule: exactly `activity: status` is on.
func readActivitySetting(root string) string {
	data, err := os.ReadFile(filepath.Join(root, activitySettingFile))
	if err != nil {
		return "off"
	}
	var parsed map[string]any
	if yaml.Unmarshal(data, &parsed) != nil {
		return "off"
	}
	if value, ok := parsed["activity"].(string); ok && value == "status" {
		return "status"
	}
	return "off"
}

func writeActivitySetting(root, value string) error {
	tmp, err := os.CreateTemp(root, ".activity-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.WriteString("activity: " + value + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(root, activitySettingFile))
}

type activitySettingOutput struct {
	Activity string `json:"activity"`
	Path     string `json:"path"`
}

func formatActivitySetting(v any) string {
	out := v.(activitySettingOutput)
	return fmt.Sprintf("activity: %s (%s)\n", out.Activity, out.Path)
}

func runActivitySet(cmd *cobra.Command, value string) error {
	root, err := activityIdentityRoot()
	if err != nil {
		return err
	}
	if err = writeActivitySetting(root, value); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Join(root, activitySettingFile), err)
	}
	return writeOutput(cmd.OutOrStdout(), activitySettingOutput{Activity: readActivitySetting(root), Path: filepath.Join(root, activitySettingFile)}, formatActivitySetting)
}

func runActivityShow(cmd *cobra.Command, _ []string) error {
	root, err := activityIdentityRoot()
	if err != nil {
		return err
	}
	return writeOutput(cmd.OutOrStdout(), activitySettingOutput{Activity: readActivitySetting(root), Path: filepath.Join(root, activitySettingFile)}, formatActivitySetting)
}
