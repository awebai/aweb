package main

import (
	"io"

	"github.com/spf13/cobra"
)

// Codex hosts that ran the activity hook installer still run
// `aw activity hook` on every turn event (UserPromptSubmit, PreToolUse,
// PostToolUse, PermissionRequest, Stop, Interrupt, SessionEnd). aweb has no
// activity route, so the command reads the event and discards it, writing
// nothing and exiting 0, until those hosts delete the entries from
// $CODEX_HOME/hooks.json. It reads no identity state.
var activityCmd = &cobra.Command{Use: "activity", Hidden: true}

var activityHookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Discard a Codex hook event from stdin",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, _ = io.Copy(io.Discard, cmd.InOrStdin())
		return nil
	},
}

func init() {
	activityCmd.AddCommand(activityHookCmd)
	rootCmd.AddCommand(activityCmd)
	offlineCommands[activityHookCmd] = struct{}{}
	identityHomeNeutralCommandExemptions[activityHookCmd] = struct{}{}
}
