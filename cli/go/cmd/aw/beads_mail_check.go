package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// bd mail check, per docs/beads-mail-delegate.md §10: the hook-facing
// pending-mail probe, implemented as a read-only unread inbox fetch. Exit
// code 0 whenever the probe worked, with or without mail — a DELIBERATE
// divergence from gt mail check (0 = new mail, 1 = none): overloading the
// exit code as the mail-present signal makes "no mail" indistinguishable
// from "probe broke" in a hook line. Scripts branch on stdout or --json.

var (
	beadsMailCheckJSON   bool
	beadsMailCheckInject bool
)

var beadsMailCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for unread mail (for hooks)",
	Long: `Probe for unread mail without changing anything. Exit code 0 means the
probe worked, whether or not mail is waiting — branch on the output or
--json, not the exit code (gt mail check exits 1 on an empty inbox; this
deliberately does not, so a real failure is never mistaken for "no
mail"). Nonzero exits are real errors only.

For Claude Code hooks, --inject emits the PostToolUse hook JSON envelope
when mail is waiting and nothing otherwise. In-session wake-ups without
polling: aw init --setup-channel.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return usageError("check for another identity is not supported: this workspace has one aweb identity")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, _, _, err := beadsMailReadClient(cmd, ctx)
		if err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{UnreadOnly: true, Limit: 50})
		if err != nil {
			return err
		}
		unread := len(resp.Messages)
		suffix := ""
		if resp.HasMore {
			suffix = "+"
		}
		switch {
		case beadsMailCheckJSON:
			encoded, err := json.Marshal(map[string]any{"unread": unread, "has_more": resp.HasMore})
			if err != nil {
				return err
			}
			fmt.Println(string(encoded))
		case beadsMailCheckInject:
			if unread > 0 {
				fmt.Println(formatHookOutput(fmt.Sprintf("You have %d%s unread bd mail message(s). Run: bd mail inbox", unread, suffix)))
			}
		default:
			if unread > 0 {
				fmt.Printf("You have %d%s unread bd mail message(s). Run: bd mail inbox\n", unread, suffix)
			}
		}
		return nil
	},
}

func init() {
	beadsMailCheckCmd.Flags().BoolVar(&beadsMailCheckJSON, "json", false, "Output as JSON: {\"unread\": N, \"has_more\": bool}")
	beadsMailCheckCmd.Flags().BoolVar(&beadsMailCheckInject, "inject", false, "Output the Claude Code PostToolUse hook envelope when mail is waiting")
	beadsMailCheckCmd.MarkFlagsMutuallyExclusive("json", "inject")
}
