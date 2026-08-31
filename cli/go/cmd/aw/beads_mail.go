package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// aw beads-mail is the aweb-backed implementation of the beads `bd mail`
// delegate contract: bd execs the configured delegate with the raw mail args
// appended, stdio passed through, and our exit code propagated. Design record:
// docs/beads-mail-delegate.md. This file is the frame (verb router, help,
// decided not-supported messages); the network-facing verbs land per that
// record's table.
var beadsMailCmd = &cobra.Command{
	Use:   "beads-mail",
	Short: "Mail for beads: the bd mail delegate backed by aweb",
	Long: `Mail for beads, no orchestrator required.

beads ships a 'bd mail' command that delegates to an external mail
provider. This is that provider, backed by aweb: durable delivery,
offline recipients, and cryptographically verified sender identity.

Setup, once per repo:

  npm i -g @awebai/aw
  aw init
  bd config set mail.delegate "aw beads-mail"

Then 'bd mail send', 'bd mail inbox', and friends work. Recipients run
the same three lines. Map beads-style names to aweb addresses in
.beads/aweb-mail.toml; addresses containing a domain (acme.com/reviewer)
need no mapping.

Two things to know that differ from 'gt mail':

  - 'bd mail' swallows --help anywhere in the arguments, so use
    'bd mail help <verb>' (or 'aw beads-mail <verb> --help') for
    per-verb help.
  - 'bd mail check' always exits 0 when the probe worked; branch on its
    output or --json, not the exit code. Nonzero means a real failure.

Optional in-session wake-ups when mail arrives: aw init --setup-channel.`,
}

// beadsMailWantsHelp mirrors bd's own delegate-side convention: with flag
// parsing disabled, -h/--help anywhere in a verb's args means help. (bd only
// intercepts --help for the whole 'bd mail' invocation; a bare verb's args
// reach us verbatim through 'aw beads-mail <verb> ...'.)
func beadsMailWantsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

// beadsMailStub declares a verb the design record marks as implemented, ahead
// of its implementation subtask. Flag parsing stays disabled so gt-shaped
// input can never crash the router; the real verb defines its flags when it
// lands.
func beadsMailStub(use, short string, aliases ...string) *cobra.Command {
	verb := strings.Fields(use)[0]
	return &cobra.Command{
		Use:                use,
		Short:              short,
		Aliases:            aliases,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if beadsMailWantsHelp(args) {
				return cmd.Help()
			}
			return usageError("beads-mail %s is not implemented yet in this build; the delegate frame landed first. Run 'aw beads-mail help' for the current surface", verb)
		},
	}
}

// beadsMailUnsupported declares a verb the design record decides against for
// v1. The message is the product surface a beads user meets: it says what the
// verb would do, why not here, and what to use instead.
func beadsMailUnsupported(use, short, message string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if beadsMailWantsHelp(args) {
				return cmd.Help()
			}
			return usageError("%s", message)
		},
	}
}

var beadsMailHelpCmd = &cobra.Command{
	Use:   "help [verb]",
	Short: "Show help for a beads-mail verb ('bd mail' swallows --help; this reaches us)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return beadsMailCmd.Help()
		}
		target, _, err := beadsMailCmd.Find(args)
		if err != nil || target == nil || target == beadsMailCmd {
			return usageError("unknown beads-mail verb %q; run 'aw beads-mail help' for the list", args[0])
		}
		return target.Help()
	},
}

func init() {
	beadsMailCmd.GroupID = groupNetwork

	beadsMailCmd.AddCommand(
		beadsMailSendCmd,
		beadsMailReplyCmd,
		beadsMailInboxCmd,
		beadsMailReadCmd,
		beadsMailPeekCmd,
		beadsMailThreadCmd,
		beadsMailCheckCmd,
		beadsMailMarkReadCmd,

		beadsMailUnsupported("mark-unread <message-id>", "Not supported: read state cannot be cleared",
			"bd mail mark-unread is not supported: the aweb server has no way to clear read state, and read state drives the wake path. If you need this, ask for it - it requires a server-side change"),
		beadsMailUnsupported("archive [message-id...]", "Not supported: the beads graph is the archive",
			"bd mail archive is not supported: aweb mail is delivery, not an archive - the durable record is your beads graph. Use 'bd mail mark-read' to clear unread state"),
		beadsMailUnsupported("delete <message-id>", "Not supported: server mail expires on its own",
			"bd mail delete is not supported: messages cannot be deleted from the aweb server; they expire under the server's retention policy. The durable record is your beads graph"),
		beadsMailUnsupported("clear [target]", "Not supported: server mail expires on its own",
			"bd mail clear is not supported: messages cannot be deleted from the aweb server; they expire under the server's retention policy. Use 'bd mail mark-read --all' to clear unread state"),
		beadsMailUnsupported("search <query>", "Not supported in v1: no server-side mail search",
			"bd mail search is not supported in v1: the aweb server has no mail search. With dual-write enabled your messages are beads issues - search them with bd. Without dual-write, 'aw log' shows the local send/fetch record"),
		beadsMailUnsupported("claim [queue-name]", "Not supported in v1: no message queues",
			"bd mail claim is not supported in v1: aweb mail has no claimable queues. Shared work claiming lives in aweb tasks"),
		beadsMailUnsupported("release <message-id>", "Not supported in v1: no message queues",
			"bd mail release is not supported in v1: aweb mail has no claimable queues. Shared work claiming lives in aweb tasks"),
		beadsMailUnsupported("announces [channel]", "Not supported in v1",
			"bd mail announces is not supported in v1: aweb mail has no announce channels"),
		beadsMailUnsupported("drain", "Not supported in v1",
			"bd mail drain is not supported in v1; use 'bd mail mark-read --all' to mark everything read"),

		beadsMailHelpCmd,
	)

	rootCmd.AddCommand(beadsMailCmd)
}
