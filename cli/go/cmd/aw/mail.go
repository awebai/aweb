package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var mailCmd = &cobra.Command{
	Use:   "mail",
	Short: "Agent messaging",
}

// mail send

var (
	mailSendTo       string
	mailSendSubject  string
	mailSendBody     string
	mailSendPriority string
)

var mailSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message to another agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mailSendTo == "" {
			return usageError("missing required flag: --to")
		}
		if mailSendBody == "" {
			return usageError("missing required flag: --body")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}

		resp, err := c.SendMessage(ctx, &awid.SendMessageRequest{
			ToAlias:  mailSendTo,
			Subject:  mailSendSubject,
			Body:     mailSendBody,
			Priority: awid.MessagePriority(mailSendPriority),
		})
		if err != nil {
			return networkError(err, mailSendTo)
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "mail",
			MessageID: resp.MessageID,
			From:      deriveIdentityAddress(sel.NamespaceSlug, sel.DefaultProject, sel.IdentityHandle),
			To:        mailSendTo,
			Subject:   mailSendSubject,
			Body:      mailSendBody,
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindMailOut,
			MessageID: resp.MessageID,
			To:        mailSendTo,
			Subject:   mailSendSubject,
			Text:      mailSendBody,
		})
		if jsonFlag {
			printJSON(resp)
		} else {
			fmt.Printf("Sent mail to %s (message_id=%s)\n", mailSendTo, resp.MessageID)
		}
		return nil
	},
}

// mail inbox

var (
	mailInboxShowAll bool
	mailInboxLimit   int
)

var mailInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages (unread only by default)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: !mailInboxShowAll,
			Limit:      mailInboxLimit,
		})
		if err != nil {
			return err
		}
		// Mark all unread messages as read — seeing them means they're read.
		for _, msg := range resp.Messages {
			if msg.ReadAt == nil && msg.MessageID != "" {
				_, _ = c.AckMessage(ctx, msg.MessageID)
			}
		}
		logsDir := defaultLogsDir()
		for _, msg := range resp.Messages {
			// Only log unread messages to avoid duplicates on repeated inbox calls.
			if msg.ReadAt != nil {
				continue
			}
			appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
				Timestamp:    msg.CreatedAt,
				Dir:          "recv",
				Channel:      "mail",
				MessageID:    msg.MessageID,
				From:         msg.FromAddress,
				To:           msg.ToAddress,
				Subject:      msg.Subject,
				Body:         msg.Body,
				FromDID:      msg.FromDID,
				ToDID:        msg.ToDID,
				FromStableID: msg.FromStableID,
				ToStableID:   msg.ToStableID,
				Signature:    msg.Signature,
				SigningKeyID: msg.SigningKeyID,
				Verification: string(msg.VerificationStatus),
			})
			appendInteractionLogForCWD(&InteractionEntry{
				Timestamp: msg.CreatedAt,
				Kind:      interactionKindMailIn,
				MessageID: msg.MessageID,
				From:      msg.FromAddress,
				To:        msg.ToAddress,
				Subject:   msg.Subject,
				Text:      msg.Body,
			})
		}
		printOutput(resp, formatMailInbox)
		return nil
	},
}

func init() {
	mailSendCmd.Flags().StringVar(&mailSendTo, "to", "", "Recipient address")
	mailSendCmd.Flags().StringVar(&mailSendSubject, "subject", "", "Subject")
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", "Body")
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")

	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")

	mailCmd.AddCommand(mailSendCmd, mailInboxCmd)
	rootCmd.AddCommand(mailCmd)
}
