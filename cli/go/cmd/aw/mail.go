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
		appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
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
	mailInboxUnreadOnly bool
	mailInboxLimit      int
)

var mailInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: mailInboxUnreadOnly,
			Limit:      mailInboxLimit,
		})
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		for _, msg := range resp.Messages {
			// Only log unread messages to avoid duplicates on repeated inbox calls.
			if msg.ReadAt != nil {
				continue
			}
			appendCommLog(logsDir, sel.AccountName, &CommLogEntry{
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

// mail ack

var mailAckMessageID string

var mailAckCmd = &cobra.Command{
	Use:   "ack",
	Short: "Acknowledge a message",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mailAckMessageID == "" {
			return usageError("missing required flag: --message-id")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, err := resolveClient()
		if err != nil {
			return err
		}
		resp, err := c.AckMessage(ctx, mailAckMessageID)
		if err != nil {
			return err
		}
		printOutput(resp, formatMailAck)
		return nil
	},
}

func init() {
	mailSendCmd.Flags().StringVar(&mailSendTo, "to", "", "Recipient address")
	mailSendCmd.Flags().StringVar(&mailSendSubject, "subject", "", "Subject")
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", "Body")
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")

	mailInboxCmd.Flags().BoolVar(&mailInboxUnreadOnly, "unread-only", false, "Only unread")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")

	mailAckCmd.Flags().StringVar(&mailAckMessageID, "message-id", "", "Message ID to acknowledge")

	mailCmd.AddCommand(mailSendCmd, mailInboxCmd, mailAckCmd)
	rootCmd.AddCommand(mailCmd)
}
