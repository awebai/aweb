package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var mailCmd = &cobra.Command{
	Use:   "mail",
	Short: "Agent messaging",
}

// mail send

var (
	mailSendTo        string
	mailSendToDID    string
	mailSendToAddress string
	mailSendSubject   string
	mailSendBody      string
	mailSendPriority  string
)

var mailSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message to another agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if mailSendBody == "" {
			return usageError("missing required flag: --body")
		}
		targetKind, targetValue, err := resolveMailTarget()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var c *aweb.Client
		var sel *awconfig.Selection
		req := &awid.SendMessageRequest{
			Subject:  mailSendSubject,
			Body:     mailSendBody,
			Priority: awid.MessagePriority(mailSendPriority),
		}
		switch targetKind {
		case "alias":
			c, sel, err = resolveClientSelection()
			if err != nil {
				return err
			}
			req.ToAlias = targetValue
		case "did":
			c, sel, err = resolveIdentityMessagingClientSelection()
			if err != nil {
				return err
			}
			req.ToDID = targetValue
		case "address":
			c, sel, err = resolveIdentityMessagingClientSelection()
			if err != nil {
				return err
			}
			req.ToAddress = targetValue
		default:
			return usageError("missing required recipient flag")
		}

		var resp *awid.SendMessageResponse
		if targetKind == "alias" {
			resp, err = c.SendMessage(ctx, req)
		} else {
			resp, err = c.SendMessageByIdentity(ctx, req)
		}
		if err != nil {
			return networkError(err, targetValue)
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "mail",
			MessageID: resp.MessageID,
			From:      selectionAddress(sel),
			To:        targetValue,
			Subject:   mailSendSubject,
			Body:      mailSendBody,
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindMailOut,
			MessageID: resp.MessageID,
			To:        targetValue,
			Subject:   mailSendSubject,
			Text:      mailSendBody,
		})
		if jsonFlag {
			printJSON(resp)
		} else {
			fmt.Printf("Sent mail to %s (message_id=%s)\n", targetValue, resp.MessageID)
		}
		return nil
	},
}

func resolveMailTarget() (string, string, error) {
	count := 0
	if strings.TrimSpace(mailSendTo) != "" {
		count++
	}
	if strings.TrimSpace(mailSendToDID) != "" {
		count++
	}
	if strings.TrimSpace(mailSendToAddress) != "" {
		count++
	}
	if count == 0 {
		return "", "", usageError("missing required recipient flag: one of --to, --to-did, or --to-address")
	}
	if count > 1 {
		return "", "", usageError("recipient flags are mutually exclusive: use only one of --to, --to-did, or --to-address")
	}
	if value := strings.TrimSpace(mailSendTo); value != "" {
		return "alias", value, nil
	}
	if value := strings.TrimSpace(mailSendToDID); value != "" {
		return "did", value, nil
	}
	return "address", strings.TrimSpace(mailSendToAddress), nil
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

		c, sel, err := resolveIdentityMessagingClientSelection()
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
	mailSendCmd.Flags().StringVar(&mailSendTo, "to", "", "Recipient alias within the active team")
	mailSendCmd.Flags().StringVar(&mailSendToDID, "to-did", "", "Recipient stable identity (did:aw:...)")
	mailSendCmd.Flags().StringVar(&mailSendToAddress, "to-address", "", "Recipient address (domain/name)")
	mailSendCmd.Flags().StringVar(&mailSendSubject, "subject", "", "Subject")
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", "Body")
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")

	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")

	mailCmd.AddCommand(mailSendCmd, mailInboxCmd)
	rootCmd.AddCommand(mailCmd)
}
