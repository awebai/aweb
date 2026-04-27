package main

import (
	"context"
	"fmt"
	"os"
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
	mailSendToDID     string
	mailSendToAddress string
	mailSendSubject   string
	mailSendBody      string
	mailSendBodyFile  string
	mailSendPriority  string
)

var mailSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message to another agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := resolveMailBody(mailSendBody, mailSendBodyFile)
		if err != nil {
			return err
		}
		mailSendBody = body
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
			c, sel, err = resolveClientSelectionForAliasTarget(ctx, targetValue)
			if err != nil {
				return err
			}
			req.ToAlias = targetValue
		case "did":
			if strings.TrimSpace(teamFlag) != "" {
				c, sel, err = resolveClientSelection()
			} else {
				c, sel, err = resolveIdentityMessagingClientSelection()
			}
			if err != nil {
				return err
			}
			req.ToDID = targetValue
		case "address":
			if strings.TrimSpace(teamFlag) != "" {
				c, sel, err = resolveClientSelection()
			} else {
				c, sel, err = resolveIdentityMessagingClientSelection()
			}
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
		from := preferredIdentityDisplayLabel(
			"",
			selectionAddress(sel),
			strings.TrimSpace(sel.StableID),
			strings.TrimSpace(sel.DID),
			"",
		)
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "mail",
			MessageID: resp.MessageID,
			From:      from,
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

// resolveMailBody returns the message body, sourcing it from --body or
// --body-file. Reading from a file bypasses shell interpolation and is the
// only safe way to send markdown that contains backticks. Exactly one
// trailing newline is stripped from file contents (editors and heredocs add
// it; users almost never want it on the wire).
func resolveMailBody(bodyArg, bodyFileArg string) (string, error) {
	bodySet := bodyArg != ""
	fileSet := bodyFileArg != ""
	if bodySet && fileSet {
		return "", usageError("--body and --body-file are mutually exclusive")
	}
	if bodySet {
		return bodyArg, nil
	}
	if !fileSet {
		return "", usageError("missing required flag: --body or --body-file")
	}
	contents, err := os.ReadFile(bodyFileArg)
	if err != nil {
		return "", fmt.Errorf("read body file %q: %w", bodyFileArg, err)
	}
	body := strings.TrimSuffix(string(contents), "\n")
	if body == "" {
		return "", usageError("body file %q is empty", bodyFileArg)
	}
	return body, nil
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
		switch {
		case strings.HasPrefix(value, "did:"):
			return "did", value, nil
		case strings.Contains(value, "/"):
			return "address", value, nil
		default:
			return "alias", value, nil
		}
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
			from := preferredIdentityDisplayLabel(
				msg.FromAlias,
				msg.FromAddress,
				msg.FromStableID,
				msg.FromDID,
				"",
			)
			to := preferredIdentityDisplayLabel(
				msg.ToAlias,
				msg.ToAddress,
				msg.ToStableID,
				msg.ToDID,
				"",
			)
			appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
				Timestamp:    msg.CreatedAt,
				Dir:          "recv",
				Channel:      "mail",
				MessageID:    msg.MessageID,
				From:         from,
				To:           to,
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
				From:      from,
				To:        to,
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
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", "Body (mutually exclusive with --body-file)")
	mailSendCmd.Flags().StringVar(&mailSendBodyFile, "body-file", "", "Read body from file (use this for markdown with backticks; bypasses shell interpolation)")
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")

	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")

	mailCmd.AddCommand(mailSendCmd, mailInboxCmd)
	rootCmd.AddCommand(mailCmd)
}
