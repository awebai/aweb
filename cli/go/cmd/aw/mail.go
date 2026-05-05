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
	mailSendTo             string
	mailSendToDID          string
	mailSendToAddress      string
	mailSendSubject        string
	mailSendBody           string
	mailSendBodyFile       string
	mailSendPriority       string
	mailSendConversationID string
)

func mailIdentityMatchesTarget(msg awid.InboxMessage, targetKind, targetValue string) bool {
	targetValue = strings.TrimSpace(targetValue)
	if targetValue == "" {
		return false
	}
	values := []string{
		msg.FromAddress,
		msg.ToAddress,
		msg.FromDID,
		msg.ToDID,
		msg.FromStableID,
		msg.ToStableID,
	}
	switch targetKind {
	case "address":
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), targetValue) {
				return true
			}
		}
	case "did":
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), targetValue) {
				return true
			}
		}
	}
	return false
}

func mailConversationMatchesTarget(conv awid.ConversationItem, targetKind, targetValue string) bool {
	targetValue = strings.TrimSpace(targetValue)
	if targetValue == "" || conv.ConversationType != "mail" || strings.TrimSpace(conv.ConversationID) == "" {
		return false
	}
	status := strings.TrimSpace(conv.Status)
	if status != "" && status != "active" {
		return false
	}
	var values []string
	switch targetKind {
	case "address":
		values = conv.ParticipantAddresses
	case "did":
		values = conv.ParticipantDIDs
	default:
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), targetValue) {
			return true
		}
	}
	return false
}

func uniqueMailConversationID(conversations map[string]bool, targetValue string) (string, error) {
	if len(conversations) == 0 {
		return "", nil
	}
	if len(conversations) != 1 {
		return "", fmt.Errorf("multiple mail conversations match %s; use --conversation-id to choose one", targetValue)
	}
	for conversationID := range conversations {
		return conversationID, nil
	}
	return "", nil
}

func findUniqueMailConversationForAgent(ctx context.Context, c *aweb.Client, agent awid.AgentView) (string, error) {
	for _, target := range []struct {
		kind  string
		value string
	}{
		{kind: "did", value: strings.TrimSpace(agent.DIDAW)},
		{kind: "did", value: strings.TrimSpace(agent.DIDKey)},
		{kind: "address", value: strings.TrimSpace(agent.Address)},
	} {
		if target.value == "" {
			continue
		}
		conversationID, err := findUniqueMailConversationForTarget(ctx, c, target.kind, target.value)
		if err != nil || conversationID != "" {
			return conversationID, err
		}
	}
	return "", nil
}

func agentMatchesSelection(agent awid.AgentView, sel *awconfig.Selection) bool {
	if sel == nil {
		return false
	}
	for _, pair := range []struct {
		agentValue string
		selfValue  string
	}{
		{agentValue: agent.DIDAW, selfValue: sel.StableID},
		{agentValue: agent.DIDKey, selfValue: sel.DID},
		{agentValue: agent.Address, selfValue: sel.Address},
	} {
		agentValue := strings.TrimSpace(pair.agentValue)
		selfValue := strings.TrimSpace(pair.selfValue)
		if agentValue != "" && selfValue != "" && strings.EqualFold(agentValue, selfValue) {
			return true
		}
	}
	return false
}

func findUniqueMailConversationForTarget(ctx context.Context, c *aweb.Client, targetKind, targetValue string) (string, error) {
	if c == nil || (targetKind != "address" && targetKind != "did") {
		return "", nil
	}
	params := awid.ConversationListParams{
		Limit:            100,
		ConversationType: "mail",
	}
	if targetKind == "did" {
		params.ParticipantDID = targetValue
	} else {
		params.ParticipantAddress = targetValue
	}
	conversationsResp, err := c.ListConversationsWithParams(ctx, params)
	if err == nil {
		conversations := map[string]bool{}
		for _, conv := range conversationsResp.Conversations {
			conversationID := strings.TrimSpace(conv.ConversationID)
			if conversationID == "" || !mailConversationMatchesTarget(conv, targetKind, targetValue) {
				continue
			}
			conversations[conversationID] = true
		}
		if conversationID, err := uniqueMailConversationID(conversations, targetValue); err != nil || conversationID != "" {
			return conversationID, err
		}
		return "", nil
	}

	// Older servers do not expose participant identities on /v1/conversations.
	// Fall back to inbox only when the conversation index is unavailable.
	resp, err := c.Inbox(ctx, awid.InboxParams{
		UnreadOnly: false,
		Limit:      200,
	})
	if err != nil {
		// Auto-threading is opportunistic; the send endpoint remains authoritative.
		return "", nil
	}
	conversations := map[string]bool{}
	for _, msg := range resp.Messages {
		conversationID := strings.TrimSpace(msg.ConversationID)
		if conversationID == "" || !mailIdentityMatchesTarget(msg, targetKind, targetValue) {
			continue
		}
		conversations[conversationID] = true
	}
	return uniqueMailConversationID(conversations, targetValue)
}

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
			Subject:        mailSendSubject,
			Body:           mailSendBody,
			Priority:       awid.MessagePriority(mailSendPriority),
			ConversationID: strings.TrimSpace(mailSendConversationID),
		}
		switch targetKind {
		case "conversation":
			if strings.TrimSpace(teamFlag) != "" {
				c, sel, err = resolveClientSelection()
			} else {
				c, sel, err = resolveIdentityMessagingClientSelection()
			}
			if err != nil {
				return err
			}
		case "alias":
			c, sel, err = resolveClientSelectionForAliasTarget(ctx, targetValue)
			if err != nil {
				return err
			}
			if agent, found, findErr := clientAgentForAlias(ctx, c, targetValue); findErr != nil {
				debugLog("list agents for mail auto-threading: %v", findErr)
				req.ToAlias = targetValue
			} else if found {
				if agentMatchesSelection(agent, sel) {
					req.ToAlias = targetValue
				} else if conversationID, findErr := findUniqueMailConversationForAgent(ctx, c, agent); findErr != nil {
					return findErr
				} else if conversationID != "" {
					targetKind = "conversation"
					targetValue = conversationID
					req.ConversationID = conversationID
				} else {
					req.ToAlias = targetValue
				}
			} else {
				req.ToAlias = targetValue
			}
		case "did":
			if strings.TrimSpace(teamFlag) != "" {
				c, sel, err = resolveClientSelection()
			} else {
				c, sel, err = resolveIdentityMessagingClientSelection()
			}
			if err != nil {
				return err
			}
			if conversationID, findErr := findUniqueMailConversationForTarget(ctx, c, targetKind, targetValue); findErr != nil {
				return findErr
			} else if conversationID != "" {
				targetKind = "conversation"
				targetValue = conversationID
				req.ConversationID = conversationID
			} else {
				req.ToDID = targetValue
			}
		case "address":
			if strings.TrimSpace(teamFlag) != "" {
				c, sel, err = resolveClientSelection()
			} else {
				c, sel, err = resolveIdentityMessagingClientSelection()
			}
			if err != nil {
				return err
			}
			if conversationID, findErr := findUniqueMailConversationForTarget(ctx, c, targetKind, targetValue); findErr != nil {
				return findErr
			} else if conversationID != "" {
				targetKind = "conversation"
				targetValue = conversationID
				req.ConversationID = conversationID
			} else {
				req.ToAddress = targetValue
			}
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
			if targetKind == "conversation" {
				return err
			}
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
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Dir:            "send",
			Channel:        "mail",
			MessageID:      resp.MessageID,
			ConversationID: resp.ConversationID,
			From:           from,
			To:             targetValue,
			Subject:        mailSendSubject,
			Body:           mailSendBody,
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Kind:           interactionKindMailOut,
			MessageID:      resp.MessageID,
			ConversationID: resp.ConversationID,
			To:             targetValue,
			Subject:        mailSendSubject,
			Text:           mailSendBody,
		})
		if jsonFlag {
			printJSON(resp)
		} else if targetKind == "conversation" {
			fmt.Printf("Sent mail in conversation %s (message_id=%s)\n", targetValue, resp.MessageID)
		} else {
			fmt.Printf("Sent mail to %s (message_id=%s)\n", targetValue, resp.MessageID)
		}
		return nil
	},
}

var (
	mailReplySubject  string
	mailReplyBody     string
	mailReplyBodyFile string
	mailReplyPriority string
)

var mailReplyCmd = &cobra.Command{
	Use:   "reply <message-id>",
	Short: "Reply to an existing mail conversation",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return usageError("usage: aw mail reply <message-id>")
		}
		if strings.TrimSpace(args[0]) == "" {
			return usageError("message-id is required")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		body, err := resolveMailBody(mailReplyBody, mailReplyBodyFile)
		if err != nil {
			return err
		}
		messageID := strings.TrimSpace(args[0])

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var c *aweb.Client
		var sel *awconfig.Selection
		if strings.TrimSpace(teamFlag) != "" {
			c, sel, err = resolveClientSelection()
		} else {
			c, sel, err = resolveIdentityMessagingClientSelection()
		}
		if err != nil {
			return err
		}
		inbox, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: false,
			Limit:      1,
			MessageID:  messageID,
		})
		if err != nil {
			return networkError(err, messageID)
		}
		if len(inbox.Messages) == 0 {
			return fmt.Errorf("mail message not found: %s", messageID)
		}
		conversationID := strings.TrimSpace(inbox.Messages[0].ConversationID)
		if conversationID == "" {
			return fmt.Errorf("message %s is legacy mail without a conversation; send a new message instead", messageID)
		}
		subject := mailReplySubject
		if strings.TrimSpace(subject) == "" {
			subject = "Re"
		}
		req := &awid.SendMessageRequest{
			ConversationID: conversationID,
			Subject:        subject,
			Body:           body,
			Priority:       awid.MessagePriority(mailReplyPriority),
		}
		resp, err := c.SendMessageByIdentity(ctx, req)
		if err != nil {
			return err
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
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Dir:            "send",
			Channel:        "mail",
			MessageID:      resp.MessageID,
			ConversationID: resp.ConversationID,
			From:           from,
			To:             conversationID,
			Subject:        subject,
			Body:           body,
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			Kind:           interactionKindMailOut,
			MessageID:      resp.MessageID,
			ConversationID: resp.ConversationID,
			To:             conversationID,
			Subject:        subject,
			Text:           body,
		})
		if jsonFlag {
			printJSON(resp)
		} else {
			fmt.Printf("Sent mail in conversation %s (message_id=%s)\n", conversationID, resp.MessageID)
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
	conversationID := strings.TrimSpace(mailSendConversationID)
	if conversationID != "" {
		if count > 0 {
			return "", "", usageError("--conversation-id cannot be combined with recipient flags")
		}
		return "conversation", conversationID, nil
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
				Timestamp:      msg.CreatedAt,
				Dir:            "recv",
				Channel:        "mail",
				MessageID:      msg.MessageID,
				ConversationID: msg.ConversationID,
				From:           from,
				To:             to,
				Subject:        msg.Subject,
				Body:           msg.Body,
				FromDID:        msg.FromDID,
				ToDID:          msg.ToDID,
				FromStableID:   msg.FromStableID,
				ToStableID:     msg.ToStableID,
				Signature:      msg.Signature,
				SigningKeyID:   msg.SigningKeyID,
				Verification:   string(msg.VerificationStatus),
			})
			appendInteractionLogForCWD(&InteractionEntry{
				Timestamp:      msg.CreatedAt,
				Kind:           interactionKindMailIn,
				MessageID:      msg.MessageID,
				ConversationID: msg.ConversationID,
				From:           from,
				To:             to,
				Subject:        msg.Subject,
				Text:           msg.Body,
			})
		}
		printOutput(resp, formatMailInbox)
		return nil
	},
}

var (
	mailShowConversationID string
	mailShowMessageID      string
	mailShowLimit          int
)

var mailShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a mail conversation",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversationID := strings.TrimSpace(mailShowConversationID)
		messageID := strings.TrimSpace(mailShowMessageID)
		if conversationID == "" && messageID == "" {
			return usageError("missing required flag: --conversation-id or --message-id")
		}
		if conversationID != "" && messageID != "" {
			return usageError("--conversation-id and --message-id are mutually exclusive")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var c *aweb.Client
		var err error
		if strings.TrimSpace(teamFlag) != "" {
			c, _, err = resolveClientSelection()
		} else {
			c, _, err = resolveIdentityMessagingClientSelection()
		}
		if err != nil {
			return err
		}
		var resp *awid.InboxResponse
		if messageID != "" {
			resp, err = c.Inbox(ctx, awid.InboxParams{
				UnreadOnly: false,
				Limit:      mailShowLimit,
				MessageID:  messageID,
			})
		} else {
			resp, err = c.MailConversation(ctx, conversationID, mailShowLimit)
		}
		if err != nil {
			if conversationID != "" {
				return mailShowConversationError(err, conversationID)
			}
			return networkError(err, messageID)
		}
		printOutput(resp, formatMailConversation)
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
	mailSendCmd.Flags().StringVar(&mailSendConversationID, "conversation-id", "", "Existing mail conversation to continue")

	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")
	mailReplyCmd.Flags().StringVar(&mailReplySubject, "subject", "", "Subject")
	mailReplyCmd.Flags().StringVar(&mailReplyBody, "body", "", "Body (mutually exclusive with --body-file)")
	mailReplyCmd.Flags().StringVar(&mailReplyBodyFile, "body-file", "", "Read body from file")
	mailReplyCmd.Flags().StringVar(&mailReplyPriority, "priority", "normal", "Priority: low|normal|high|urgent")
	mailShowCmd.Flags().StringVar(&mailShowConversationID, "conversation-id", "", "Mail conversation to inspect")
	mailShowCmd.Flags().StringVar(&mailShowMessageID, "message-id", "", "Legacy mail message to inspect")
	mailShowCmd.Flags().IntVar(&mailShowLimit, "limit", 200, "Max messages")

	mailCmd.AddCommand(mailSendCmd, mailReplyCmd, mailInboxCmd, mailShowCmd)
	rootCmd.AddCommand(mailCmd)
}
