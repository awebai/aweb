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
	mailSendTo              string
	mailSendToDID           string
	mailSendToAddress       string
	mailSendSubject         string
	mailSendBody            string
	mailSendBodyFile        string
	mailSendPriority        string
	mailSendConversationID  string
	mailSendE2EE            bool
	mailSendLegacyPlaintext bool
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

func uniqueMailConversationTarget(conversations map[string]mailConversationTarget, targetValue string) (mailConversationTarget, error) {
	if len(conversations) == 0 {
		return mailConversationTarget{}, nil
	}
	if len(conversations) != 1 {
		return mailConversationTarget{}, fmt.Errorf("multiple mail conversations match %s; use --conversation-id to choose one", targetValue)
	}
	for _, target := range conversations {
		return target, nil
	}
	return mailConversationTarget{}, nil
}

type mailConversationTarget struct {
	conversationID string
	kind           string
	value          string
}

func mailConversationParticipantTarget(c *awid.Client, conv awid.ConversationItem, fallbackKind, fallbackValue string) mailConversationTarget {
	target := mailConversationTarget{
		conversationID: strings.TrimSpace(conv.ConversationID),
		kind:           fallbackKind,
		value:          strings.TrimSpace(fallbackValue),
	}
	if target.conversationID == "" {
		return target
	}
	if c != nil {
		otherDIDs, otherAddresses := awid.OtherConversationParticipants(
			conv.ParticipantDIDs,
			conv.ParticipantAddresses,
			c.StableID(),
			c.DID(),
			c.Address(),
		)
		if len(otherDIDs) == 1 {
			target.kind = "did"
			target.value = otherDIDs[0]
			return target
		}
		if len(otherAddresses) == 1 {
			target.kind = "address"
			target.value = otherAddresses[0]
			return target
		}
	}
	return target
}

func mailInboxMessageParticipantTarget(c *awid.Client, msg awid.InboxMessage, fallbackKind, fallbackValue string) mailConversationTarget {
	target := mailConversationTarget{
		conversationID: strings.TrimSpace(msg.ConversationID),
		kind:           fallbackKind,
		value:          strings.TrimSpace(fallbackValue),
	}
	if candidate := mailMatchedMessageParticipantTarget(msg, fallbackKind, fallbackValue); candidate.value != "" {
		candidate.conversationID = target.conversationID
		return candidate
	}
	if c == nil {
		return target
	}
	selfStableID := strings.TrimSpace(c.StableID())
	selfDID := strings.TrimSpace(c.DID())
	selfAddress := strings.TrimSpace(c.Address())
	for _, participant := range []struct {
		stableID string
		did      string
		address  string
	}{
		{stableID: msg.FromStableID, did: msg.FromDID, address: msg.FromAddress},
		{stableID: msg.ToStableID, did: msg.ToDID, address: msg.ToAddress},
	} {
		stableID := strings.TrimSpace(participant.stableID)
		did := strings.TrimSpace(participant.did)
		address := strings.TrimSpace(participant.address)
		isSelf := (selfStableID != "" && strings.EqualFold(stableID, selfStableID)) ||
			(selfDID != "" && strings.EqualFold(did, selfDID)) ||
			(selfAddress != "" && strings.EqualFold(address, selfAddress))
		if isSelf {
			continue
		}
		if stableID != "" {
			target.kind = "did"
			target.value = stableID
			return target
		}
		if did != "" {
			target.kind = "did"
			target.value = did
			return target
		}
		if address != "" {
			target.kind = "address"
			target.value = address
			return target
		}
	}
	return target
}

func mailMatchedMessageParticipantTarget(msg awid.InboxMessage, targetKind, targetValue string) mailConversationTarget {
	targetValue = strings.TrimSpace(targetValue)
	if targetValue == "" {
		return mailConversationTarget{}
	}
	for _, participant := range []struct {
		stableID string
		did      string
		address  string
	}{
		{stableID: msg.FromStableID, did: msg.FromDID, address: msg.FromAddress},
		{stableID: msg.ToStableID, did: msg.ToDID, address: msg.ToAddress},
	} {
		stableID := strings.TrimSpace(participant.stableID)
		did := strings.TrimSpace(participant.did)
		address := strings.TrimSpace(participant.address)
		matched := (targetKind == "address" && strings.EqualFold(address, targetValue)) ||
			(targetKind == "did" && (strings.EqualFold(stableID, targetValue) || strings.EqualFold(did, targetValue)))
		if !matched {
			continue
		}
		if stableID != "" {
			return mailConversationTarget{kind: "did", value: stableID}
		}
		if did != "" {
			return mailConversationTarget{kind: "did", value: did}
		}
		if address != "" {
			return mailConversationTarget{kind: "address", value: address}
		}
	}
	return mailConversationTarget{}
}

func applyMailRecipientTarget(req *awid.SendMessageRequest, kind, value string) {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return
	case kind == "did" && strings.HasPrefix(value, "did:aw:"):
		req.ToStableID = value
	case kind == "did":
		req.ToDID = value
	case kind == "address":
		req.ToAddress = value
	default:
		req.ToAlias = value
	}
}

func mailRecipientTargetApplied(req *awid.SendMessageRequest) bool {
	return req.ToAlias != "" || req.ToDID != "" || req.ToStableID != "" || req.ToAddress != ""
}

func findUniqueMailConversationForAgent(ctx context.Context, c *aweb.Client, agent awid.AgentView) (mailConversationTarget, error) {
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
		conversation, err := findUniqueMailConversationForTarget(ctx, c, target.kind, target.value)
		if err != nil || conversation.conversationID != "" {
			return conversation, err
		}
	}
	return mailConversationTarget{}, nil
}

func resolveMailMessagingClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	if strings.TrimSpace(teamFlag) != "" {
		return resolveClientSelection()
	}
	c, sel, err := resolveClientSelection()
	if err == nil {
		return c, sel, nil
	}
	debugLog("resolve certificate messaging client for mail: %v", err)
	return resolveIdentityMessagingClientSelection()
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

func findUniqueMailConversationForTarget(ctx context.Context, c *aweb.Client, targetKind, targetValue string) (mailConversationTarget, error) {
	if c == nil || (targetKind != "address" && targetKind != "did") {
		return mailConversationTarget{}, nil
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
		conversations := map[string]mailConversationTarget{}
		for _, conv := range conversationsResp.Conversations {
			conversationID := strings.TrimSpace(conv.ConversationID)
			if conversationID == "" || !mailConversationMatchesTarget(conv, targetKind, targetValue) {
				continue
			}
			conversations[conversationID] = mailConversationParticipantTarget(c.Client, conv, targetKind, targetValue)
		}
		if conversation, err := uniqueMailConversationTarget(conversations, targetValue); err != nil || conversation.conversationID != "" {
			return conversation, err
		}
		return mailConversationTarget{}, nil
	}

	// Older servers do not expose participant identities on /v1/conversations.
	// Fall back to inbox only when the conversation index is unavailable.
	resp, err := c.Inbox(ctx, awid.InboxParams{
		UnreadOnly: false,
		Limit:      200,
	})
	if err != nil {
		// Auto-threading is opportunistic; the send endpoint remains authoritative.
		return mailConversationTarget{}, nil
	}
	conversations := map[string]mailConversationTarget{}
	for _, msg := range resp.Messages {
		conversationID := strings.TrimSpace(msg.ConversationID)
		if conversationID == "" || !mailIdentityMatchesTarget(msg, targetKind, targetValue) {
			continue
		}
		conversations[conversationID] = mailInboxMessageParticipantTarget(c.Client, msg, targetKind, targetValue)
	}
	return uniqueMailConversationTarget(conversations, targetValue)
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
			c, sel, err = resolveMailMessagingClientSelection()
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
				} else if conversation, findErr := findUniqueMailConversationForAgent(ctx, c, agent); findErr != nil {
					return findErr
				} else if conversation.conversationID != "" {
					targetKind = "conversation"
					targetValue = conversation.conversationID
					req.ConversationID = conversation.conversationID
					applyMailRecipientTarget(req, conversation.kind, conversation.value)
					if !mailRecipientTargetApplied(req) {
						applyMailRecipientTarget(req, "did", strings.TrimSpace(agent.DIDAW))
					}
					if !mailRecipientTargetApplied(req) {
						applyMailRecipientTarget(req, "did", strings.TrimSpace(agent.DIDKey))
					}
					if !mailRecipientTargetApplied(req) {
						applyMailRecipientTarget(req, "address", strings.TrimSpace(agent.Address))
					}
					if !mailRecipientTargetApplied(req) {
						applyMailRecipientTarget(req, "alias", strings.TrimSpace(agent.Alias))
					}
				} else {
					req.ToAlias = targetValue
				}
			} else {
				req.ToAlias = targetValue
			}
		case "did":
			c, sel, err = resolveMailMessagingClientSelection()
			if err != nil {
				return err
			}
			recipientDID := targetValue
			if conversation, findErr := findUniqueMailConversationForTarget(ctx, c, targetKind, targetValue); findErr != nil {
				return findErr
			} else if conversation.conversationID != "" {
				targetKind = "conversation"
				targetValue = conversation.conversationID
				req.ConversationID = conversation.conversationID
				applyMailRecipientTarget(req, conversation.kind, conversation.value)
				if req.ToDID == "" && req.ToStableID == "" {
					applyMailRecipientTarget(req, "did", recipientDID)
				}
			} else {
				req.ToDID = targetValue
			}
		case "address":
			c, sel, err = resolveMailMessagingClientSelection()
			if err != nil {
				return err
			}
			if conversation, findErr := findUniqueMailConversationForTarget(ctx, c, targetKind, targetValue); findErr != nil {
				return findErr
			} else if conversation.conversationID != "" {
				targetKind = "conversation"
				targetValue = conversation.conversationID
				req.ConversationID = conversation.conversationID
				applyMailRecipientTarget(req, conversation.kind, conversation.value)
			} else {
				req.ToAddress = targetValue
			}
		default:
			return usageError("missing required recipient flag")
		}

		var resp *awid.SendMessageResponse
		if mailSendE2EE && mailSendLegacyPlaintext {
			return usageError("--e2ee and --legacy-plaintext are mutually exclusive")
		}
		req.EncryptE2EE = mailSendE2EE
		if req.EncryptE2EE {
			if err := configureClientE2EEForMail(c, sel, true); err != nil {
				return err
			}
		}
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
	mailReplySubject         string
	mailReplyBody            string
	mailReplyBodyFile        string
	mailReplyPriority        string
	mailReplyE2EE            bool
	mailReplyLegacyPlaintext bool
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
		c, sel, err = resolveMailMessagingClientSelection()
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
		if mailReplyE2EE && mailReplyLegacyPlaintext {
			return usageError("--e2ee and --legacy-plaintext are mutually exclusive")
		}
		req := &awid.SendMessageRequest{
			ConversationID: conversationID,
			Subject:        subject,
			Body:           body,
			Priority:       awid.MessagePriority(mailReplyPriority),
			EncryptE2EE:    mailReplyE2EE,
		}
		if req.EncryptE2EE {
			if err := configureClientE2EEForMail(c, sel, true); err != nil {
				return err
			}
		}
		resp, err := c.SendMessageByIdentity(ctx, req)
		if err != nil {
			return err
		}
		if _, ackErr := c.AckMessage(ctx, messageID); ackErr != nil {
			debugLog("ack replied mail %s: %v", messageID, ackErr)
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
	if value := awid.NormalizeHostedHandleAddress(mailSendTo); value != "" {
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
	return "address", awid.NormalizeHostedHandleAddress(mailSendToAddress), nil
}

func configureClientE2EEForMail(c *aweb.Client, sel *awconfig.Selection, required bool) error {
	if c == nil || c.Client == nil || sel == nil {
		return usageError("E2E mail requires an initialized self-custodial workspace")
	}
	statePath := awconfig.WorktreeEncryptionStatePath(sel.WorkingDir)
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			if !required {
				return nil
			}
			return usageError("E2E mail requires a local encryption key; run `aw id encryption-key setup`, or pass --legacy-plaintext for explicit server-readable mail")
		}
		return err
	}
	record := state.ActiveRecord()
	if record == nil {
		if !required {
			return nil
		}
		return usageError("E2E mail requires an active local encryption key; run `aw id encryption-key setup`, or pass --legacy-plaintext for explicit server-readable mail")
	}
	material, err := validateEncryptionRecordPrivateKey(sel.WorkingDir, record)
	if err != nil {
		return err
	}
	assertion, err := loadEncryptionAssertion(sel.WorkingDir, record.AssertionPath)
	if err != nil {
		return err
	}
	identity := e2eeAssertionIdentityForSelection(sel)
	if err := validateEncryptionRecordAssertion(identity, record, assertion, material); err != nil {
		return err
	}
	privatePath := resolveWorktreeRelativePath(sel.WorkingDir, record.PrivateKeyPath)
	privateKey, err := awid.LoadX25519PrivateKey(privatePath)
	if err != nil {
		return err
	}
	c.Client.SetE2EEKey(assertion, privateKey)
	return nil
}

func e2eeAssertionIdentityForSelection(sel *awconfig.Selection) *awconfig.ResolvedIdentity {
	if sel == nil {
		return &awconfig.ResolvedIdentity{}
	}
	did := strings.TrimSpace(sel.DID)
	stableID := strings.TrimSpace(sel.StableID)

	// A global identity can join a local/team-scoped certificate whose cert does
	// not carry member_did_aw. The local encryption-key assertion is still
	// identity-signed and must be checked against identity.yaml when it matches
	// the selected signing did:key.
	if identity, err := awconfig.ResolveIdentity(sel.WorkingDir); err == nil {
		identityDID := strings.TrimSpace(identity.DID)
		if identityDID != "" && (did == "" || identityDID == did) {
			did = identityDID
			if stableID == "" {
				stableID = strings.TrimSpace(identity.StableID)
			}
		}
	}

	return &awconfig.ResolvedIdentity{
		WorkingDir: strings.TrimSpace(sel.WorkingDir),
		DID:        did,
		StableID:   stableID,
	}
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
		if err := configureClientE2EEForMail(c, sel, false); err != nil {
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
		var sel *awconfig.Selection
		var err error
		if strings.TrimSpace(teamFlag) != "" {
			c, sel, err = resolveClientSelection()
		} else {
			c, sel, err = resolveIdentityMessagingClientSelection()
		}
		if err != nil {
			return err
		}
		if err := configureClientE2EEForMail(c, sel, false); err != nil {
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
	mailSendCmd.Flags().BoolVar(&mailSendE2EE, "e2ee", false, "Send E2E encrypted mail; fails closed if local or recipient encryption keys are missing")
	mailSendCmd.Flags().BoolVar(&mailSendLegacyPlaintext, "legacy-plaintext", false, "Send explicit server-readable legacy plaintext mail instead of E2E encrypted mail")

	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages")
	mailReplyCmd.Flags().StringVar(&mailReplySubject, "subject", "", "Subject")
	mailReplyCmd.Flags().StringVar(&mailReplyBody, "body", "", "Body (mutually exclusive with --body-file)")
	mailReplyCmd.Flags().StringVar(&mailReplyBodyFile, "body-file", "", "Read body from file")
	mailReplyCmd.Flags().StringVar(&mailReplyPriority, "priority", "normal", "Priority: low|normal|high|urgent")
	mailReplyCmd.Flags().BoolVar(&mailReplyE2EE, "e2ee", false, "Send E2E encrypted mail; fails closed if local or recipient encryption keys are missing")
	mailReplyCmd.Flags().BoolVar(&mailReplyLegacyPlaintext, "legacy-plaintext", false, "Send explicit server-readable legacy plaintext mail instead of E2E encrypted mail")
	mailShowCmd.Flags().StringVar(&mailShowConversationID, "conversation-id", "", "Mail conversation to inspect")
	mailShowCmd.Flags().StringVar(&mailShowMessageID, "message-id", "", "Legacy mail message to inspect")
	mailShowCmd.Flags().IntVar(&mailShowLimit, "limit", 200, "Max messages")

	mailCmd.AddCommand(mailSendCmd, mailReplyCmd, mailInboxCmd, mailShowCmd)
	rootCmd.AddCommand(mailCmd)
}
