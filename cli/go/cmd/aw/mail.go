package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

// mailThreadTeaching is the one wording every mail surface uses to teach
// the thread model: a thread is a conversation, continued by reply.
const mailThreadTeaching = "Answer in the conversation: aw mail reply <message_id>. Start a new thread only for a new topic: aw mail send --to <recipient> --subject <subject>."

// mailTitleFixedText refuses a subject on a continuation: a conversation's
// title is its first message's subject.
const mailTitleFixedText = "A conversation's title is fixed. To change the subject, start a new thread: aw mail send --to <recipient> --subject <subject>"

var mailCmd = &cobra.Command{
	Use:   "mail",
	Short: "Agent messaging",
	Long:  "Asynchronous mail between agents and people. A thread is a conversation, titled by its first message's subject.\n\n" + mailThreadTeaching,
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
	mailSendPlaintext       bool
)

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

// startNewThread makes req start a new thread: a fresh client-signed
// conversation ID that the server must not merge into another conversation.
func startNewThread(req *awid.SendMessageRequest) error {
	id, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	req.NewConversation, req.ConversationID = true, id
	return nil
}

// newThreadAnswered refuses a server that answered a new thread with another
// conversation: the message may already be in that conversation, so the
// sender must not retry.
func newThreadAnswered(req *awid.SendMessageRequest, resp *awid.SendMessageResponse) error {
	if req.NewConversation && resp.ConversationID != req.ConversationID {
		return fmt.Errorf("server does not support new conversations: returned a different conversation_id; the message may already have been sent; do not retry automatically")
	}
	return nil
}

var mailSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Start a mail thread, or continue one by its conversation ID",
	Long: mailThreadTeaching + "\n\n" +
		"With a recipient (--to, --to-did or --to-address), send starts a new thread\n" +
		"titled by --subject, which is required. With --conversation-id it continues\n" +
		"that conversation; its title stays the first message's subject, so --subject\n" +
		"is refused there. JSON returns message_id and conversation_id. A server that\n" +
		"answers a new thread with another conversation_id fails without retry; the\n" +
		"message may already have been sent into that conversation.",
	Args: func(cmd *cobra.Command, args []string) error {
		recipient := strings.TrimSpace(mailSendTo+mailSendToDID+mailSendToAddress) != ""
		if strings.TrimSpace(mailSendConversationID) != "" {
			if recipient {
				return usageError("--conversation-id cannot be combined with recipient flags")
			}
			if cmd.Flags().Changed("subject") {
				return usageError("%s", mailTitleFixedText)
			}
			return nil
		}
		if recipient && strings.TrimSpace(mailSendSubject) == "" {
			return usageError("A new thread needs a title: add --subject. To continue a conversation instead: aw mail reply <message_id>")
		}
		return nil
	},
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
		recipientLabel := targetValue

		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		sendEncryptE2EE := mailSendE2EE
		var c *aweb.Client
		var sel *awconfig.Selection
		req := &awid.SendMessageRequest{
			Subject:        mailSendSubject,
			Body:           mailSendBody,
			Priority:       awid.MessagePriority(mailSendPriority),
			ConversationID: strings.TrimSpace(mailSendConversationID),
		}
		if targetKind != "conversation" {
			if err := startNewThread(req); err != nil {
				return err
			}
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
			// /v1/agents lists the team's agents; a name it lacks may be a
			// human on the live roster, which binds the member's current key.
			if _, found, findErr := clientAgentForAlias(ctx, c, targetValue); findErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: recipient lookup failed: %v\n", findErr)
				req.ToAlias = targetValue
			} else if found || sendEncryptE2EE {
				// Key discovery for a human is scoped to the selected team,
				// using its original identity-signed assertion.
				req.ToAlias = targetValue
			} else if liveTarget, liveFound, liveErr := resolveLiveTeamMemberAliasTarget(ctx, sel, targetValue); liveErr != nil {
				debugLog("resolve live team member %s/%s: %v", strings.TrimSpace(sel.TeamID), targetValue, liveErr)
				req.ToAlias = targetValue
			} else if liveFound {
				kind, value := liveTarget.identityTarget()
				applyMailRecipientTarget(req, kind, value)
				// The live team roster already binds the member's current key.
				// Keep it with the stable ID instead of treating the member as
				// an external bare-DID first contact. /v1/agents omits humans.
				req.ToDID = strings.TrimSpace(liveTarget.DIDKey)
				if mailRecipientTargetApplied(req) {
					targetKind = kind
					targetValue = value
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
			req.ToDID = targetValue
		case "address":
			c, sel, err = resolveMailMessagingClientSelection()
			if err != nil {
				return err
			}
			req.ToAddress = targetValue
		default:
			return usageError("missing required recipient flag")
		}

		var resp *awid.SendMessageResponse
		if cmd.Flags().Changed("e2ee") && (mailSendPlaintext || mailSendLegacyPlaintext) {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		req.EncryptE2EE = sendEncryptE2EE
		if req.EncryptE2EE {
			if err := configureClientE2EE(ctx, c, sel, true); err != nil {
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
		if err := newThreadAnswered(req, resp); err != nil {
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
			fmt.Fprintf(commandStdout, "Sent mail in conversation %s (message_id=%s)\n", targetValue, resp.MessageID)
		} else {
			fmt.Fprintf(commandStdout, "Started a new thread with %s: \"%s\" (conversation_id=%s, message_id=%s)\n", termtext.Line(recipientLabel), termtext.Line(strings.TrimSpace(mailSendSubject)), resp.ConversationID, resp.MessageID)
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
	mailReplyPlaintext       bool
)

var mailReplyCmd = &cobra.Command{
	Use:   "reply <message-id>",
	Short: "Reply to an existing mail conversation",
	Long: mailThreadTeaching + "\n\n" +
		"A reply continues the message's conversation, with the subject \"Re: <title>\".\n" +
		"The title is fixed, so --subject is refused.",
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("subject") {
			return usageError("%s", mailTitleFixedText)
		}
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

		// Source reads and reply preparation share the configured API budget;
		// a hidden shorter deadline must not defeat AWEB_HTTP_TIMEOUT.
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		var c *aweb.Client
		var sel *awconfig.Selection
		awid.RecordHTTPDiagnosticPhase("client_selection_started")
		c, sel, err = resolveMailMessagingClientSelection()
		if err != nil {
			return err
		}
		awid.RecordHTTPDiagnosticPhase("client_selection_ready")
		if cmd.Flags().Changed("e2ee") && (mailReplyPlaintext || mailReplyLegacyPlaintext) {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		awid.RecordHTTPDiagnosticPhase("key_read_started")
		if err := configureClientE2EE(ctx, c, sel, false); err != nil {
			var unavailable *e2eeDecryptionUnavailableError
			if !errors.As(err, &unavailable) {
				return err
			}
			// Plaintext replies need no read key. An encrypted source fails
			// below with its decryption error and recovery guidance.
		}
		awid.RecordHTTPDiagnosticPhase("key_read_ready")
		inbox, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: false,
			Limit:      1,
			MessageID:  messageID,
		})
		if err != nil {
			if awconfig.IsGrantHome(sel.IdentityHome) && err.Error() == "archived_key_unavailable" {
				err = fmt.Errorf("%w; ask the resident host to restore the encryption key for this source message", err)
			}
			return networkError(err, messageID)
		}
		if len(inbox.Messages) == 0 {
			return fmt.Errorf("mail message not found: %s", messageID)
		}
		encryptReply := mailReplyE2EE
		if !cmd.Flags().Changed("e2ee") && !mailReplyPlaintext && !mailReplyLegacyPlaintext {
			source := inbox.Messages[0]
			encryptReply = source.ContentMode == awid.ContentModeEncryptedV2 || source.MessageVersion == awid.E2EEMessageVersion || source.Encrypted != nil
		}
		if encryptReply {
			if err := configureClientE2EE(ctx, c, sel, true); err != nil {
				return err
			}
		}
		conversationID := strings.TrimSpace(inbox.Messages[0].ConversationID)
		if conversationID == "" {
			return fmt.Errorf("message %s is legacy mail without a conversation; send a new message instead", messageID)
		}
		subject := replySubject("", inbox.Messages[0].Subject)
		req := &awid.SendMessageRequest{
			ConversationID: conversationID,
			Subject:        subject,
			Body:           body,
			Priority:       awid.MessagePriority(mailReplyPriority),
			EncryptE2EE:    encryptReply,
			E2EEInherited:  encryptReply && !cmd.Flags().Changed("e2ee"),
		}
		if encryptReply && inbox.Messages[0].Encrypted != nil {
			source := inbox.Messages[0]
			if source.MessageID != messageID {
				return fmt.Errorf("reply source does not match requested message %s", messageID)
			}
			recipient, err := c.MailReplyRecipient(ctx, source)
			if err != nil {
				return err
			}
			req.ReplyToMessageID = source.MessageID
			req.E2EERecipient = &recipient
			req.ToDID = recipient.DID
			req.ToStableID = recipient.StableID
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
			fmt.Fprintf(commandStdout, "Sent mail in conversation %s (message_id=%s)\n", conversationID, resp.MessageID)
		}
		return nil
	},
}

// resolveMailBody returns the message body, sourcing it from --body or
// --body-file. Reading from a file bypasses shell interpolation. Exactly one
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
	contents, err := readFileBounded(bodyFileArg, maxBodyFileBytes)
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

type e2eeDecryptionUnavailableError struct {
	statePath string
	reason    string
}

func (e *e2eeDecryptionUnavailableError) Error() string {
	return fmt.Sprintf("E2E decryption unavailable: %s at %s", e.reason, e.statePath)
}

func configureClientE2EEForRead(cmd *cobra.Command, ctx context.Context, c *aweb.Client, sel *awconfig.Selection) error {
	err := configureClientE2EE(ctx, c, sel, false)
	var unavailable *e2eeDecryptionUnavailableError
	if errors.As(err, &unavailable) {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: %v\n", unavailable)
		return nil
	}
	return err
}

func configureClientE2EE(ctx context.Context, c *aweb.Client, sel *awconfig.Selection, required bool) error {
	if c == nil || c.Client == nil || sel == nil {
		return usageError("E2E messaging requires an initialized self-custodial workspace")
	}
	if awconfig.IsGrantHome(sel.IdentityHome) {
		grant, err := awconfig.LoadGrantHome(sel.IdentityHome)
		if err == nil && strings.TrimSpace(grant.Custody.SocketPath) != "" {
			return nil
		}
		if required {
			return usageError("E2E messaging under an identity grant requires a local custody socket; ask the resident host to run `aw custody serve`, or pass --plaintext only for explicit server-readable messaging")
		}
		return &e2eeDecryptionUnavailableError{statePath: awconfig.GrantHomeStatePath(sel.IdentityHome), reason: "grant home has no custody.socket_path; ask the resident host to run `aw custody serve` and mint or attach the grant custody socket"}
	}
	if required {
		if err := ensureE2EEKeyReadyForSend(ctx, sel); err != nil {
			return err
		}
	}
	statePath := awconfig.WorktreeEncryptionStatePath(sel.WorkingDir)
	if strings.TrimSpace(sel.IdentityHome) != "" {
		var pathErr error
		statePath, pathErr = awconfig.IdentityHomePath(awconfig.IdentityHome{Root: sel.IdentityHome}, "encryption.yaml")
		if pathErr != nil {
			return pathErr
		}
	}
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			if !required {
				return &e2eeDecryptionUnavailableError{statePath: statePath, reason: "no encryption key state found"}
			}
			return usageError("E2E messaging requires a local encryption key; upgrade aw and run `aw id encryption-key setup`, or pass --plaintext only for explicit server-readable messaging")
		}
		return err
	}
	record := state.ActiveRecord()
	if record == nil {
		if !required {
			return &e2eeDecryptionUnavailableError{statePath: statePath, reason: "no active encryption key in state"}
		}
		return usageError("E2E messaging requires an active local encryption key; upgrade aw and run `aw id encryption-key setup`, or pass --plaintext only for explicit server-readable messaging")
	}
	material, err := validateEncryptionRecordPrivateKeyAt(sel.WorkingDir, sel.IdentityHome, record)
	if err != nil {
		return err
	}
	assertion, err := loadEncryptionAssertionAt(sel.WorkingDir, sel.IdentityHome, record.AssertionPath)
	if err != nil {
		return err
	}
	identity := e2eeAssertionIdentityForSelection(sel)
	if !required {
		if err := validateEncryptionRecordForRead(identity, record, assertion, material); err != nil && !shouldRefreshEncryptionKeyForIdentityBinding(err) {
			return err
		}
		if expiry, err := time.Parse(time.RFC3339Nano, assertion.ExpiresAt); err == nil && !expiry.After(time.Now()) {
			fmt.Fprintln(os.Stderr, "Warning: local E2E encryption-key assertion is expired; existing messages remain decryptable; run `aw id encryption-key setup` to renew publication.")
		}
	} else if err := validateEncryptionRecordAssertion(identity, record, assertion, material); err != nil {
		return err
	}
	privatePath, err := resolveIdentityStoredPath(sel.WorkingDir, sel.IdentityHome, record.PrivateKeyPath)
	if err != nil {
		return err
	}
	privateKey, err := awid.LoadX25519PrivateKey(privatePath)
	if err != nil {
		return err
	}
	c.Client.SetE2EEKey(assertion, privateKey)
	return nil
}

func ensureE2EEKeyReadyForSend(ctx context.Context, sel *awconfig.Selection) error {
	identityHome := currentEncryptionKeyIdentityHome()
	if sel.ExternalIdentityHome {
		// Only external selection uses the explicit resolver. Ordinary homes
		// retain active-certificate precedence over stale identity.yaml state.
		// External certificate-only homes must never fall back to the cwd.
		identityHome = explicitEncryptionKeyIdentityHome(sel.IdentityHome)
	}
	out, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, sel.WorkingDir, false, identityHome)
	if err != nil {
		return err
	}
	if len(out.Published) == 0 {
		return usageError("E2E messaging requires a published encryption key; run `aw id encryption-key setup` after joining a service, or pass --plaintext only for explicit server-readable messaging")
	}
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
	var identity *awconfig.ResolvedIdentity
	var err error
	if strings.TrimSpace(sel.IdentityHome) != "" {
		identity, err = awconfig.ResolveIdentityFromHome(sel.WorkingDir, sel.IdentityHome)
	} else {
		identity, err = awconfig.ResolveIdentity(sel.WorkingDir)
	}
	if err == nil {
		identityDID := strings.TrimSpace(identity.DID)
		if identityDID != "" && (did == "" || identityDID == did) {
			did = identityDID
			if stableID == "" && strings.TrimSpace(sel.IdentityScope) != awid.IdentityModeLocal {
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
	mailInboxCountOnly bool
	mailInboxShowAll   bool
	mailInboxLimit     int
	mailInboxCursor    string
)

// countUnreadMail walks read-only inbox pages without decrypting, verifying,
// presenting, logging or acknowledging their content. Older servers need no
// new endpoint; a failed continuation never becomes a partial successful count.
func countUnreadMail(ctx context.Context, client *aweb.Client) (int, error) {
	count := 0
	cursor := ""
	seen := map[string]bool{}
	for {
		path := "/v1/messages/inbox?unread_only=true&limit=200"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		var page struct {
			Messages   []json.RawMessage `json:"messages"`
			HasMore    bool              `json:"has_more"`
			NextCursor string            `json:"next_cursor"`
		}
		if err := client.Get(ctx, path, &page); err != nil {
			return 0, err
		}
		count += len(page.Messages)
		if !page.HasMore {
			return count, nil
		}
		cursor = strings.TrimSpace(page.NextCursor)
		if cursor == "" || seen[cursor] {
			return 0, errors.New("unread mail count: invalid inbox continuation")
		}
		seen[cursor] = true
	}
}

func presentAndAcknowledgeMailInbox(
	ctx context.Context,
	writer io.Writer,
	client *aweb.Client,
	resp *awid.InboxResponse,
) error {
	if err := writeOutput(writer, resp, formatMailInbox); err != nil {
		return fmt.Errorf("present mail inbox: %w", err)
	}
	// Acknowledgements remain best effort, but cannot precede presentation.
	for _, msg := range resp.Messages {
		if msg.ReadAt == nil && msg.MessageID != "" {
			_, _ = client.AckMessage(ctx, msg.MessageID)
		}
	}
	return nil
}

var mailInboxCmd = &cobra.Command{
	Use:   "inbox",
	Short: "List inbox messages (unread only by default)",
	Long: "List inbox messages, newest first and unread only by default. Messages shown by this command are acknowledged as read.\n\n" +
		"Use --count-only to count all unread mail without acknowledging or displaying messages. This read-only count walks inbox pages and does not decrypt message content.\n\n" +
		"Without --count-only, the response is one bounded page. Text output reports when more messages exist and prints a continuation command; JSON output carries has_more and next_cursor. Pass the returned value to --cursor to continue without overlap.",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("count-only") {
			for _, flag := range []string{"show-all", "limit", "cursor"} {
				if cmd.Flags().Changed(flag) {
					scope := "every page"
					if flag == "show-all" {
						scope = "unread messages"
					}
					return fmt.Errorf("--count-only counts %s, so it cannot be combined with --%s.", scope, flag)
				}
			}
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if mailInboxCountOnly {
			count, err := countUnreadMail(ctx, c)
			if err != nil {
				return err
			}
			result := struct {
				UnreadCount int `json:"unread_count"`
			}{count}
			return writeOutput(cmd.OutOrStdout(), result, func(any) string {
				unit := "messages"
				if count == 1 {
					unit = "message"
				}
				return fmt.Sprintf("%d unread %s\n", count, unit)
			})
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		resp, err := c.Inbox(ctx, awid.InboxParams{
			UnreadOnly: !mailInboxShowAll,
			Limit:      mailInboxLimit,
			Cursor:     mailInboxCursor,
		})
		if err != nil {
			return err
		}
		if err := presentAndAcknowledgeMailInbox(ctx, cmd.OutOrStdout(), c, resp); err != nil {
			return err
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
		return nil
	},
}

var (
	mailShowConversationID string
	mailShowMessageID      string
	mailShowLimit          int
)

func formatMailAck(v any) string {
	resp, ok := v.(*awid.AckResponse)
	if !ok || resp == nil {
		return ""
	}
	if resp.AcknowledgedAt != "" {
		return fmt.Sprintf("Acknowledged mail %s at %s\n", resp.MessageID, resp.AcknowledgedAt)
	}
	return fmt.Sprintf("Acknowledged mail %s\n", resp.MessageID)
}

var mailAckCmd = &cobra.Command{
	Use:   "ack <message-id>",
	Short: "Acknowledge one mail message as read",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		messageID := strings.TrimSpace(args[0])
		if messageID == "" {
			return usageError("message id is required")
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, _, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.AckMessage(ctx, messageID)
		if err != nil {
			return err
		}
		printOutput(resp, formatMailAck)
		return nil
	},
}

var mailShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show a mail conversation or exact message",
	// Which end the conversation window takes belongs in the help rather than only
	// in the output, because a reader deciding whether this command can answer "did
	// I miss something recent" needs it BEFORE they run it and believe the result.
	Long: "Show mail by conversation or exact message ID.\n\n" +
		"With --message-id, one unique message is selected. The conversation-window " +
		"direction and 500-message ceiling below do not apply.\n\n" +
		"With --conversation-id, --limit caps how many messages are returned and defaults " +
		"to 200. The messages returned are the OLDEST ones, so on a conversation longer " +
		"than the limit the newest messages are the ones missing - which is the opposite " +
		"of what someone checking for recent mail expects.\n\n" +
		"aw mail inbox windows from the other end and has a different default and ceiling. " +
		"Do not carry an expectation from one command to the other.\n\n" +
		"To read a whole conversation, pass --limit above its length and check the " +
		"returned count. If it equals the limit, there may be more; raise it and re-run, up to " +
		"500. At the 500-message ceiling, an exact full window cannot establish completeness. " +
		"The conversation endpoint rejects higher limits and has no paging flag, so a " +
		"conversation longer than 500 messages cannot be returned whole by this command.",
	RunE: func(cmd *cobra.Command, args []string) error {
		conversationID := strings.TrimSpace(mailShowConversationID)
		messageID := strings.TrimSpace(mailShowMessageID)
		if conversationID == "" && messageID == "" {
			return usageError("missing required flag: --conversation-id or --message-id")
		}
		if conversationID != "" && messageID != "" {
			return usageError("--conversation-id and --message-id are mutually exclusive")
		}

		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		// Same client selection as mail send/reply: certificate-authenticated
		// when the workspace has one, identity-auth fallback otherwise. Reads
		// are DID-scoped server-side under either credential, but the
		// certificate client can also verify senders against the team roster;
		// mail show choosing identity-auth unconditionally is what rendered
		// every current-team sender as [verification stale] (aweb-abfc).
		c, sel, err := resolveMailMessagingClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		var resp *awid.InboxResponse
		if messageID != "" {
			resp, err = c.Message(ctx, messageID)
		} else {
			resp, err = c.MailConversation(ctx, conversationID, mailShowLimit)
		}
		if err != nil {
			if conversationID != "" {
				return mailShowConversationError(err, conversationID)
			}
			return networkError(err, messageID)
		}
		// The text formatter carries this notice inline. JSON output must stay a
		// clean parseable document, so it goes to stderr - where a human still sees
		// it and a consumer reading stdout is unaffected. Without this, the
		// machine-readable path is the one surface that reports a partial read as a
		// whole one with nothing anywhere to say otherwise.
		if jsonFlag && conversationID != "" {
			if notice := mailWindowNotice(len(resp.Messages), mailShowLimit); notice != "" {
				fmt.Fprintln(os.Stderr, strings.TrimSpace(notice))
			}
		}
		formatter := formatMailExactMessage
		if conversationID != "" {
			formatter = formatMailConversation
		}
		printOutput(resp, formatter)
		return nil
	},
}

func init() {
	mailSendCmd.Flags().StringVar(&mailSendTo, "to", "", "Recipient name within the active team, or a routable address")
	mailSendCmd.Flags().StringVar(&mailSendToDID, "to-did", "", "Recipient stable identity (did:aw:...)")
	mailSendCmd.Flags().StringVar(&mailSendToAddress, "to-address", "", "Recipient address (domain/name)")
	mailSendCmd.Flags().StringVar(&mailSendSubject, "subject", "", "Title of the new thread (required with a recipient)")
	mailSendCmd.Flags().StringVar(&mailSendBody, "body", "", shellExpandedInlineHelp("Body", "--body-file"))
	mailSendCmd.Flags().StringVar(&mailSendBodyFile, "body-file", "", safeFileInputHelp("message body"))
	mailSendCmd.Flags().StringVar(&mailSendPriority, "priority", "normal", "Priority: low|normal|high|urgent")
	mailSendCmd.Flags().StringVar(&mailSendConversationID, "conversation-id", "", "Existing mail conversation to continue (no recipient or --subject)")
	mailSendCmd.Flags().BoolVar(&mailSendPlaintext, "plaintext", false, "Send explicit server-readable plaintext mail (currently the default)")
	mailSendCmd.Flags().BoolVar(&mailSendE2EE, "e2ee", false, "Send E2E encrypted mail; fails closed if encryption keys are missing")
	mailSendCmd.Flags().BoolVar(&mailSendLegacyPlaintext, "legacy-plaintext", false, "Deprecated alias for --plaintext")
	_ = mailSendCmd.Flags().MarkHidden("legacy-plaintext")

	mailInboxCmd.Flags().BoolVar(&mailInboxCountOnly, "count-only", false, "Count all unread mail without acknowledging or displaying messages")
	mailInboxCmd.Flags().BoolVar(&mailInboxShowAll, "show-all", false, "Show all messages including already-read")
	mailInboxCmd.Flags().IntVar(&mailInboxLimit, "limit", 50, "Max messages per page")
	mailInboxCmd.Flags().StringVar(&mailInboxCursor, "cursor", "", "Continue from next_cursor in a previous inbox response")
	// Kept only to refuse it in words: a conversation's title is fixed.
	mailReplyCmd.Flags().StringVar(&mailReplySubject, "subject", "", "Refused: a conversation's title is fixed")
	_ = mailReplyCmd.Flags().MarkHidden("subject")
	mailReplyCmd.Flags().StringVar(&mailReplyBody, "body", "", shellExpandedInlineHelp("Body", "--body-file"))
	mailReplyCmd.Flags().StringVar(&mailReplyBodyFile, "body-file", "", safeFileInputHelp("message body"))
	mailReplyCmd.Flags().StringVar(&mailReplyPriority, "priority", "normal", "Priority: low|normal|high|urgent")
	mailReplyCmd.Flags().BoolVar(&mailReplyPlaintext, "plaintext", false, "Send explicit server-readable plaintext mail, even when replying to encrypted mail")
	mailReplyCmd.Flags().BoolVar(&mailReplyE2EE, "e2ee", false, "Send E2E encrypted mail (default for an encrypted source, except to a recipient on aweb's hosted service, which gets server-readable mail); fails closed if encryption keys are missing")
	mailReplyCmd.Flags().BoolVar(&mailReplyLegacyPlaintext, "legacy-plaintext", false, "Deprecated alias for --plaintext")
	_ = mailReplyCmd.Flags().MarkHidden("legacy-plaintext")
	mailShowCmd.Flags().StringVar(&mailShowConversationID, "conversation-id", "", "Mail conversation to inspect")
	mailShowCmd.Flags().StringVar(&mailShowMessageID, "message-id", "", "Legacy mail message to inspect")
	mailShowCmd.Flags().IntVar(&mailShowLimit, "limit", 200, "For --conversation-id, max messages from the OLDEST end; exact --message-id reads are not windowed")

	mailThreadsCmd.Flags().IntVar(&mailThreadsLimit, "limit", 50, "Max threads per page")
	mailThreadsCmd.Flags().StringVar(&mailThreadsCursor, "cursor", "", "Continue from next_cursor in a previous threads response")
	mailCmd.AddCommand(mailSendCmd, mailReplyCmd, mailInboxCmd, mailShowCmd, mailAckCmd, mailThreadsCmd)
	rootCmd.AddCommand(mailCmd)
}

// replySubject is the subject of a reply: the explicit one when given,
// otherwise "Re: <original>", never prefixed twice.
func replySubject(explicit, original string) string {
	if subject := strings.TrimSpace(explicit); subject != "" {
		return subject
	}
	original = strings.TrimSpace(original)
	switch {
	case original == "":
		return "Re"
	case len(original) >= 3 && strings.EqualFold(original[:3], "re:"):
		return original
	default:
		return "Re: " + original
	}
}

var (
	mailThreadsLimit  int
	mailThreadsCursor string
)

var mailThreadsCmd = &cobra.Command{
	Use:   "threads",
	Short: "List your mail threads",
	Long: "List your mail conversations, newest activity first: each thread's title (its\n" +
		"first message's subject), participants, last activity, unread count and\n" +
		"conversation ID. Listing marks nothing read.\n\n" + mailThreadTeaching,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()
		c, sel, err := resolveMailMessagingClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.ListConversationsWithParams(ctx, awid.ConversationListParams{
			Limit:            mailThreadsLimit,
			Cursor:           strings.TrimSpace(mailThreadsCursor),
			ConversationType: "mail",
		})
		if err != nil {
			return err
		}
		if err := readEncryptedThreadTitles(cmd, ctx, c, sel, resp); err != nil {
			return err
		}
		if jsonFlag {
			printOutput(resp, formatMailThreads)
		} else {
			printOutput(threadsWithoutSelf(resp, sel), formatMailThreads)
		}
		return nil
	},
}

// readEncryptedThreadTitles fills the title the server cannot read: an
// end-to-end encrypted first message's subject, decrypted from that message.
// A title that cannot be read stays empty.
func readEncryptedThreadTitles(cmd *cobra.Command, ctx context.Context, c *aweb.Client, sel *awconfig.Selection, resp *awid.ConversationsResponse) error {
	configured := false
	for i := range resp.Conversations {
		thread := &resp.Conversations[i]
		firstID := strings.TrimSpace(thread.FirstMessageID)
		if strings.TrimSpace(thread.Title) != "" || firstID == "" {
			continue
		}
		if !configured {
			if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
				return err
			}
			configured = true
		}
		first, err := c.Message(ctx, firstID)
		if err != nil || first == nil || len(first.Messages) == 0 {
			continue
		}
		thread.Title = first.Messages[0].Subject
	}
	return nil
}

// threadsWithoutSelf is the text listing's view: each thread names the other
// participants, not you. JSON keeps the server's participant list.
func threadsWithoutSelf(resp *awid.ConversationsResponse, sel *awconfig.Selection) *awid.ConversationsResponse {
	self := map[string]bool{}
	if sel != nil {
		for _, label := range []string{sel.Alias, selectionAddress(sel)} {
			if label = strings.TrimSpace(label); label != "" {
				self[label] = true
			}
		}
	}
	view := *resp
	view.Conversations = make([]awid.ConversationItem, len(resp.Conversations))
	for i, thread := range resp.Conversations {
		others := make([]string, 0, len(thread.Participants))
		for _, participant := range thread.Participants {
			if !self[strings.TrimSpace(participant)] {
				others = append(others, participant)
			}
		}
		thread.Participants = others
		view.Conversations[i] = thread
	}
	return &view
}
