package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// Write-side verbs of the beads mail delegate, per docs/beads-mail-delegate.md
// §6, §8, §9. Threading is always explicit (a plain send opens a fresh
// conversation; reply and --reply-to continue the source's conversation by
// id) — never the opportunistic auto-threading of `aw mail send`. v1 sends
// plaintext, as `aw mail` defaults today.

const beadsMailBodyLimit = 10 << 20

// beadsMailEnvelope is the fenced beads-mail body block (§9): the carrier for
// gt-shaped structure aweb mail has no field for. Emitted only when it holds
// non-default values, so plain messages stay plain.
type beadsMailEnvelope struct {
	V         int    `json:"v"`
	Type      string `json:"type,omitempty"`
	Priority  *int   `json:"priority,omitempty"`
	Pinned    bool   `json:"pinned,omitempty"`
	Ephemeral *bool  `json:"ephemeral,omitempty"`
}

func (e beadsMailEnvelope) empty() bool {
	return e.Type == "" && e.Priority == nil && !e.Pinned && e.Ephemeral == nil
}

func appendBeadsMailEnvelope(body string, env beadsMailEnvelope) string {
	if env.empty() {
		return body
	}
	env.V = 1
	encoded, err := json.Marshal(env)
	if err != nil {
		return body
	}
	return strings.TrimRight(body, "\n") + "\n\n```beads-mail\n" + string(encoded) + "\n```\n"
}

// beadsMailPriorityToAweb maps beads 0-4 onto the aweb enum (§9). high|urgent
// are the wake lever; beads 4 (backlog) folds into low.
func beadsMailPriorityToAweb(p int) awid.MessagePriority {
	switch {
	case p <= 0:
		return awid.PriorityUrgent
	case p == 1:
		return awid.PriorityHigh
	case p == 2:
		return awid.PriorityNormal
	default:
		return awid.PriorityLow
	}
}

var (
	beadsMailSendSubject   string
	beadsMailSendBody      string
	beadsMailSendBodyAlias string
	beadsMailSendStdin     bool
	beadsMailSendPriority  int
	beadsMailSendUrgent    bool
	beadsMailSendType      string
	beadsMailSendReplyTo   string
	beadsMailSendTo        string
	beadsMailSendSelf      bool
	beadsMailSendFrom      string
	beadsMailSendCC        []string
	beadsMailSendNotify    bool
	beadsMailSendNoNotify  bool
	beadsMailSendPinned    bool
	beadsMailSendWisp      bool
	beadsMailSendPermanent bool
)

var beadsMailSendCmd = &cobra.Command{
	Use:   "send <address>",
	Short: "Send a message",
	Long: `Send mail to a beads-style name (mapped in .beads/aweb-mail.toml), an
aweb address like acme.aweb.ai/reviewer, or a did:aw identity. The
resolved address is always shown: mail goes out under this workspace's
cryptographically verified identity.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(beadsMailSendFrom) != "" {
			return usageError("--from is not supported: beads-mail sender identity is cryptographic, not asserted; mail goes out as this workspace's verified aweb identity")
		}
		if len(beadsMailSendCC) > 0 {
			return usageError("--cc is not supported in v1: aweb mail is one recipient per message; send to each recipient separately")
		}
		recipient, err := beadsMailSendRecipientArg(args)
		if err != nil {
			return err
		}
		if beadsMailSendSelf && strings.TrimSpace(beadsMailSendReplyTo) != "" {
			// A continuation delivers to the conversation's counterparty; a
			// self-named continuation would make the disclosure line lie
			// (the involves-check cannot catch it: the sender is always a
			// participant of any message they can read).
			return usageError("--self and --reply-to cannot be combined: a continuation goes to the conversation's counterparty, not to yourself")
		}
		if strings.TrimSpace(beadsMailSendSubject) == "" {
			return usageError("-s/--subject is required")
		}
		mailType := strings.TrimSpace(beadsMailSendType)
		if !beadsMailSupportedType(mailType) {
			return usageError("--type must be one of: task, scavenge, notification, reply")
		}
		body, err := beadsMailResolveBody(cmd, beadsMailSendBody, beadsMailSendBodyAlias, beadsMailSendStdin, "")
		if err != nil {
			return err
		}
		if beadsMailSendPriority < 0 || beadsMailSendPriority > 4 {
			return usageError("--priority must be 0-4 (0=urgent, 1=high, 2=normal, 3=low, 4=backlog)")
		}
		beadsPriority := beadsMailSendPriority
		if beadsMailSendUrgent {
			beadsPriority = 0
		}
		awebPriority := beadsMailPriorityToAweb(beadsPriority)
		if beadsMailSendNotify && awebPriority != awid.PriorityUrgent {
			awebPriority = awid.PriorityHigh
		}
		if beadsMailSendNoNotify && (awebPriority == awid.PriorityHigh || awebPriority == awid.PriorityUrgent) {
			fmt.Fprintln(os.Stderr, "note: high and urgent mail always wakes the recipient; --no-notify cannot suppress that. Lower the priority to send quietly.")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		// --self never needs the map; a malformed map must not break it
		// (dual-write just stays off, like reply's tolerant load).
		addressMap, mapErr := loadBeadsMailAddressMap(cwd)
		if mapErr != nil && !beadsMailSendSelf {
			return mapErr
		}
		var target beadsMailTarget
		if !beadsMailSendSelf {
			target, err = resolveBeadsMailRecipient(addressMap, recipient)
			if err != nil {
				return err
			}
		}

		var c *aweb.Client
		var sel *awconfig.Selection
		if target.Kind == "alias" {
			c, sel, err = resolveClientSelectionForAliasTarget(ctx, target.Value)
		} else {
			c, sel, err = resolveMailMessagingClientSelection()
		}
		if err != nil {
			return beadsMailClientError(err)
		}
		beadsMailIdentifyTransport(c)
		if beadsMailSendSelf {
			target, err = beadsMailSelfTarget(sel)
			if err != nil {
				return err
			}
		}

		env := beadsMailEnvelope{}
		if mailType != "notification" {
			env.Type = mailType
		}
		if beadsPriority != 2 {
			p := beadsPriority
			env.Priority = &p
		}
		if beadsMailSendPinned {
			env.Pinned = true
		}
		if beadsMailSendPermanent || cmd.Flags().Changed("wisp") && !beadsMailSendWisp {
			ephemeral := false
			env.Ephemeral = &ephemeral
		}

		req := &awid.SendMessageRequest{
			Subject:  beadsMailSendSubject,
			Body:     appendBeadsMailEnvelope(body, env),
			Priority: awebPriority,
		}

		if replyTo := strings.TrimSpace(beadsMailSendReplyTo); replyTo != "" {
			source, err := beadsMailSourceMessage(ctx, c, replyTo)
			if err != nil {
				return err
			}
			conversationID := strings.TrimSpace(source.ConversationID)
			if conversationID == "" {
				return fmt.Errorf("--reply-to message %s is legacy mail without a conversation", replyTo)
			}
			// The recipient argument stays a CHECK, not a routing input: a
			// continuation routes by conversation (the server requires the
			// signed recipient to match the conversation's, so the client's
			// rediscovery must fill it — found live 2026-09-01), and the
			// named recipient must actually be that conversation's
			// counterparty or the disclosure line would lie. The check only
			// refuses an actual mismatch: a message whose identity fields
			// are all empty (key rotation can blank the derived
			// address/stable-id) cannot be verified and proceeds — reply is
			// always the recipient-free escape hatch either way.
			if known, matches := beadsMailReplyToTargetMatches(source, sel, target.Value); known && !matches {
				return usageError("--reply-to message %s is a conversation with %s, not with %s; drop --reply-to or name that correspondent", replyTo, sanitizeBeadsMailDisplay(beadsMailCounterpartyLabel(source, sel)), sanitizeBeadsMailDisplay(target.Value))
			}
			req.ConversationID = conversationID
		} else {
			applyMailRecipientTarget(req, target.Kind, target.Value)
		}

		var resp *awid.SendMessageResponse
		if beadsMailUsesCertSend(target.Kind, req.ConversationID) {
			resp, err = c.SendMessage(ctx, req)
		} else {
			resp, err = c.SendMessageByIdentity(ctx, req)
		}
		if err != nil && req.ConversationID == "" {
			resp, err = beadsMailRetryAsContinuation(ctx, c, target, req, err)
		}
		if err != nil {
			return networkError(err, target.Value)
		}

		beadsMailAppendSendLogs(sel, resp, target.Value, beadsMailSendSubject, body)
		fmt.Printf("sent %s (message_id=%s conversation_id=%s)\n", beadsMailResolutionNote(target), resp.MessageID, resp.ConversationID)
		if mapErr != nil {
			beadsMailRecordGap("could not read the beads mail configuration: " + mapErr.Error())
		} else {
			beadsMailRecordBead(sel, addressMap, beadsMailSendSubject, body, resp, strings.TrimSpace(beadsMailSendReplyTo), env)
		}
		return nil
	},
}

var (
	beadsMailReplySubject   string
	beadsMailReplyBody      string
	beadsMailReplyBodyAlias string
	beadsMailReplyStdin     bool
)

var beadsMailReplyCmd = &cobra.Command{
	Use:   "reply <message-id> [message]",
	Short: "Reply to a message",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
			return usageError("usage: bd mail reply <message-id> [message]")
		}
		if len(args) > 2 {
			return usageError("usage: bd mail reply <message-id> [message]")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		messageID := strings.TrimSpace(args[0])
		positional := ""
		if len(args) == 2 {
			positional = args[1]
		}
		body, err := beadsMailResolveBody(cmd, beadsMailReplyBody, beadsMailReplyBodyAlias, beadsMailReplyStdin, positional)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, sel, err := resolveMailMessagingClientSelection()
		if err != nil {
			return beadsMailClientError(err)
		}
		beadsMailIdentifyTransport(c)
		source, err := beadsMailSourceMessage(ctx, c, messageID)
		if err != nil {
			return err
		}
		conversationID := strings.TrimSpace(source.ConversationID)
		if conversationID == "" {
			return fmt.Errorf("message %s is legacy mail without a conversation; send a new message instead", messageID)
		}
		subject := strings.TrimSpace(beadsMailReplySubject)
		if subject == "" {
			original := strings.TrimSpace(source.Subject)
			if original == "" {
				subject = "Re"
			} else if strings.HasPrefix(original, "Re: ") {
				subject = original
			} else {
				subject = "Re: " + original
			}
		}

		req := &awid.SendMessageRequest{
			ConversationID: conversationID,
			Subject:        subject,
			Body:           body,
			Priority:       awid.PriorityNormal,
		}
		resp, err := c.SendMessageByIdentity(ctx, req)
		if err != nil {
			return err
		}
		if _, ackErr := c.AckMessage(ctx, messageID); ackErr != nil {
			fmt.Fprintf(os.Stderr, "note: reply was sent, but the source message could not be marked read: %s\n", sanitizeBeadsMailDisplay(ackErr.Error()))
		}
		beadsMailAppendSendLogs(sel, resp, conversationID, subject, body)
		fmt.Printf("replied (message_id=%s conversation_id=%s)\n", resp.MessageID, resp.ConversationID)
		if cwd, cwdErr := os.Getwd(); cwdErr != nil {
			beadsMailRecordGap("could not locate the beads repository: " + cwdErr.Error())
		} else if addressMap, mapErr := loadBeadsMailAddressMap(cwd); mapErr != nil {
			beadsMailRecordGap("could not read the beads mail configuration: " + mapErr.Error())
		} else {
			beadsMailRecordBead(sel, addressMap, subject, body, resp, messageID, beadsMailEnvelope{})
		}
		return nil
	},
}

// beadsMailUsesCertSend implements the design record §5 dispatch split: a
// same-team alias sends certificate-authenticated, but EVERY conversation
// continuation — reply and send --reply-to included — goes by identity, so
// the signed sender is always the workspace's verified identity rather than a
// team-local alias.
func beadsMailUsesCertSend(kind, conversationID string) bool {
	return kind == "alias" && strings.TrimSpace(conversationID) == ""
}

func beadsMailSupportedType(value string) bool {
	switch value {
	case "task", "scavenge", "notification", "reply":
		return true
	default:
		return false
	}
}

func beadsMailMessageSideIdentifiers(alias, address, did, stableID string) []string {
	var identifiers []string
	for _, candidate := range []string{address, alias, did, stableID} {
		if value := strings.TrimSpace(candidate); value != "" {
			identifiers = append(identifiers, value)
		}
	}
	return identifiers
}

func beadsMailSelectionIdentifiers(sel *awconfig.Selection) []string {
	if sel == nil {
		return nil
	}
	return beadsMailMessageSideIdentifiers(sel.Alias, selectionAddress(sel), sel.DID, sel.StableID)
}

func beadsMailIdentifiersOverlap(left, right []string) bool {
	for _, value := range left {
		if beadsMailValueAmong(value, right) {
			return true
		}
	}
	return false
}

// beadsMailCounterpartyIdentifiers identifies the side of the source message
// that is not this workspace. If old or rotated message data cannot identify
// the local side, all non-empty participants remain the conservative fallback;
// an entirely blank legacy row is unverifiable and deliberately fails open.
func beadsMailCounterpartyIdentifiers(msg *awid.InboxMessage, sel *awconfig.Selection) ([]string, bool) {
	if msg == nil {
		return nil, false
	}
	from := beadsMailMessageSideIdentifiers(msg.FromAlias, msg.FromAddress, msg.FromDID, msg.FromStableID)
	to := beadsMailMessageSideIdentifiers(msg.ToAlias, msg.ToAddress, msg.ToDID, msg.ToStableID)
	all := append(append([]string{}, from...), to...)
	if len(all) == 0 {
		return nil, false
	}
	self := beadsMailSelectionIdentifiers(sel)
	fromIsSelf := beadsMailIdentifiersOverlap(from, self)
	toIsSelf := beadsMailIdentifiersOverlap(to, self)
	switch {
	case fromIsSelf && !toIsSelf:
		return to, true
	case toIsSelf && !fromIsSelf:
		return from, true
	case fromIsSelf && toIsSelf:
		return nil, true
	default:
		return all, true
	}
}

func beadsMailReplyToTargetMatches(msg *awid.InboxMessage, sel *awconfig.Selection, target string) (known, matches bool) {
	participants, known := beadsMailCounterpartyIdentifiers(msg, sel)
	if !known {
		return false, true
	}
	// A conversation continuation always routes to the other side. Naming
	// ourselves through an address, alias, or DID would make the disclosure
	// line lie even though our identity is naturally one of the participants.
	if beadsMailValueAmong(target, beadsMailSelectionIdentifiers(sel)) {
		return true, false
	}
	return true, beadsMailValueAmong(target, participants)
}

func beadsMailValueAmong(value string, candidates []string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func beadsMailCounterpartyLabel(msg *awid.InboxMessage, sel *awconfig.Selection) string {
	if participants, known := beadsMailCounterpartyIdentifiers(msg, sel); known {
		for _, candidate := range participants {
			if strings.TrimSpace(candidate) != "" {
				return strings.TrimSpace(candidate)
			}
		}
	}
	return "an unidentified correspondent"
}

func beadsMailSendRecipientArg(args []string) (string, error) {
	positional := ""
	if len(args) > 1 {
		return "", usageError("send takes one recipient; got %d arguments", len(args))
	}
	if len(args) == 1 {
		positional = strings.TrimSpace(args[0])
	}
	flagTo := strings.TrimSpace(beadsMailSendTo)
	set := 0
	for _, v := range []bool{positional != "", flagTo != "", beadsMailSendSelf} {
		if v {
			set++
		}
	}
	if set == 0 {
		return "", usageError("recipient is required: bd mail send <address> (or --to, or --self)")
	}
	if set > 1 {
		return "", usageError("give exactly one recipient: the positional address, --to, or --self")
	}
	if positional != "" {
		return positional, nil
	}
	return flagTo, nil
}

func beadsMailSelfTarget(sel *awconfig.Selection) (beadsMailTarget, error) {
	if sel == nil {
		return beadsMailTarget{}, fmt.Errorf("cannot resolve own identity for --self")
	}
	if address := strings.TrimSpace(sel.Address); address != "" {
		return beadsMailTarget{Kind: "address", Value: address, Input: "self"}, nil
	}
	if did := strings.TrimSpace(sel.DID); did != "" {
		return beadsMailTarget{Kind: "did", Value: did, Input: "self"}, nil
	}
	return beadsMailTarget{}, fmt.Errorf("cannot resolve own identity for --self: no address or DID in workspace state")
}

func beadsMailResolveBody(cmd *cobra.Command, body, bodyAlias string, fromStdin bool, positional string) (string, error) {
	sources := 0
	value := ""
	for _, candidate := range []string{body, bodyAlias, positional} {
		if candidate != "" {
			sources++
			value = candidate
		}
	}
	if fromStdin {
		sources++
	}
	if sources > 1 {
		return "", usageError("give the message body one way: -m/--message, --body, --stdin, or the positional message")
	}
	if fromStdin {
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, beadsMailBodyLimit+1))
		if err != nil {
			return "", fmt.Errorf("read body from stdin: %w", err)
		}
		if len(raw) > beadsMailBodyLimit {
			return "", usageError("body exceeds the %d MiB limit", beadsMailBodyLimit>>20)
		}
		return string(raw), nil
	}
	return value, nil
}

// beadsMailSourceMessage fetches one exact message. It uses the exact-read
// endpoint, which is visible to sender OR recipient — the recipient-scoped
// inbox lookup cannot see your own sent mail, which broke
// `send --reply-to <own-message>` in the first live exchange (2026-09-01).
func beadsMailSourceMessage(ctx context.Context, c *aweb.Client, messageID string) (*awid.InboxMessage, error) {
	resp, err := c.Message(ctx, messageID)
	if err != nil {
		return nil, networkError(err, messageID)
	}
	if resp == nil || len(resp.Messages) == 0 {
		return nil, fmt.Errorf("mail message not found: %s", messageID)
	}
	return &resp.Messages[0], nil
}

// beadsMailRetryAsContinuation handles the server refusing a fresh
// conversation because the pair already has an active one (HTTP 409, found
// live 2026-09-01). Continuation is server-directed, not opportunistic: the
// delegate still sends fresh first, and only when the server names the
// conflict does it look up the pair's unique active conversation and resend
// into it (design record §8 amendment).
func beadsMailRetryAsContinuation(ctx context.Context, c *aweb.Client, target beadsMailTarget, req *awid.SendMessageRequest, sendErr error) (*awid.SendMessageResponse, error) {
	if code, ok := awid.HTTPStatusCode(sendErr); !ok || code != http.StatusConflict {
		return nil, sendErr
	}
	var conversation mailConversationTarget
	var err error
	switch target.Kind {
	case "address", "did":
		conversation, err = findUniqueMailConversationForTarget(ctx, c, target.Kind, target.Value)
	case "alias":
		if agent, found, findErr := clientAgentForAlias(ctx, c, target.Value); findErr == nil && found {
			conversation, err = findUniqueMailConversationForAgent(ctx, c, agent)
		}
	}
	if err != nil || conversation.conversationID == "" {
		return nil, sendErr
	}
	fmt.Fprintf(os.Stderr, "note: continuing the existing conversation with %s (the server keeps one active conversation per pair)\n", sanitizeBeadsMailDisplay(target.Value))
	continuation := &awid.SendMessageRequest{
		ConversationID: conversation.conversationID,
		Subject:        req.Subject,
		Body:           req.Body,
		Priority:       req.Priority,
	}
	return c.SendMessageByIdentity(ctx, continuation)
}

func beadsMailAppendSendLogs(sel *awconfig.Selection, resp *awid.SendMessageResponse, to, subject, body string) {
	from := preferredIdentityDisplayLabel(
		"",
		selectionAddress(sel),
		strings.TrimSpace(sel.StableID),
		strings.TrimSpace(sel.DID),
		"",
	)
	appendCommLog(defaultLogsDir(), commLogNameForSelection(sel), &CommLogEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Dir:            "send",
		Channel:        "mail",
		MessageID:      resp.MessageID,
		ConversationID: resp.ConversationID,
		From:           from,
		To:             to,
		Subject:        subject,
		Body:           body,
	})
	appendInteractionLogForCWD(&InteractionEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Kind:           interactionKindMailOut,
		MessageID:      resp.MessageID,
		ConversationID: resp.ConversationID,
		To:             to,
		Subject:        subject,
		Text:           body,
	})
}

func init() {
	flags := beadsMailSendCmd.Flags()
	flags.StringVarP(&beadsMailSendSubject, "subject", "s", "", "Message subject (required)")
	flags.StringVarP(&beadsMailSendBody, "message", "m", "", "Message body")
	flags.StringVar(&beadsMailSendBodyAlias, "body", "", "Alias for --message")
	flags.BoolVar(&beadsMailSendStdin, "stdin", false, "Read message body from stdin")
	flags.IntVar(&beadsMailSendPriority, "priority", 2, "Message priority (0=urgent, 1=high, 2=normal, 3=low, 4=backlog); 0-1 wake the recipient")
	flags.BoolVar(&beadsMailSendUrgent, "urgent", false, "Set priority=0 (urgent)")
	flags.StringVar(&beadsMailSendType, "type", "notification", "Message type (task, scavenge, notification, reply); carried in the beads-mail envelope")
	flags.StringVar(&beadsMailSendReplyTo, "reply-to", "", "Message ID this replies to; continues that conversation")
	flags.StringVar(&beadsMailSendTo, "to", "", "Recipient address (alternative to the positional argument)")
	flags.BoolVar(&beadsMailSendSelf, "self", false, "Send to this workspace's own identity")
	flags.StringVar(&beadsMailSendFrom, "from", "", "Not supported: sender identity is cryptographic here")
	flags.StringArrayVar(&beadsMailSendCC, "cc", nil, "Not supported in v1: send to each recipient separately")
	flags.BoolVarP(&beadsMailSendNotify, "notify", "n", false, "Bump priority to high so the recipient wakes")
	flags.BoolVar(&beadsMailSendNoNotify, "no-notify", false, "No-op at priority <= normal (idle wake anyway); cannot silence high/urgent")
	flags.BoolVar(&beadsMailSendPinned, "pinned", false, "Carried in the beads-mail envelope; no delivery behavior")
	flags.BoolVar(&beadsMailSendWisp, "wisp", true, "Use the beads ephemeral default")
	flags.BoolVar(&beadsMailSendPermanent, "permanent", false, "Carry ephemeral=false metadata; v1 does not promote the underlying message bead")
	beadsMailSendCmd.MarkFlagsMutuallyExclusive("notify", "no-notify")
	beadsMailSendCmd.MarkFlagsMutuallyExclusive("wisp", "permanent")

	replyFlags := beadsMailReplyCmd.Flags()
	replyFlags.StringVarP(&beadsMailReplySubject, "subject", "s", "", "Override reply subject (default: Re: <original>)")
	replyFlags.StringVarP(&beadsMailReplyBody, "message", "m", "", "Reply message body")
	replyFlags.StringVar(&beadsMailReplyBodyAlias, "body", "", "Alias for --message")
	replyFlags.BoolVar(&beadsMailReplyStdin, "stdin", false, "Read the reply body from stdin (delegate extension; gt reply lacks it, but shell-unsafe bodies need it)")
}
