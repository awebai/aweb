package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
	"github.com/awebai/aw/internal/termtext"
	"github.com/spf13/cobra"
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Real-time chat",
	Long: "Real-time chat between agents. aweb reaches people by mail: chat to a person is\n" +
		"refused; use aw mail send --to <person> --subject <subject>.",
}

// The commands that search the sender's other teams for a bare name say how.
func init() {
	for _, cmd := range []*cobra.Command{mailSendCmd, chatSendAndWaitCmd, chatSendAndLeaveCmd, beadsMailSendCmd} {
		cmd.Long += aliasTeamSearchHelp
	}
}

func chatStderrCallback(kind, message string) {
	writeChatStatus(os.Stderr, kind, message)
}

func writeChatStatus(w io.Writer, kind, message string) {
	termtext.Fprintln(w, "[chat:%s] %s", kind, message)
}

// e2eeFlagChoice is the encryption a chat or mail command's flags ask for:
// --e2ee or --plaintext decide (--e2ee=false is --plaintext), and with
// neither a continuation inherits its conversation's encryption.
func e2eeFlagChoice(cmd *cobra.Command, e2ee, plaintext bool) chat.E2EEChoice {
	switch {
	case cmd.Flags().Changed("e2ee") && e2ee:
		return chat.E2EERequired
	case plaintext || cmd.Flags().Changed("e2ee"):
		return chat.E2EEPlaintext
	default:
		return chat.E2EEInherit
	}
}

// configureSendE2EE loads the keys a chat or mail send may need: --e2ee
// requires them, and an inherited continuation uses them when this workspace
// has them (an encrypted conversation is continued in plaintext, with a
// notice, without them).
func configureSendE2EE(ctx context.Context, c *aweb.Client, sel *awconfig.Selection, choice chat.E2EEChoice) error {
	switch choice {
	case chat.E2EERequired:
		return configureClientE2EE(ctx, c, sel, true)
	case chat.E2EEInherit:
		err := configureClientE2EE(ctx, c, sel, false)
		var unavailable *e2eeDecryptionUnavailableError
		if errors.As(err, &unavailable) {
			return nil
		}
		return err
	default:
		return nil
	}
}

func chatSend(ctx context.Context, toAlias, message string, opts chat.SendOptions) (*chat.SendResult, *awconfig.Selection, error) {
	c, sel, err := resolveClientSelectionForAliasTarget(ctx, toAlias)
	if err != nil {
		return nil, nil, err
	}
	if err := configureSendE2EE(ctx, c, sel, opts.Encryption()); err != nil {
		return nil, nil, err
	}
	target := strings.TrimSpace(toAlias)
	// Encrypted human aliases use selected-team key discovery; preserve the
	// released plaintext live-roster route.
	confirmed, err := confirmTeamAlias(ctx, c, sel, target, opts.Encryption() != chat.E2EERequired)
	if err != nil {
		return nil, sel, err
	}
	switch confirmed.source {
	case teamAliasFromAgentList:
		// An existing session is selected by the confirmed DID; a new one is
		// created by the alias, which the server resolves in the team, and
		// signs the member the agent list names.
		opts.RecipientDID = confirmed.sessionDID
		opts.ConfirmedRecipient = confirmed.recipient
	case teamAliasFromLiveRoster:
		if strings.HasPrefix(confirmed.sessionDID, "did:aw:") {
			// The roster confirms session identity. A new global recipient
			// is still selected by its team alias; a bare did:aw supplies
			// no first-contact route.
			opts.RecipientDID = confirmed.sessionDID
		} else {
			target = confirmed.sessionDID
		}
	}
	r, err := chat.Send(ctx, c.Client, sel.Alias, []string{target}, message, opts, chatStderrCallback)
	return r, sel, err
}

type teamAliasSource int

const (
	teamAliasUnconfirmed teamAliasSource = iota
	teamAliasFromAgentList
	teamAliasFromLiveRoster
)

// confirmedTeamAlias is a bare alias confirmed in the selected team, for a
// chat or a mail send.
type confirmedTeamAlias struct {
	source teamAliasSource
	// sessionDID selects the chat session: the member's did:aw, else its
	// did:key.
	sessionDID string
	// recipient is the identity a new message signs as its recipient
	// binding; only the agent list sets it.
	recipient *awid.ConfirmedRecipient
	// live is the live roster's member, when it confirmed the alias: its
	// identity target and current key.
	live liveTeamMemberAliasTarget
}

// confirmTeamAlias confirms a bare alias in the selected team, for chat and
// mail alike: the identity its agent list names for it, or else, with
// useLiveRoster, the member the team's live roster names. A confirmed DID is
// a strong identity, so it selects the chat session rather than the name,
// which an outside participant may also hold (chat/IDENTITY_RULES.md). A
// failed lookup refuses. Any other target, or an alias neither confirms, is
// unconfirmed.
func confirmTeamAlias(ctx context.Context, c *aweb.Client, sel *awconfig.Selection, target string, useLiveRoster bool) (confirmedTeamAlias, error) {
	target = strings.TrimSpace(target)
	if !shouldTryLiveRosterAliasFallback(target) {
		return confirmedTeamAlias{}, nil
	}
	agent, found, err := clientAgentForAlias(ctx, c, target)
	if err != nil {
		return confirmedTeamAlias{}, recipientLookupError(target, "agent list", err)
	}
	if found {
		recipient, err := agentListRecipient(target, agent)
		if err != nil {
			return confirmedTeamAlias{}, err
		}
		sessionDID := firstNonEmpty(recipient.StableID, recipient.DID)
		return confirmedTeamAlias{source: teamAliasFromAgentList, sessionDID: sessionDID, recipient: recipient}, nil
	}
	if !useLiveRoster {
		return confirmedTeamAlias{}, nil
	}
	live, liveFound, err := resolveLiveTeamMemberAliasTarget(ctx, sel, target)
	if err != nil {
		return confirmedTeamAlias{}, recipientLookupError(target, "live roster", err)
	}
	if liveFound {
		if _, value := live.identityTarget(); strings.TrimSpace(value) != "" {
			return confirmedTeamAlias{source: teamAliasFromLiveRoster, sessionDID: strings.TrimSpace(value), live: live}, nil
		}
	}
	return confirmedTeamAlias{}, nil
}

// agentListRecipient is the identity the selected team's agent list names
// for alias: the binding a message to that alias signs. A row that names no
// identity cannot be confirmed and refuses.
func agentListRecipient(alias string, agent awid.AgentView) (*awid.ConfirmedRecipient, error) {
	recipient := &awid.ConfirmedRecipient{DID: strings.TrimSpace(agent.DIDKey), StableID: strings.TrimSpace(agent.DIDAW)}
	if recipient.DID == "" && recipient.StableID == "" {
		return nil, fmt.Errorf("cannot confirm recipient %q: the agent list names no DID for it; use the recipient's full address or DID", alias)
	}
	return recipient, nil
}

// chatSessionDID is the DID that selects a session for a command that looks
// one up by target: the DID the selected team's agent list confirms for a
// teammate's alias, or "" when the list does not name it. A failed lookup
// refuses.
func chatSessionDID(ctx context.Context, c *aweb.Client, sel *awconfig.Selection, target string) (string, error) {
	confirmed, err := confirmTeamAlias(ctx, c, sel, target, false)
	if err != nil || confirmed.source != teamAliasFromAgentList {
		return "", err
	}
	return confirmed.sessionDID, nil
}

// logChatEvent logs a single chat event to the communication log.
func logChatEvent(logsDir, logName string, logPolicy localLogPolicy, myAddress string, ev chat.Event, selfDIDs ...string) {
	dir := "recv"
	kind := interactionKindChatIn
	from := preferredIdentityDisplayLabel(ev.FromAgent, ev.FromAddress, ev.FromStableID, ev.FromDID, "")
	to := preferredIdentityDisplayLabel("", ev.ToAddress, ev.ToStableID, ev.ToDID, "")
	if chatEventIsFromSelf(ev, myAddress, selfDIDs...) {
		dir = "send"
		kind = interactionKindChatOut
	}
	appendCommLog(logsDir, logName, logPolicy, &CommLogEntry{
		Timestamp:    ev.Timestamp,
		Dir:          dir,
		Channel:      "chat",
		MessageID:    ev.MessageID,
		SessionID:    ev.SessionID,
		From:         from,
		To:           to,
		Body:         ev.Body,
		FromDID:      ev.FromDID,
		ToDID:        ev.ToDID,
		FromStableID: ev.FromStableID,
		ToStableID:   ev.ToStableID,
		Signature:    ev.Signature,
		SigningKeyID: ev.SigningKeyID,
		Verification: string(ev.VerificationStatus),
	})
	appendInteractionLogForCWD(logPolicy, &InteractionEntry{
		Timestamp: ev.Timestamp,
		Kind:      kind,
		MessageID: ev.MessageID,
		SessionID: ev.SessionID,
		From:      from,
		To:        to,
		Text:      ev.Body,
	})
}

func chatEventIsFromSelf(ev chat.Event, myAddress string, selfDIDs ...string) bool {
	return identityMatchesSelf(
		strings.TrimSpace(ev.FromAgent),
		strings.TrimSpace(ev.FromAddress),
		strings.TrimSpace(ev.FromStableID),
		strings.TrimSpace(ev.FromDID),
		handleFromAddress(myAddress),
		myAddress,
		selfDIDs...,
	)
}

// logChatEvents logs all message events from a list.
func logChatEvents(logsDir, logName string, logPolicy localLogPolicy, myAddress string, events []chat.Event, selfDIDs ...string) {
	for _, ev := range events {
		if ev.Type != "message" {
			continue
		}
		logChatEvent(logsDir, logName, logPolicy, myAddress, ev, selfDIDs...)
	}
}

func selectionIdentityDIDs(sel *awconfig.Selection) []string {
	if sel == nil {
		return nil
	}
	return uniqueIdentityDIDs(sel.StableID, sel.DID)
}

// chat send-and-wait

var (
	chatSendAndWaitWait               int
	chatSendAndWaitStartConversation  bool
	chatSendAndLeaveStartConversation bool
	chatSendAndWaitBodyFile           string
	chatSendAndLeaveBodyFile          string
	chatSendAndWaitE2EE               bool
	chatSendAndLeaveE2EE              bool
	chatSendE2EE                      bool
	chatExtendWaitBodyFile            string
	chatExtendWaitE2EE                bool
	chatSendAndWaitPlaintext          bool
	chatSendAndLeavePlaintext         bool
	chatSendPlaintext                 bool
	chatExtendWaitPlaintext           bool
	chatHistorySessionID              string
	chatHistoryMessageID              string
	chatHistoryLimit                  int
	chatHistoryUnreadOnly             bool
	chatListenWait                    int
	chatReadSessionID                 string
	chatReadMessageID                 string
	chatSendSessionID                 string
	chatSendBody                      string
	chatSendBodyFile                  string
	chatSendLeave                     bool
)

var chatSendAndWaitCmd = &cobra.Command{
	Use:   "send-and-wait <recipient> [message]",
	Short: "Send a message and wait for a reply",
	Long:  shellExpandedInlineHelp("Send a message and wait for a reply", "--body-file"),
	Args:  exactArgsWithBodyFile,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatSendAndWaitPlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		message, err := resolvePositionalMessage(cmd, args)
		if err != nil {
			return err
		}
		// Chat send-and-wait/leave retains the protocol wait budget instead of the ordinary API budget.
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], message, chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
			E2EE:              e2eeFlagChoice(cmd, chatSendAndWaitE2EE, chatSendAndWaitPlaintext),
		})
		if err != nil {
			return networkError(err, args[0])
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		myAddr := selectionAddress(sel)
		logName := commLogNameForSelection(sel)
		// Log the sent message.
		appendCommLog(logsDir, logName, logPolicy, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      myAddr,
			To:        args[0],
			Body:      message,
		})
		appendInteractionLogForCWD(logPolicy, &InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        args[0],
			Text:      message,
		})
		// Log any reply events.
		logChatEvents(logsDir, logName, logPolicy, myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat send-and-leave

var chatSendAndLeaveCmd = &cobra.Command{
	Use:   "send-and-leave <recipient> [message]",
	Short: "Send a message and leave the conversation",
	Long:  shellExpandedInlineHelp("Send a message and leave the conversation", "--body-file"),
	Args:  exactArgsWithBodyFile,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatSendAndLeavePlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		message, err := resolvePositionalMessage(cmd, args)
		if err != nil {
			return err
		}
		// Chat send-and-wait/leave retains the protocol wait budget instead of the ordinary API budget.
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], message, chat.SendOptions{
			Wait:              0,
			Leaving:           true,
			StartConversation: chatSendAndLeaveStartConversation,
			E2EE:              e2eeFlagChoice(cmd, chatSendAndLeaveE2EE, chatSendAndLeavePlaintext),
		})
		if err != nil {
			return networkError(err, args[0])
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		appendCommLog(logsDir, commLogNameForSelection(sel), logPolicy, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      selectionAddress(sel),
			To:        args[0],
			Body:      message,
		})
		appendInteractionLogForCWD(logPolicy, &InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        args[0],
			Text:      message,
		})
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat pending

var chatPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending chat sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		result, err := chat.Pending(ctx, c.Client)
		if err != nil {
			return err
		}
		printOutput(result, formatChatPending)
		return nil
	},
}

// chat open

var chatOpenCmd = &cobra.Command{
	Use:   "open <recipient>",
	Short: "Open a chat session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		confirmedDID, err := chatSessionDID(ctx, c, sel, args[0])
		if err != nil {
			return err
		}
		result, err := chat.OpenConfirmed(ctx, c.Client, args[0], confirmedDID)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		myAddr := selectionAddress(sel)
		for _, m := range result.Messages {
			logChatEvent(logsDir, commLogNameForSelection(sel), logPolicy, myAddr, m, selectionIdentityDIDs(sel)...)
		}
		printOutput(result, formatChatOpen)
		return nil
	},
}

// chat history

var chatHistoryCmd = &cobra.Command{
	Use:   "history <recipient>",
	Short: "Show chat history with a recipient name or address",
	Args: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(chatHistorySessionID) != "" {
			if len(args) != 0 {
				return usageError("chat history with --session-id does not accept a recipient")
			}
			return nil
		}
		if len(args) != 1 {
			return usageError("chat history requires a recipient name/address, or use --session-id")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Each HTTP/custody request has its own timeout. A replay must not
		// spend one shared API budget decrypting an entire history page.
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		var result *chat.HistoryResult
		if strings.TrimSpace(chatHistorySessionID) != "" {
			result, err = chat.HistoryBySession(ctx, c.Client, chatHistorySessionID, chatHistoryMessageID, chatHistoryUnreadOnly, chatHistoryLimit)
		} else {
			var confirmedDID string
			if confirmedDID, err = chatSessionDID(ctx, c, sel, args[0]); err != nil {
				return err
			}
			result, err = chat.HistoryConfirmed(ctx, c.Client, args[0], chatHistoryUnreadOnly, chatHistoryLimit, confirmedDID)
		}
		if err != nil {
			return err
		}
		// History is a replay; skip logging to avoid duplicates.
		printOutput(result, formatChatHistory)
		return nil
	},
}

// chat send exact session

func formatChatSendMessage(v any) string {
	resp, ok := v.(*awid.ChatSendMessageResponse)
	if !ok || resp == nil {
		return ""
	}
	if resp.MessageID != "" {
		return fmt.Sprintf("Sent chat message %s\n", resp.MessageID)
	}
	return "Sent chat message\n"
}

var chatSendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send a message to an exact chat session",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatSendPlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		sessionID := strings.TrimSpace(chatSendSessionID)
		if sessionID == "" {
			return usageError("missing required flag: --session-id")
		}
		body, err := resolveMailBody(chatSendBody, chatSendBodyFile)
		if err != nil {
			return err
		}

		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		choice := e2eeFlagChoice(cmd, chatSendE2EE, chatSendPlaintext)
		if err := configureSendE2EE(ctx, c, sel, choice); err != nil {
			return err
		}
		encrypt, err := chat.ContinuationEncrypted(ctx, c.Client, sessionID, choice, chatStderrCallback)
		if err != nil {
			return err
		}
		resp, err := c.Client.ChatSendMessage(ctx, sessionID, &awid.ChatSendMessageRequest{
			Body:        body,
			Leaving:     chatSendLeave,
			EncryptE2EE: encrypt,
		})
		if err != nil {
			return humanMailOnlyRefusal(err)
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		appendCommLog(logsDir, commLogNameForSelection(sel), logPolicy, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			MessageID: resp.MessageID,
			SessionID: sessionID,
			From:      selectionAddress(sel),
			Body:      body,
		})
		printOutput(resp, formatChatSendMessage)
		return nil
	},
}

// chat read

func formatChatRead(v any) string {
	resp, ok := v.(*awid.ChatMarkReadResponse)
	if !ok || resp == nil {
		return ""
	}
	return fmt.Sprintf("Marked %d chat message(s) read\n", resp.MessagesMarked)
}

var chatReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Mark chat messages read by session and message id",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		sessionID := strings.TrimSpace(chatReadSessionID)
		messageID := strings.TrimSpace(chatReadMessageID)
		if sessionID == "" {
			return usageError("missing required flag: --session-id")
		}
		if messageID == "" {
			return usageError("missing required flag: --message-id")
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, _, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.Client.ChatMarkRead(ctx, sessionID, &awid.ChatMarkReadRequest{MessageIDs: []string{messageID}})
		if err != nil {
			return err
		}
		printOutput(resp, formatChatRead)
		return nil
	},
}

// chat extend-wait

var chatExtendWaitCmd = &cobra.Command{
	Use:   "extend-wait <recipient> [message]",
	Short: "Ask the other party to wait longer",
	Long:  shellExpandedInlineHelp("Ask the other party to wait longer", "--body-file"),
	Args:  exactArgsWithBodyFile,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatExtendWaitPlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		message, err := resolvePositionalMessage(cmd, args)
		if err != nil {
			return err
		}
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		choice := e2eeFlagChoice(cmd, chatExtendWaitE2EE, chatExtendWaitPlaintext)
		if err := configureSendE2EE(ctx, c, sel, choice); err != nil {
			return err
		}
		confirmedDID, err := chatSessionDID(ctx, c, sel, args[0])
		if err != nil {
			return err
		}
		opts := chat.ExtendWaitOptions{E2EE: choice, RecipientDID: confirmedDID}
		result, err := chat.ExtendWaitWithStatus(ctx, c.Client, args[0], message, opts, chatStderrCallback)
		if err != nil {
			return humanMailOnlyRefusal(err)
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		appendCommLog(logsDir, commLogNameForSelection(sel), logPolicy, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      selectionAddress(sel),
			To:        result.TargetAgent,
			Body:      message,
		})
		appendInteractionLogForCWD(logPolicy, &InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        result.TargetAgent,
			Text:      message,
		})
		printOutput(result, formatChatExtendWait)
		return nil
	},
}

// chat listen

var chatListenCmd = &cobra.Command{
	Use:   "listen <recipient>",
	Short: "Wait for a message without sending",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := chat.MaxSendTimeout
		// Chat listen retains its protocol long-poll budget.
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		confirmedDID, err := chatSessionDID(ctx, c, sel, args[0])
		if err != nil {
			return err
		}
		result, err := chat.ListenConfirmed(ctx, c.Client, args[0], chatListenWait, chatStderrCallback, confirmedDID)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), logPolicy, myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat show-pending

var chatShowPendingCmd = &cobra.Command{
	Use:   "show-pending <recipient>",
	Short: "Show pending messages for a recipient name or address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := commandAPIContext(cmd)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if err := configureClientE2EEForRead(cmd, ctx, c, sel); err != nil {
			return err
		}
		confirmedDID, err := chatSessionDID(ctx, c, sel, args[0])
		if err != nil {
			return err
		}
		result, err := chat.ShowPendingConfirmed(ctx, c.Client, args[0], confirmedDID)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		logPolicy := localLogPolicyForSelection(sel)
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), logPolicy, myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

func init() {
	chatSendAndWaitCmd.Flags().IntVar(&chatSendAndWaitWait, "wait", chat.DefaultWait, "Seconds to wait for reply")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitStartConversation, "start-conversation", false, "Start conversation (5min default wait)")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitPlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatSendAndWaitCmd.Flags().StringVar(&chatSendAndWaitBodyFile, "body-file", "", safeFileInputHelp("message body"))
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeaveStartConversation, "start-conversation", false, "Start a new conversation instead of continuing an existing one")
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeavePlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)")
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeaveE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatSendAndLeaveCmd.Flags().StringVar(&chatSendAndLeaveBodyFile, "body-file", "", safeFileInputHelp("message body"))
	chatSendCmd.Flags().StringVar(&chatSendSessionID, "session-id", "", "Existing chat session id")
	chatSendCmd.Flags().StringVar(&chatSendBody, "body", "", shellExpandedInlineHelp("Body", "--body-file"))
	chatSendCmd.Flags().StringVar(&chatSendBodyFile, "body-file", "", safeFileInputHelp("message body"))
	chatSendCmd.Flags().BoolVar(&chatSendLeave, "leave", false, "Leave the conversation after sending")
	chatSendCmd.Flags().BoolVar(&chatSendPlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)")
	chatSendCmd.Flags().BoolVar(&chatSendE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatExtendWaitCmd.Flags().BoolVar(&chatExtendWaitPlaintext, "plaintext", false, "Send explicit server-readable plaintext wait extension (by default it inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)")
	chatExtendWaitCmd.Flags().BoolVar(&chatExtendWaitE2EE, "e2ee", false, "Send E2E encrypted wait extension; fails closed if encryption keys are missing")
	chatExtendWaitCmd.Flags().StringVar(&chatExtendWaitBodyFile, "body-file", "", safeFileInputHelp("message body"))

	chatHistoryCmd.Flags().StringVar(&chatHistorySessionID, "session-id", "", "Fetch chat history by session id instead of recipient")
	chatHistoryCmd.Flags().StringVar(&chatHistoryMessageID, "message-id", "", "Fetch one message by id when using --session-id")
	chatHistoryCmd.Flags().IntVar(&chatHistoryLimit, "limit", 1000, "Maximum messages to fetch")
	chatHistoryCmd.Flags().BoolVar(&chatHistoryUnreadOnly, "unread-only", false, "Fetch unread messages only")

	chatListenCmd.Flags().IntVar(&chatListenWait, "wait", chat.DefaultWait, "Seconds to wait for a message (0 = no wait)")
	chatReadCmd.Flags().StringVar(&chatReadSessionID, "session-id", "", "Chat session id")
	chatReadCmd.Flags().StringVar(&chatReadMessageID, "message-id", "", "Last delivered message id to mark read")

	chatCmd.AddCommand(chatSendAndWaitCmd, chatSendAndLeaveCmd, chatSendCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatReadCmd, chatExtendWaitCmd, chatShowPendingCmd, chatListenCmd)
	rootCmd.AddCommand(chatCmd)
}
