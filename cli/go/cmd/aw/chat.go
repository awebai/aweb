package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

var chatCmd = &cobra.Command{
	Use:   "chat",
	Short: "Real-time chat",
}

func chatStderrCallback(kind, message string) {
	fmt.Fprintf(os.Stderr, "[chat:%s] %s\n", kind, message)
}

func chatSend(ctx context.Context, toAlias, message string, opts chat.SendOptions) (*chat.SendResult, *awconfig.Selection, error) {
	c, sel, err := resolveClientSelectionForAliasTarget(ctx, toAlias)
	if err != nil {
		return nil, nil, err
	}
	if opts.EncryptE2EE {
		if err := configureClientE2EE(ctx, c, sel, true); err != nil {
			return nil, nil, err
		}
	}
	r, err := chat.Send(ctx, c.Client, sel.Alias, []string{toAlias}, message, opts, chatStderrCallback)
	return r, sel, err
}

// logChatEvent logs a single chat event to the communication log.
func logChatEvent(logsDir, logName, myAddress string, ev chat.Event, selfDIDs ...string) {
	dir := "recv"
	kind := interactionKindChatIn
	from := preferredIdentityDisplayLabel(ev.FromAgent, ev.FromAddress, ev.FromStableID, ev.FromDID, "")
	to := preferredIdentityDisplayLabel("", ev.ToAddress, ev.ToStableID, ev.ToDID, "")
	if chatEventIsFromSelf(ev, myAddress, selfDIDs...) {
		dir = "send"
		kind = interactionKindChatOut
	}
	appendCommLog(logsDir, logName, &CommLogEntry{
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
	appendInteractionLogForCWD(&InteractionEntry{
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
func logChatEvents(logsDir, logName, myAddress string, events []chat.Event, selfDIDs ...string) {
	for _, ev := range events {
		if ev.Type != "message" {
			continue
		}
		logChatEvent(logsDir, logName, myAddress, ev, selfDIDs...)
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
	chatSendAndWaitE2EE               bool
	chatSendAndLeaveE2EE              bool
	chatSendE2EE                      bool
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
	Use:   "send-and-wait <alias> <message>",
	Short: "Send a message and wait for a reply",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatSendAndWaitPlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
			EncryptE2EE:       chatSendAndWaitE2EE,
		})
		if err != nil {
			return networkError(err, args[0])
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		logName := commLogNameForSelection(sel)
		// Log the sent message.
		appendCommLog(logsDir, logName, &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      myAddr,
			To:        args[0],
			Body:      args[1],
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        args[0],
			Text:      args[1],
		})
		// Log any reply events.
		logChatEvents(logsDir, logName, myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat send-and-leave

var chatSendAndLeaveCmd = &cobra.Command{
	Use:   "send-and-leave <alias> <message>",
	Short: "Send a message and leave the conversation",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatSendAndLeavePlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:              0,
			Leaving:           true,
			StartConversation: chatSendAndLeaveStartConversation,
			EncryptE2EE:       chatSendAndLeaveE2EE,
		})
		if err != nil {
			return networkError(err, args[0])
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      selectionAddress(sel),
			To:        args[0],
			Body:      args[1],
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        args[0],
			Text:      args[1],
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		_ = configureClientE2EE(ctx, c, sel, false)
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
	Use:   "open <alias>",
	Short: "Open a chat session",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		_ = configureClientE2EE(ctx, c, sel, false)
		result, err := chat.Open(ctx, c.Client, args[0])
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		for _, m := range result.Messages {
			logChatEvent(logsDir, commLogNameForSelection(sel), myAddr, m, selectionIdentityDIDs(sel)...)
		}
		printOutput(result, formatChatOpen)
		return nil
	},
}

// chat history

var chatHistoryCmd = &cobra.Command{
	Use:   "history <alias>",
	Short: "Show chat history with alias",
	Args: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(chatHistorySessionID) != "" {
			if len(args) != 0 {
				return usageError("chat history with --session-id does not accept an alias")
			}
			return nil
		}
		if len(args) != 1 {
			return usageError("chat history requires an alias, or use --session-id")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		_ = configureClientE2EE(ctx, c, sel, false)
		var result *chat.HistoryResult
		if strings.TrimSpace(chatHistorySessionID) != "" {
			result, err = chat.HistoryBySession(ctx, c.Client, chatHistorySessionID, chatHistoryMessageID, chatHistoryUnreadOnly, chatHistoryLimit)
		} else {
			result, err = chat.History(ctx, c.Client, args[0])
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

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		if chatSendE2EE {
			if err := configureClientE2EE(ctx, c, sel, true); err != nil {
				return err
			}
		}
		resp, err := c.Client.ChatSendMessage(ctx, sessionID, &awid.ChatSendMessageRequest{
			Body:        body,
			Leaving:     chatSendLeave,
			EncryptE2EE: chatSendE2EE,
		})
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
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
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, _, err := resolveClientSelection()
		if err != nil {
			return err
		}
		resp, err := c.Client.ChatMarkRead(ctx, sessionID, &awid.ChatMarkReadRequest{UpToMessageID: messageID})
		if err != nil {
			return err
		}
		printOutput(resp, formatChatRead)
		return nil
	},
}

// chat extend-wait

var chatExtendWaitCmd = &cobra.Command{
	Use:   "extend-wait <alias> <message>",
	Short: "Ask the other party to wait longer",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("e2ee") && chatExtendWaitPlaintext {
			return usageError("--e2ee and --plaintext are mutually exclusive")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		encryptE2EE := chatExtendWaitE2EE
		if encryptE2EE {
			if err := configureClientE2EE(ctx, c, sel, true); err != nil {
				return err
			}
		}
		result, err := chat.ExtendWait(ctx, c.Client, args[0], args[1], encryptE2EE)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		appendCommLog(logsDir, commLogNameForSelection(sel), &CommLogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Dir:       "send",
			Channel:   "chat",
			SessionID: result.SessionID,
			From:      selectionAddress(sel),
			To:        result.TargetAgent,
			Body:      args[1],
		})
		appendInteractionLogForCWD(&InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindChatOut,
			SessionID: result.SessionID,
			To:        result.TargetAgent,
			Text:      args[1],
		})
		printOutput(result, formatChatExtendWait)
		return nil
	},
}

// chat listen

var chatListenCmd = &cobra.Command{
	Use:   "listen <alias>",
	Short: "Wait for a message without sending",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		timeout := chat.MaxSendTimeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		_ = configureClientE2EE(ctx, c, sel, false)
		result, err := chat.Listen(ctx, c.Client, args[0], chatListenWait, chatStderrCallback)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

// chat show-pending

var chatShowPendingCmd = &cobra.Command{
	Use:   "show-pending <alias>",
	Short: "Show pending messages for alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		_ = configureClientE2EE(ctx, c, sel, false)
		result, err := chat.ShowPending(ctx, c.Client, args[0])
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), myAddr, result.Events, selectionIdentityDIDs(sel)...)
		printOutput(result, formatChatSend)
		return nil
	},
}

func init() {
	chatSendAndWaitCmd.Flags().IntVar(&chatSendAndWaitWait, "wait", chat.DefaultWait, "Seconds to wait for reply")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitStartConversation, "start-conversation", false, "Start conversation (5min default wait)")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitPlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (currently the default)")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeaveStartConversation, "start-conversation", false, "Start a new conversation instead of continuing an existing one")
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeavePlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (currently the default)")
	chatSendAndLeaveCmd.Flags().BoolVar(&chatSendAndLeaveE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatSendCmd.Flags().StringVar(&chatSendSessionID, "session-id", "", "Existing chat session id")
	chatSendCmd.Flags().StringVar(&chatSendBody, "body", "", "Body (mutually exclusive with --body-file)")
	chatSendCmd.Flags().StringVar(&chatSendBodyFile, "body-file", "", "Read body from file")
	chatSendCmd.Flags().BoolVar(&chatSendLeave, "leave", false, "Leave the conversation after sending")
	chatSendCmd.Flags().BoolVar(&chatSendPlaintext, "plaintext", false, "Send explicit server-readable plaintext chat (currently the default)")
	chatSendCmd.Flags().BoolVar(&chatSendE2EE, "e2ee", false, "Send E2E encrypted chat; fails closed if encryption keys are missing")
	chatExtendWaitCmd.Flags().BoolVar(&chatExtendWaitPlaintext, "plaintext", false, "Send explicit server-readable plaintext wait extension (currently the default)")
	chatExtendWaitCmd.Flags().BoolVar(&chatExtendWaitE2EE, "e2ee", false, "Send E2E encrypted wait extension; fails closed if encryption keys are missing")

	chatHistoryCmd.Flags().StringVar(&chatHistorySessionID, "session-id", "", "Fetch chat history by session id instead of alias")
	chatHistoryCmd.Flags().StringVar(&chatHistoryMessageID, "message-id", "", "Fetch one message by id when using --session-id")
	chatHistoryCmd.Flags().IntVar(&chatHistoryLimit, "limit", 1000, "Maximum messages to fetch")
	chatHistoryCmd.Flags().BoolVar(&chatHistoryUnreadOnly, "unread-only", false, "Fetch unread messages only")

	chatListenCmd.Flags().IntVar(&chatListenWait, "wait", chat.DefaultWait, "Seconds to wait for a message (0 = no wait)")
	chatReadCmd.Flags().StringVar(&chatReadSessionID, "session-id", "", "Chat session id")
	chatReadCmd.Flags().StringVar(&chatReadMessageID, "message-id", "", "Last delivered message id to mark read")

	chatCmd.AddCommand(chatSendAndWaitCmd, chatSendAndLeaveCmd, chatSendCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatReadCmd, chatExtendWaitCmd, chatShowPendingCmd, chatListenCmd)
	rootCmd.AddCommand(chatCmd)
}
