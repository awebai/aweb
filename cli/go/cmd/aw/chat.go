package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/awebai/aw/awconfig"
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
	c, sel, err := resolveClientSelection()
	if err != nil {
		return nil, nil, err
	}
	r, err := chat.Send(ctx, c.Client, sel.Alias, []string{toAlias}, message, opts, chatStderrCallback)
	return r, sel, err
}

// logChatEvent logs a single chat event to the communication log.
func logChatEvent(logsDir, logName, myAddress string, ev chat.Event) {
	dir := "recv"
	kind := interactionKindChatIn
	from := ev.FromAddress
	if from == "" {
		from = ev.FromAgent
	}
	to := ev.ToAddress
	if ev.FromAddress != "" {
		if ev.FromAddress == myAddress {
			dir = "send"
			kind = interactionKindChatOut
		}
	} else if ev.FromAgent == myAddress {
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

// logChatEvents logs all message events from a list.
func logChatEvents(logsDir, logName, myAddress string, events []chat.Event) {
	for _, ev := range events {
		if ev.Type != "message" {
			continue
		}
		logChatEvent(logsDir, logName, myAddress, ev)
	}
}

// chat send-and-wait

var (
	chatSendAndWaitWait              int
	chatSendAndWaitStartConversation bool
	chatListenWait                   int
)

var chatSendAndWaitCmd = &cobra.Command{
	Use:   "send-and-wait <alias> <message>",
	Short: "Send a message and wait for a reply",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:              chatSendAndWaitWait,
			WaitExplicit:      cmd.Flags().Changed("wait"),
			StartConversation: chatSendAndWaitStartConversation,
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
		logChatEvents(logsDir, logName, myAddr, result.Events)
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
		ctx, cancel := context.WithTimeout(context.Background(), chat.MaxSendTimeout)
		defer cancel()

		result, sel, err := chatSend(ctx, args[0], args[1], chat.SendOptions{
			Wait:    0,
			Leaving: true,
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

		c, err := resolveClient()
		if err != nil {
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
		result, err := chat.Open(ctx, c.Client, args[0])
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		for _, m := range result.Messages {
			logChatEvent(logsDir, commLogNameForSelection(sel), myAddr, m)
		}
		printOutput(result, formatChatOpen)
		return nil
	},
}

// chat history

var chatHistoryCmd = &cobra.Command{
	Use:   "history <alias>",
	Short: "Show chat history with alias",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, _, err := resolveClientSelection()
		if err != nil {
			return err
		}
		result, err := chat.History(ctx, c.Client, args[0])
		if err != nil {
			return err
		}
		// History is a replay; skip logging to avoid duplicates.
		printOutput(result, formatChatHistory)
		return nil
	},
}

// chat extend-wait

var chatExtendWaitCmd = &cobra.Command{
	Use:   "extend-wait <alias> <message>",
	Short: "Ask the other party to wait longer",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}
		result, err := chat.ExtendWait(ctx, c.Client, args[0], args[1])
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
		result, err := chat.Listen(ctx, c.Client, args[0], chatListenWait, chatStderrCallback)
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), myAddr, result.Events)
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
		result, err := chat.ShowPending(ctx, c.Client, args[0])
		if err != nil {
			return err
		}
		logsDir := defaultLogsDir()
		myAddr := selectionAddress(sel)
		logChatEvents(logsDir, commLogNameForSelection(sel), myAddr, result.Events)
		printOutput(result, formatChatSend)
		return nil
	},
}

func init() {
	chatSendAndWaitCmd.Flags().IntVar(&chatSendAndWaitWait, "wait", chat.DefaultWait, "Seconds to wait for reply")
	chatSendAndWaitCmd.Flags().BoolVar(&chatSendAndWaitStartConversation, "start-conversation", false, "Start conversation (5min default wait)")

	chatListenCmd.Flags().IntVar(&chatListenWait, "wait", chat.DefaultWait, "Seconds to wait for a message (0 = no wait)")

	chatCmd.AddCommand(chatSendAndWaitCmd, chatSendAndLeaveCmd, chatPendingCmd, chatOpenCmd, chatHistoryCmd, chatExtendWaitCmd, chatShowPendingCmd, chatListenCmd)
	rootCmd.AddCommand(chatCmd)
}
