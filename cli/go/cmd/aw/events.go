package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Event stream operations",
}

var eventsStreamTimeout int

var eventsStreamCmd = &cobra.Command{
	Use:   "stream",
	Short: "Listen to real-time agent events via SSE",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		if eventsStreamTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(eventsStreamTimeout)*time.Second)
			defer cancel()
		}

		deadline := time.Now().Add(24 * time.Hour)
		if dl, ok := ctx.Deadline(); ok {
			deadline = dl
		}

		stream, err := client.EventStream(ctx, deadline)
		if err != nil {
			return err
		}
		defer stream.Close()

		enc := json.NewEncoder(os.Stdout)

		for {
			ev, err := stream.Next(ctx)
			if err != nil {
				if err == io.EOF || ctx.Err() != nil {
					return nil
				}
				return err
			}

			if jsonFlag {
				if err := enc.Encode(ev); err != nil {
					return err
				}
			} else {
				printEventText(ev)
			}
		}
	},
}

func printEventText(ev *awid.AgentEvent) {
	switch ev.Type {
	case awid.AgentEventConnected:
		fmt.Printf("[connected] agent_id=%s project_id=%s\n", ev.AgentID, ev.ProjectID)
	case awid.AgentEventMailMessage:
		fmt.Printf("[mail_message] from=%s message_id=%s subject=%q\n", ev.FromAlias, ev.MessageID, ev.Subject)
	case awid.AgentEventChatMessage:
		fmt.Printf("[chat_message] from=%s session_id=%s message_id=%s\n", ev.FromAlias, ev.SessionID, ev.MessageID)
	case awid.AgentEventActionableMail:
		fmt.Printf(
			"[actionable_mail] from=%s wake_mode=%s unread=%d message_id=%s subject=%q\n",
			ev.FromAlias,
			eventTextValue(ev.WakeMode),
			ev.UnreadCount,
			ev.MessageID,
			ev.Subject,
		)
	case awid.AgentEventActionableChat:
		fmt.Printf(
			"[actionable_chat] from=%s wake_mode=%s unread=%d sender_waiting=%t session_id=%s message_id=%s\n",
			ev.FromAlias,
			eventTextValue(ev.WakeMode),
			ev.UnreadCount,
			ev.SenderWaiting,
			ev.SessionID,
			ev.MessageID,
		)
	case awid.AgentEventWorkAvailable:
		fmt.Printf("[work_available] task_id=%s title=%q\n", ev.TaskID, ev.Title)
	case awid.AgentEventClaimUpdate:
		fmt.Printf("[claim_update] task_id=%s title=%q status=%s\n", ev.TaskID, ev.Title, ev.Status)
	case awid.AgentEventClaimRemoved:
		fmt.Printf("[claim_removed] task_id=%s\n", ev.TaskID)
	case awid.AgentEventControlPause:
		fmt.Printf("[control_pause] signal_id=%s\n", ev.SignalID)
	case awid.AgentEventControlResume:
		fmt.Printf("[control_resume] signal_id=%s\n", ev.SignalID)
	case awid.AgentEventControlInterrupt:
		fmt.Printf("[control_interrupt] signal_id=%s\n", ev.SignalID)
	case awid.AgentEventError:
		fmt.Fprintf(os.Stderr, "[error] %s\n", ev.Text)
	default:
		fmt.Printf("[%s] %s\n", ev.Type, string(ev.Raw))
	}
}

func eventTextValue(value string) string {
	if value == "" {
		return "-"
	}
	return value
}

func init() {
	eventsStreamCmd.Flags().IntVar(&eventsStreamTimeout, "timeout", 0, "Stop after N seconds (0 = indefinite)")

	eventsCmd.AddCommand(eventsStreamCmd)
	rootCmd.AddCommand(eventsCmd)
}
