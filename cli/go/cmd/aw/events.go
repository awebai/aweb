package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

		baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		ctx := baseCtx
		if eventsStreamTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(baseCtx, time.Duration(eventsStreamTimeout)*time.Second)
			defer cancel()
		}

		enc := json.NewEncoder(os.Stdout)

		// The server closes every events stream at its own lifetime cap
		// (MAX_STREAM_DURATION, server/src/aweb/routes/events.py), and an
		// intermediary may cut an idle connection sooner. A subscription is
		// therefore made of several streams, and ending one is not ending the
		// subscription: reopen until the caller's context says to stop. Reporting
		// the first close as an error is what surfaced to a customer as
		// "unexpected EOF" with exit 1 after a single event (aweb-aamn).
		backoff := eventsReconnectInitialBackoff
		for {
			stream, closeStream, err := openEventStream(ctx, baseCtx, client.Client)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				// A request the server rejects on its merits will be rejected
				// identically on every retry, so retrying buries the reason in a
				// reconnect loop instead of reporting it.
				if isFatalStreamOpenError(err) {
					return err
				}
				if !sleepUntil(ctx, backoff) {
					return nil
				}
				backoff = nextEventsBackoff(backoff)
				continue
			}

			delivered, outputErr := drainEventStream(ctx, stream, enc)
			closeStream()

			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return nil
			}
			// Any end of a stream - a clean EOF at the lifetime cap or a severed
			// connection - is a reconnect, not a result. Only the context ends the
			// subscription.
			//
			// A stream that delivered events was working, so the next failure is a
			// fresh one and starts from the shortest delay. Without this, a
			// long-lived subscription reconnecting every few minutes would ratchet
			// its backoff to the maximum and stay there.
			if delivered {
				backoff = eventsReconnectInitialBackoff
			}
			if !sleepUntil(ctx, backoff) {
				return nil
			}
			if !delivered {
				backoff = nextEventsBackoff(backoff)
			}
		}
	},
}

// Reconnect pacing. The common case is one reconnect every few minutes at the
// server's lifetime cap, where the delay is irrelevant; the backoff exists for the
// case where a stream ends immediately and repeatedly, so the client does not spin
// against a server that is refusing or failing.
const (
	eventsReconnectInitialBackoff = 250 * time.Millisecond
	eventsReconnectMaxBackoff     = 30 * time.Second
)

func nextEventsBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > eventsReconnectMaxBackoff {
		return eventsReconnectMaxBackoff
	}
	return next
}

// sleepUntil waits for d, reporting false when the context ended first so the
// caller stops rather than reconnecting after a cancellation.
func sleepUntil(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// openEventStream opens one stream, honouring cancellation while the open is in
// flight. The deadline is recomputed per stream: the server clamps it to its own
// cap, so sending the subscription's remaining lifetime each time keeps the
// client's intent and the server's policy from disagreeing.
// It returns a close function that releases both the stream body and the context
// governing it. They are released together because cancelling the context while
// the body is still being read would tear down the connection mid-event.
func openEventStream(ctx, baseCtx context.Context, client *awid.Client) (*awid.AgentEventStream, func(), error) {
	deadline := time.Now().Add(24 * time.Hour)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}

	type streamResult struct {
		stream *awid.AgentEventStream
		err    error
	}
	openCtx, cancelOpen := context.WithCancel(baseCtx)
	streamCh := make(chan streamResult, 1)
	go func() {
		stream, err := client.EventStream(openCtx, deadline)
		streamCh <- streamResult{stream: stream, err: err}
	}()

	select {
	case <-ctx.Done():
		cancelOpen()
		return nil, nil, ctx.Err()
	case result := <-streamCh:
		if result.err != nil {
			cancelOpen()
			return nil, nil, result.err
		}
		stream := result.stream
		return stream, func() {
			_ = stream.Close()
			cancelOpen()
		}, nil
	}
}

// drainEventStream emits events until the stream ends. It reports whether the
// stream did any real work, and separately an output failure, which is fatal.
//
// "Real work" deliberately excludes the connected preamble. The server sends
// `event: connected` on EVERY stream before anything else
// (server/src/aweb/routes/events.py), so a flag set by any event at all is set by
// every stream that opens - which would make the backoff escalation below
// unreachable and pin the reconnect rate at its floor against a server that is
// only ever accepting and hanging up. The codebase already classifies connected as
// informational rather than delivery: see "connected never wakes" in
// awid/event_source_test.go.
//
// How the stream ENDED is not interesting - every ending is a reconnect - but
// whether it was working is, because that is what separates a healthy subscription
// reaching the lifetime cap from a server that cannot serve one.
func drainEventStream(ctx context.Context, stream *awid.AgentEventStream, enc *json.Encoder) (delivered bool, outputErr error) {
	for {
		ev, err := stream.Next(ctx)
		if err != nil {
			return delivered, nil
		}
		if ev.Type != awid.AgentEventConnected {
			delivered = true
		}

		if jsonFlag {
			// An output failure is not a stream problem and reconnecting cannot fix
			// it. Dropping the event and silently carrying on would lose it with
			// nothing reported anywhere, which is the opposite of what a delivery
			// fix should do.
			if err := enc.Encode(ev); err != nil {
				return delivered, err
			}
		} else {
			printEventText(ev)
		}
	}
}

// isFatalStreamOpenError reports whether reopening would fail the same way. A
// request the server refuses - bad credentials, a revoked certificate, a malformed
// deadline - is refused identically every time, so retrying turns a clear error
// into a silent loop.
func isFatalStreamOpenError(err error) bool {
	var apiErr *awid.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooManyRequests:
			// Whose entire meaning is "retry later". Treating them as fatal ends the
			// subscription at exactly the moment the server is asking it to wait.
			return false
		}
		return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
	}
	return false
}

func printEventText(ev *awid.AgentEvent) {
	switch ev.Type {
	case awid.AgentEventConnected:
		fmt.Printf("[connected] agent_id=%s team_id=%s\n", ev.AgentID, ev.TeamID)
	case awid.AgentEventActionableMail:
		conversation := ""
		if strings.TrimSpace(ev.ConversationID) != "" {
			conversation = fmt.Sprintf(" conversation_id=%s", ev.ConversationID)
		}
		fmt.Printf(
			"[actionable_mail] from=%s wake_mode=%s unread=%d%s message_id=%s subject=%q\n",
			preferredIdentityDisplayLabel(ev.FromAlias, ev.FromAddress, ev.FromStableID, ev.FromDID, ""),
			eventTextValue(ev.WakeMode),
			ev.UnreadCount,
			conversation,
			ev.MessageID,
			ev.Subject,
		)
	case awid.AgentEventActionableChat:
		conversation := ""
		if strings.TrimSpace(ev.ConversationID) != "" {
			conversation = fmt.Sprintf(" conversation_id=%s", ev.ConversationID)
		}
		fmt.Printf(
			"[actionable_chat] from=%s wake_mode=%s unread=%d sender_waiting=%t%s session_id=%s message_id=%s\n",
			preferredIdentityDisplayLabel(ev.FromAlias, ev.FromAddress, ev.FromStableID, ev.FromDID, ""),
			eventTextValue(ev.WakeMode),
			ev.UnreadCount,
			ev.SenderWaiting,
			conversation,
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
