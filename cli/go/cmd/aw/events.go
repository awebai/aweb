package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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
			// The event stream is indefinite unless the caller explicitly supplies --timeout.
			ctx, cancel = context.WithTimeout(baseCtx, time.Duration(eventsStreamTimeout)*time.Second)
			defer cancel()
		}

		enc := json.NewEncoder(os.Stdout)
		printed := newPrintedEvents(printedEventsLimit)

		// A subscription is made of several streams: the server closes every
		// stream at its duration cap (MAX_STREAM_DURATION,
		// server/src/aweb/routes/events.py) and a proxy may cut one sooner. So
		// the end of a stream is a reconnect, and only the context (--timeout or
		// Ctrl-C) ends the subscription.
		backoff := eventsReconnectInitialBackoff
		for {
			stream, closeStream, err := openEventStream(ctx, client.Client)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				// A request the server refuses on its merits is refused the same
				// way on every retry; retrying would hide the reason.
				if isFatalStreamOpenError(err) {
					return err
				}
				if !sleepUntil(ctx, backoff) {
					return nil
				}
				backoff = nextEventsBackoff(backoff)
				continue
			}

			streamStartedAt := time.Now()
			delivered, endErr, outputErr := drainEventStream(ctx, stream, enc, printed)
			streamLasted := time.Since(streamStartedAt)
			closeStream()

			if outputErr != nil {
				return outputErr
			}
			if ctx.Err() != nil {
				return nil
			}
			retryable, fatal := classifyStreamEnd(endErr)
			if fatal != nil {
				return fatal
			}
			if retryable != nil {
				// The server asked to be retried; say why, and back off as
				// for a stream that was not served.
				fmt.Fprintf(os.Stderr, "aw events stream: %v; reconnecting\n", retryable)
				delivered = false
				streamLasted = 0
			}
			// A stream that was served starts the next reconnect from the
			// shortest delay, so a healthy subscription reconnecting at the
			// duration cap does not ratchet its delay upward. A healthy idle
			// stream delivers nothing substantive (the preamble does not count
			// and keepalives are comments that never become events), so having
			// lasted past the health threshold also counts as served.
			healthy := delivered || streamLasted >= healthyStreamDuration()
			if healthy {
				backoff = eventsReconnectInitialBackoff
			}
			if !sleepUntil(ctx, backoff) {
				return nil
			}
			if !healthy {
				backoff = nextEventsBackoff(backoff)
			}
		}
	},
}

// Reconnect pacing. The common case is one reconnect every few minutes at the
// server's duration cap, where the delay is irrelevant; the backoff exists for a
// stream that ends immediately and repeatedly, so the client does not spin
// against a server that is refusing or failing.
const (
	eventsReconnectInitialBackoff = 250 * time.Millisecond
	eventsReconnectMaxBackoff     = 30 * time.Second
)

// defaultHealthyStreamDuration is how long a stream must last to count as
// served even though it carried nothing substantive: one server heartbeat
// interval. It is deliberately not the server's duration cap, since a stream a
// proxy cut early still shows a working server.
const defaultHealthyStreamDuration = 30 * time.Second

// healthyStreamDuration is overridable through AW_EVENTS_HEALTHY_STREAM_MS so
// tests need not hold a stream open for the real interval.
func healthyStreamDuration() time.Duration {
	if raw := os.Getenv("AW_EVENTS_HEALTHY_STREAM_MS"); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultHealthyStreamDuration
}

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
// flight. The deadline is the subscription's remaining time; the server
// clamps it to its own cap. The stream's body is bound to the subscription's
// context, so --timeout and Ctrl-C end a stream that is open and idle. The
// returned close function releases the body and its context together.
func openEventStream(ctx context.Context, client *awid.Client) (*awid.AgentEventStream, func(), error) {
	deadline := time.Now().Add(24 * time.Hour)
	if dl, ok := ctx.Deadline(); ok {
		deadline = dl
	}

	type streamResult struct {
		stream *awid.AgentEventStream
		err    error
	}
	openCtx, cancelOpen := context.WithCancel(ctx)
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

// printedEvents remembers which messages this subscription has already printed.
// Each new stream announces everything still actionable, so mail that stays
// unread is announced again after every reconnect; a consumer is told once. It
// keeps the newest limit messages, forgetting the oldest first, so a
// subscription that runs for weeks does not grow without bound; a forgotten
// message that is announced again prints again.
type printedEvents struct {
	limit int
	seen  map[string]struct{}
	order []string
}

// printedEventsLimit bounds how many messages a subscription remembers.
const printedEventsLimit = 10_000

func newPrintedEvents(limit int) *printedEvents {
	return &printedEvents{limit: limit, seen: map[string]struct{}{}}
}

// firstTime reports whether ev should be printed: always for events that do not
// name a message, and only the first time for one that does.
func (p *printedEvents) firstTime(ev *awid.AgentEvent) bool {
	if strings.TrimSpace(ev.MessageID) == "" {
		return true
	}
	key := string(ev.Type) + "\x00" + ev.MessageID
	if _, seen := p.seen[key]; seen {
		return false
	}
	if len(p.order) >= p.limit {
		delete(p.seen, p.order[0])
		p.order = p.order[1:]
	}
	p.seen[key] = struct{}{}
	p.order = append(p.order, key)
	return true
}

// drainEventStream prints events until the stream ends. It reports whether the
// stream did real work, why it ended, and, separately, an output failure, which
// is fatal. The connected preamble and error frames are lifecycle, not work.
func drainEventStream(ctx context.Context, stream *awid.AgentEventStream, enc *json.Encoder, printed *printedEvents) (delivered bool, endErr error, outputErr error) {
	for {
		ev, err := stream.Next(ctx)
		if err != nil {
			return delivered, err, nil
		}
		if ev.Type != awid.AgentEventConnected && ev.Type != awid.AgentEventError {
			delivered = true
		}
		if !printed.firstTime(ev) {
			continue
		}
		if jsonFlag {
			// Reconnecting cannot fix an output failure, and carrying on would
			// drop the event without a trace.
			if err := enc.Encode(ev); err != nil {
				return delivered, nil, err
			}
		} else {
			printEventText(ev)
		}
	}
}

// classifyStreamEnd sorts why a stream ended. Only the failures reconnecting
// cannot fix are fatal: a grant that ended, and a frame that does not decode.
// A grant-verification outage the server asks to retry is returned as
// retryable. Every other read error is a transport end and reconnects, so an
// error the client does not recognise (an HTTP/2 stream reset, say) never ends
// the subscription.
func classifyStreamEnd(err error) (retryable error, fatal error) {
	if err == nil {
		return nil, nil
	}
	var closed *awid.AgentEventStreamClosedError
	if errors.As(err, &closed) {
		if closed.Retryable() {
			return err, nil
		}
		return nil, err
	}
	var decode *awid.AgentEventDecodeError
	if errors.As(err, &decode) {
		return nil, err
	}
	return nil, nil
}

// isFatalStreamOpenError reports whether reopening would fail the same way: a
// 4xx refusal (bad credentials, a revoked certificate, a malformed deadline),
// except 408 and 429, whose meaning is to retry later.
func isFatalStreamOpenError(err error) bool {
	var apiErr *awid.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.StatusCode {
		case http.StatusRequestTimeout, http.StatusTooManyRequests:
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
