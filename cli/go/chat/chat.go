// ABOUTME: Chat protocol functions composing low-level aweb-go client methods.
// ABOUTME: Provides Send, Open, History, Pending, ExtendWait, and ShowPending.

package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	awid "github.com/awebai/aw/awid"
)

const DefaultWait = 120 // Default wait timeout in seconds for replies

// maxStreamDeadline is the server-side SSE connection safety net.
// The local waitTimer manages actual wait semantics; this just prevents
// orphaned server connections. Must exceed any possible wait extension chain.
const maxStreamDeadline = 15 * time.Minute

// MaxSendTimeout is the maximum duration a Send() call can take,
// accounting for all possible wait extensions.
const MaxSendTimeout = 16 * time.Minute

// sseResult wraps an SSE event or error for channel-based processing.
type sseResult struct {
	event *awid.SSEEvent
	err   error
}

// streamToChannel bridges SSEStream.Next() to a channel for select-based processing.
// Returns the event channel and a cleanup function. The cleanup function closes the
// stream, signals the goroutine to stop, and blocks until it has exited.
// The caller must call cleanup to avoid goroutine leaks.
func streamToChannel(ctx context.Context, stream *awid.SSEStream) (<-chan sseResult, func()) {
	ch := make(chan sseResult, 10)
	stopCtx, stopCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		defer close(done)
		for {
			ev, err := stream.Next()
			if err != nil {
				select {
				case ch <- sseResult{err: err}:
				case <-stopCtx.Done():
				}
				return
			}
			select {
			case ch <- sseResult{event: ev}:
			case <-stopCtx.Done():
				return
			}
		}
	}()
	cleanup := func() {
		stopCancel()
		stream.Close()
		<-done
	}
	return ch, cleanup
}

// parseSSEEvent converts an SSE event to a chat Event.
func parseSSEEvent(sseEvent *awid.SSEEvent) Event {
	ev := Event{
		Type: sseEvent.Event,
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(sseEvent.Data), &data); err != nil {
		return ev
	}

	if v, ok := data["agent"].(string); ok {
		ev.Agent = v
	}
	if v, ok := data["session_id"].(string); ok {
		ev.SessionID = v
	}
	if v, ok := data["message_id"].(string); ok {
		ev.MessageID = v
	}
	if v, ok := data["from_agent"].(string); ok {
		ev.FromAgent = v
	} else if v, ok := data["from"].(string); ok {
		ev.FromAgent = v
	}
	if v, ok := data["from_address"].(string); ok {
		ev.FromAddress = v
	}
	if v, ok := data["to_address"].(string); ok {
		ev.ToAddress = v
	}
	if v, ok := data["body"].(string); ok {
		ev.Body = v
	}
	if v, ok := data["by"].(string); ok {
		ev.By = v
	}
	if v, ok := data["reason"].(string); ok {
		ev.Reason = v
	}
	if v, ok := data["timestamp"].(string); ok {
		ev.Timestamp = v
	}
	if v, ok := data["sender_leaving"].(bool); ok {
		ev.SenderLeaving = v
	}
	if v, ok := data["sender_waiting"].(bool); ok {
		ev.SenderWaiting = v
	}
	if v, ok := data["reader_alias"].(string); ok {
		ev.ReaderAlias = v
	}
	if v, ok := data["hang_on"].(bool); ok {
		ev.ExtendWait = v
	}
	if v, ok := data["extends_wait_seconds"].(float64); ok {
		ev.ExtendsWaitSeconds = int(v)
	}
	if v, ok := data["from_did"].(string); ok {
		ev.FromDID = v
	}
	if v, ok := data["to_did"].(string); ok {
		ev.ToDID = v
	}
	if v, ok := data["from_stable_id"].(string); ok {
		ev.FromStableID = v
	}
	if v, ok := data["to_stable_id"].(string); ok {
		ev.ToStableID = v
	}
	if v, ok := data["signature"].(string); ok {
		ev.Signature = v
	}
	if v, ok := data["signing_key_id"].(string); ok {
		ev.SigningKeyID = v
	}
	if v, ok := data["is_contact"].(bool); ok {
		ev.IsContact = &v
	}
	if raData, ok := data["rotation_announcement"].(map[string]any); ok {
		ev.RotationAnnouncement = &awid.RotationAnnouncement{}
		if v, ok := raData["old_did"].(string); ok {
			ev.RotationAnnouncement.OldDID = v
		}
		if v, ok := raData["new_did"].(string); ok {
			ev.RotationAnnouncement.NewDID = v
		}
		if v, ok := raData["timestamp"].(string); ok {
			ev.RotationAnnouncement.Timestamp = v
		}
		if v, ok := raData["old_key_signature"].(string); ok {
			ev.RotationAnnouncement.OldKeySignature = v
		}
	}
	if replData, ok := data["replacement_announcement"].(map[string]any); ok {
		ev.ReplacementAnnouncement = &awid.ReplacementAnnouncement{}
		if v, ok := replData["address"].(string); ok {
			ev.ReplacementAnnouncement.Address = v
		}
		if v, ok := replData["old_did"].(string); ok {
			ev.ReplacementAnnouncement.OldDID = v
		}
		if v, ok := replData["new_did"].(string); ok {
			ev.ReplacementAnnouncement.NewDID = v
		}
		if v, ok := replData["controller_did"].(string); ok {
			ev.ReplacementAnnouncement.ControllerDID = v
		}
		if v, ok := replData["timestamp"].(string); ok {
			ev.ReplacementAnnouncement.Timestamp = v
		}
		if v, ok := replData["controller_signature"].(string); ok {
			ev.ReplacementAnnouncement.ControllerSignature = v
		}
	}

	// Verify message signature when identity fields are present.
	from := ev.FromAgent
	if ev.FromAddress != "" {
		from = ev.FromAddress
	}
	env := &awid.MessageEnvelope{
		From:         from,
		FromDID:      ev.FromDID,
		To:           ev.ToAddress,
		ToDID:        ev.ToDID,
		Type:         "chat",
		Body:         ev.Body,
		Timestamp:    ev.Timestamp,
		FromStableID: ev.FromStableID,
		ToStableID:   ev.ToStableID,
		MessageID:    ev.MessageID,
		Signature:    ev.Signature,
		SigningKeyID: ev.SigningKeyID,
	}
	// Error is encoded in VerificationStatus; discard it.
	ev.VerificationStatus, _ = awid.VerifyMessage(env)

	return ev
}

// findSession finds the session ID for a conversation with targetAlias.
// Checks pending first (captures sender_waiting), falls back to listing sessions.
func findSession(ctx context.Context, client *awid.Client, targetAlias string) (sessionID string, senderWaiting bool, err error) {
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}

	var bestPendingID string
	var bestPendingWaiting bool
	bestPendingSize := 0
	for _, p := range pendingResp.Pending {
		for _, participant := range p.Participants {
			if participant == targetAlias {
				if bestPendingSize == 0 || len(p.Participants) < bestPendingSize {
					bestPendingID = p.SessionID
					bestPendingWaiting = p.SenderWaiting
					bestPendingSize = len(p.Participants)
				}
				break
			}
		}
	}
	if bestPendingID != "" {
		return bestPendingID, bestPendingWaiting, nil
	}

	// Fallback to listing all sessions.
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	var bestSessionID string
	bestSessionSize := 0
	for _, s := range sessionsResp.Sessions {
		for _, participant := range s.Participants {
			if participant == targetAlias {
				if bestSessionSize == 0 || len(s.Participants) < bestSessionSize {
					bestSessionID = s.SessionID
					bestSessionSize = len(s.Participants)
				}
				break
			}
		}
	}
	if bestSessionID != "" {
		return bestSessionID, false, nil
	}

	return "", false, fmt.Errorf("no conversation found with %s", targetAlias)
}

// findNetworkSession finds the session ID for a network conversation with targetAddress.
// Checks network pending conversations. No fallback to list-sessions (endpoint not available for network).

// buildMessages converts ChatMessage slice to Event slice.
func buildMessages(messages []awid.ChatMessage) []Event {
	events := make([]Event, len(messages))
	for i, m := range messages {
		events[i] = Event{
			Type:                    "message",
			MessageID:               m.MessageID,
			FromAgent:               m.FromAgent,
			FromAddress:             m.FromAddress,
			ToAddress:               m.ToAddress,
			Body:                    m.Body,
			Timestamp:               m.Timestamp,
			SenderLeaving:           m.SenderLeaving,
			FromDID:                 m.FromDID,
			ToDID:                   m.ToDID,
			FromStableID:            m.FromStableID,
			ToStableID:              m.ToStableID,
			Signature:               m.Signature,
			SigningKeyID:            m.SigningKeyID,
			RotationAnnouncement:    m.RotationAnnouncement,
			ReplacementAnnouncement: m.ReplacementAnnouncement,
			VerificationStatus:      m.VerificationStatus,
			IsContact:               m.IsContact,
		}
	}
	return events
}

// streamOpener opens an SSE stream for a chat session.
// after controls replay: non-nil replays messages after that timestamp; nil skips replay.
type streamOpener func(ctx context.Context, sessionID string, deadline time.Time, after *time.Time) (*awid.SSEStream, error)

// messageAcceptor decides how to handle a received message event during the wait loop.
//
//	accept=true:  treat as the awaited reply
//	skip=true:    silently ignore (e.g., replayed own message)
//	both false:   unrelated message, continue waiting
type messageAcceptor func(ev Event) (accept, skip bool)

// waitForMessage opens an SSE stream and waits for a message matching the acceptor.
// Handles read receipts, extend-wait messages, and wait extensions.
// after controls SSE replay: non-nil replays messages after that timestamp; nil skips replay.
func waitForMessage(ctx context.Context, client *awid.Client, openStream streamOpener, sessionID string, waitSeconds int, after *time.Time, callback StatusCallback, accept messageAcceptor) (*SendResult, error) {
	result := &SendResult{
		SessionID: sessionID,
		Status:    "timeout",
		Events:    []Event{},
	}

	waitTimeout := time.Duration(waitSeconds) * time.Second
	waitDeadline := time.Now().Add(waitTimeout)

	// The server deadline is a safety net for orphaned connections —
	// the local waitTimer manages actual wait semantics.
	stream, err := openStream(ctx, sessionID, time.Now().Add(maxStreamDeadline), after)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSE: %w", err)
	}
	events, streamCleanup := streamToChannel(ctx, stream)
	defer streamCleanup()

	waitStart := time.Now()
	waitTimer := time.NewTimer(waitTimeout)
	defer func() {
		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
	}()

	extendWait := func(extendsSeconds int, reason string) {
		if extendsSeconds <= 0 {
			return
		}
		if time.Now().After(waitDeadline) {
			waitDeadline = time.Now()
		}
		waitDeadline = waitDeadline.Add(time.Duration(extendsSeconds) * time.Second)

		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
		waitTimer.Reset(time.Until(waitDeadline))

		if callback != nil {
			minutes := extendsSeconds / 60
			if minutes > 0 {
				callback("wait_extended", fmt.Sprintf("wait extended by %d min (%s)", minutes, reason))
			} else {
				callback("wait_extended", fmt.Sprintf("wait extended by %ds (%s)", extendsSeconds, reason))
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waitTimer.C:
			result.WaitedSeconds = int(time.Since(waitStart).Seconds())
			return result, nil
		case sr, ok := <-events:
			if !ok || sr.err != nil {
				result.WaitedSeconds = int(time.Since(waitStart).Seconds())
				return result, nil
			}

			chatEvent := parseSSEEvent(sr.event)
			tofuFrom := chatEvent.FromAgent
			if chatEvent.FromAddress != "" {
				tofuFrom = chatEvent.FromAddress
			}
			chatEvent.VerificationStatus, chatEvent.IsContact = client.NormalizeSenderTrust(ctx, chatEvent.VerificationStatus, tofuFrom, chatEvent.FromDID, chatEvent.FromStableID, chatEvent.RotationAnnouncement, chatEvent.ReplacementAnnouncement, chatEvent.IsContact)

			if chatEvent.Type == "read_receipt" {
				result.Events = append(result.Events, chatEvent)
				if callback != nil {
					callback("read_receipt", fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				if chatEvent.ExtendsWaitSeconds > 0 {
					extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				continue
			}

			if chatEvent.Type == "message" {
				accepted, skip := accept(chatEvent)
				if skip {
					continue
				}

				result.Events = append(result.Events, chatEvent)

				if !accepted {
					continue
				}

				if chatEvent.ExtendWait {
					if callback != nil {
						callback("extend_wait", fmt.Sprintf("%s: %s", chatEvent.FromAgent, chatEvent.Body))
					}
					if chatEvent.ExtendsWaitSeconds > 0 {
						extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
					}
					continue
				}

				result.SenderWaiting = chatEvent.SenderWaiting

				if chatEvent.SenderLeaving {
					result.Status = "sender_left"
					result.Reply = chatEvent.Body
					return result, nil
				}

				result.Status = "replied"
				result.Reply = chatEvent.Body
				return result, nil
			}
		}
	}
}

// sendResponse normalizes the response from ChatCreateSession or NetworkCreateChat.
type sendResponse struct {
	SessionID        string
	MessageID        string
	TargetsConnected []string
	TargetsLeft      []string
}

// Send sends a message to target agents and optionally waits for a reply.
//
// Wait logic:
//   - opts.Leaving: send with leaving=true, exit immediately
//   - opts.Wait == 0: send, return immediately
//   - opts.StartConversation: ignore targets_left, use 5min wait unless WaitExplicit
//   - default: send, if all targets in targets_left → skip wait; else wait opts.Wait seconds
func Send(ctx context.Context, client *awid.Client, myAlias string, targets []string, message string, opts SendOptions, callback StatusCallback) (*SendResult, error) {
	sentAt := time.Now()
	createResp, err := client.ChatCreateSession(ctx, &awid.ChatCreateSessionRequest{
		ToAliases: targets,
		Message:   message,
		Leaving:   opts.Leaving,
	})
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}

	return sendCommon(ctx, client, client.ChatStream, sendResponse{
		SessionID:        createResp.SessionID,
		MessageID:        createResp.MessageID,
		TargetsConnected: createResp.TargetsConnected,
		TargetsLeft:      createResp.TargetsLeft,
	}, myAlias, targets, message, opts, &sentAt, callback)
}

// sendCommon handles the post-send wait logic shared by Send and SendNetwork.
func sendCommon(ctx context.Context, client *awid.Client, openStream streamOpener, resp sendResponse, myAlias string, targets []string, message string, opts SendOptions, after *time.Time, callback StatusCallback) (*SendResult, error) {
	result := &SendResult{
		SessionID:   resp.SessionID,
		Status:      "sent",
		TargetAgent: strings.Join(targets, ", "),
		Events:      []Event{},
	}

	if opts.Leaving {
		return result, nil
	}

	if opts.Wait == 0 {
		return result, nil
	}

	// Check if any target has left
	targetHasLeft := false
	for _, leftAlias := range resp.TargetsLeft {
		for _, target := range targets {
			if leftAlias == target {
				targetHasLeft = true
				break
			}
		}
		if targetHasLeft {
			break
		}
	}

	if targetHasLeft && !opts.StartConversation {
		result.Status = "targets_left"
		return result, nil
	}

	// Check target connection status (informational)
	allTargetsConnected := true
	for _, target := range targets {
		found := false
		for _, alias := range resp.TargetsConnected {
			if alias == target {
				found = true
				break
			}
		}
		if !found {
			allTargetsConnected = false
			break
		}
	}
	if !allTargetsConnected {
		result.TargetNotConnected = true
	}

	// Determine wait timeout
	waitSeconds := opts.Wait
	if opts.StartConversation && !opts.WaitExplicit {
		waitSeconds = 300 // 5 minutes
	}

	// Build message acceptor: skip replays, accept only from targets.
	sentMessageID := resp.MessageID
	seenSentMessage := sentMessageID == ""
	acceptor := func(ev Event) (accept, skip bool) {
		if !seenSentMessage {
			if (ev.MessageID != "" && ev.MessageID == sentMessageID) ||
				(ev.MessageID == "" && ev.FromAgent == myAlias && ev.Body == message) {
				seenSentMessage = true
			}
			return false, true
		}
		for _, target := range targets {
			if ev.FromAgent == target {
				return true, false
			}
		}
		return false, false
	}

	waitResult, err := waitForMessage(ctx, client, openStream, resp.SessionID, waitSeconds, after, callback, acceptor)
	if err != nil {
		return nil, err
	}

	if waitResult.Status == "timeout" {
		result.Status = "sent" // backward compat: "sent" means "sent but no reply"
	} else {
		result.Status = waitResult.Status
	}
	result.Reply = waitResult.Reply
	result.Events = waitResult.Events
	result.SenderWaiting = waitResult.SenderWaiting
	result.WaitedSeconds = waitResult.WaitedSeconds
	return result, nil
}

// Listen waits for a message in an existing conversation without sending.
// Returns on any message in the session (not filtered by sender).
func Listen(ctx context.Context, client *awid.Client, targetAlias string, waitSeconds int, callback StatusCallback) (*SendResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	acceptAll := func(ev Event) (bool, bool) { return true, false }

	result, err := waitForMessage(ctx, client, client.ChatStream, sessionID, waitSeconds, nil, callback, acceptAll)
	if err != nil {
		return nil, err
	}

	result.TargetAgent = targetAlias
	return result, nil
}

// Open fetches unread messages for a conversation and marks them as read.
func Open(ctx context.Context, client *awid.Client, targetAlias string) (*OpenResult, error) {
	sessionID, senderWaiting, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, awid.ChatHistoryParams{
		SessionID:  sessionID,
		UnreadOnly: true,
		Limit:      1000,
	})
	if err != nil {
		return nil, fmt.Errorf("getting unread messages: %w", err)
	}

	result := &OpenResult{
		SessionID:     sessionID,
		TargetAgent:   targetAlias,
		Messages:      buildMessages(messagesResp.Messages),
		SenderWaiting: senderWaiting,
	}

	if len(messagesResp.Messages) == 0 {
		result.UnreadWasEmpty = true
		return result, nil
	}

	lastMessageID := messagesResp.Messages[len(messagesResp.Messages)-1].MessageID
	_, err = client.ChatMarkRead(ctx, sessionID, &awid.ChatMarkReadRequest{
		UpToMessageID: lastMessageID,
	})
	if err == nil {
		result.MarkedRead = len(messagesResp.Messages)
	}

	return result, nil
}

// History fetches all messages in a conversation.
func History(ctx context.Context, client *awid.Client, targetAlias string) (*HistoryResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, awid.ChatHistoryParams{
		SessionID: sessionID,
		Limit:     1000,
	})
	if err != nil {
		return nil, fmt.Errorf("getting messages: %w", err)
	}

	return &HistoryResult{
		SessionID: sessionID,
		Messages:  buildMessages(messagesResp.Messages),
	}, nil
}

// Pending lists conversations with unread messages.
func Pending(ctx context.Context, client *awid.Client) (*PendingResult, error) {
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	result := &PendingResult{
		Pending:         make([]PendingConversation, 0, len(resp.Pending)),
		MessagesWaiting: resp.MessagesWaiting,
	}
	for _, p := range resp.Pending {
		result.Pending = append(result.Pending, PendingConversation{
			SessionID:            p.SessionID,
			Participants:         p.Participants,
			LastMessage:          p.LastMessage,
			LastFrom:             p.LastFrom,
			UnreadCount:          p.UnreadCount,
			LastActivity:         p.LastActivity,
			SenderWaiting:        p.SenderWaiting,
			TimeRemainingSeconds: p.TimeRemainingSeconds,
		})
	}

	return result, nil
}

// ExtendWait sends an extend-wait message requesting more time to reply.
func ExtendWait(ctx context.Context, client *awid.Client, targetAlias string, message string) (*ExtendWaitResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	msgResp, err := client.ChatSendMessage(ctx, sessionID, &awid.ChatSendMessageRequest{
		Body:       message,
		ExtendWait: true,
	})
	if err != nil {
		return nil, fmt.Errorf("sending extend-wait message: %w", err)
	}

	return &ExtendWaitResult{
		SessionID:          sessionID,
		TargetAgent:        targetAlias,
		Message:            message,
		ExtendsWaitSeconds: msgResp.ExtendsWaitSeconds,
	}, nil
}

// ShowPending shows the pending conversation with a specific agent.
func ShowPending(ctx context.Context, client *awid.Client, targetAlias string) (*SendResult, error) {
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	for _, p := range pendingResp.Pending {
		for _, participant := range p.Participants {
			if participant == targetAlias {
				return &SendResult{
					SessionID:     p.SessionID,
					Status:        "pending",
					TargetAgent:   targetAlias,
					Reply:         p.LastMessage,
					SenderWaiting: p.SenderWaiting,
					Events: []Event{
						{
							Type:      "message",
							FromAgent: p.LastFrom,
							Body:      p.LastMessage,
							Timestamp: p.LastActivity,
						},
					},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no pending conversation with %s", targetAlias)
}

// --- Network variants ---
// These mirror the OSS functions above but route through network endpoints.

// ListenNetwork waits for a message in a network conversation without sending.
