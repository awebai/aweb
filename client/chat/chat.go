// ABOUTME: Chat protocol functions composing low-level aweb-go client methods.
// ABOUTME: Provides Send, Open, History, Pending, HangOn, and ShowPending.

package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aweb/client"
)

const defaultWait = 60 // Default wait timeout in seconds for replies

// sseResult wraps an SSE event or error for channel-based processing.
type sseResult struct {
	event *aweb.SSEEvent
	err   error
}

// streamToChannel bridges SSEStream.Next() to a channel for select-based processing.
// The goroutine exits when ctx is cancelled or the stream returns an error.
func streamToChannel(ctx context.Context, stream *aweb.SSEStream) <-chan sseResult {
	ch := make(chan sseResult, 10)
	go func() {
		defer close(ch)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			ev, err := stream.Next()
			if err != nil {
				ch <- sseResult{err: err}
				return
			}
			ch <- sseResult{event: ev}
		}
	}()
	return ch
}

// parseSSEEvent converts an SSE event to a chat Event.
func parseSSEEvent(sseEvent *aweb.SSEEvent) Event {
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
	if v, ok := data["reader_alias"].(string); ok {
		ev.ReaderAlias = v
	}
	if v, ok := data["hang_on"].(bool); ok {
		ev.HangOn = v
	}
	if v, ok := data["extends_wait_seconds"].(float64); ok {
		ev.ExtendsWaitSeconds = int(v)
	}

	return ev
}

// findSession finds the session ID for a conversation with targetAlias.
// Checks pending first (captures sender_waiting), falls back to listing sessions.
func findSession(ctx context.Context, client *aweb.Client, targetAlias string) (sessionID string, senderWaiting bool, err error) {
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}

	for _, p := range pendingResp.Pending {
		for _, participant := range p.Participants {
			if participant == targetAlias {
				return p.SessionID, p.SenderWaiting, nil
			}
		}
	}

	// Fallback to listing all sessions.
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	for _, s := range sessionsResp.Sessions {
		for _, participant := range s.Participants {
			if participant == targetAlias {
				return s.SessionID, false, nil
			}
		}
	}

	return "", false, fmt.Errorf("no conversation found with %s", targetAlias)
}

// Send sends a message to target agents and optionally waits for a reply.
//
// Wait logic:
//   - opts.Leaving: send with leaving=true, exit immediately
//   - opts.Wait == 0: send, return immediately
//   - opts.StartConversation: ignore targets_left, use 5min default wait if opts.Wait == defaultWait
//   - default: send, if all targets in targets_left → skip wait; else wait opts.Wait seconds
func Send(ctx context.Context, client *aweb.Client, myAlias string, targets []string, message string, opts SendOptions, callback StatusCallback) (*SendResult, error) {
	createResp, err := client.ChatCreateSession(ctx, &aweb.ChatCreateSessionRequest{
		ToAliases: targets,
		Message:   message,
		Leaving:   opts.Leaving,
	})
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}

	result := &SendResult{
		SessionID:   createResp.SessionID,
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
	for _, leftAlias := range createResp.TargetsLeft {
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
		for _, alias := range createResp.TargetsConnected {
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
	if opts.StartConversation && waitSeconds == defaultWait {
		waitSeconds = 300 // 5 minutes
	}
	waitTimeout := time.Duration(waitSeconds) * time.Second

	// SSE stream for reply waiting
	waitDeadline := time.Now().Add(waitTimeout)
	stream, err := client.ChatStream(ctx, createResp.SessionID, waitDeadline)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSE: %w", err)
	}
	defer stream.Close()

	events := streamToChannel(ctx, stream)

	// Skip replayed messages — wait until we see our own sent message.
	sentMessageID := createResp.MessageID
	seenSentMessage := sentMessageID == ""

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
			result.Events = append(result.Events, chatEvent)

			if chatEvent.Type == "read_receipt" {
				if callback != nil {
					callback("read_receipt", fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				if chatEvent.ExtendsWaitSeconds > 0 {
					extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				continue
			}

			if chatEvent.Type == "message" {
				if !seenSentMessage {
					if chatEvent.MessageID != "" && chatEvent.MessageID == sentMessageID {
						seenSentMessage = true
						continue
					}
					if chatEvent.MessageID == "" && chatEvent.FromAgent == myAlias && chatEvent.Body == message {
						seenSentMessage = true
						continue
					}
					continue
				}

				isFromTarget := false
				for _, target := range targets {
					if chatEvent.FromAgent == target {
						isFromTarget = true
						break
					}
				}
				if isFromTarget {
					if chatEvent.HangOn {
						if callback != nil {
							callback("hang_on", fmt.Sprintf("%s: %s", chatEvent.FromAgent, chatEvent.Body))
						}
						if chatEvent.ExtendsWaitSeconds > 0 {
							extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
						} else if callback != nil {
							callback("hang_on", fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
						}
						continue
					}

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
}

// Open fetches unread messages for a conversation and marks them as read.
func Open(ctx context.Context, client *aweb.Client, targetAlias string) (*OpenResult, error) {
	sessionID, senderWaiting, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, aweb.ChatHistoryParams{
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
		Messages:      make([]Event, len(messagesResp.Messages)),
		MarkedRead:    0,
		SenderWaiting: senderWaiting,
	}

	if len(messagesResp.Messages) == 0 {
		result.UnreadWasEmpty = true
		return result, nil
	}

	for i, m := range messagesResp.Messages {
		result.Messages[i] = Event{
			Type:          "message",
			MessageID:     m.MessageID,
			FromAgent:     m.FromAgent,
			Body:          m.Body,
			Timestamp:     m.Timestamp,
			SenderLeaving: m.SenderLeaving,
		}
	}

	lastMessageID := messagesResp.Messages[len(messagesResp.Messages)-1].MessageID
	markReadResp, err := client.ChatMarkRead(ctx, sessionID, &aweb.ChatMarkReadRequest{
		UpToMessageID: lastMessageID,
	})
	if err != nil {
		return nil, fmt.Errorf("marking messages as read: %w", err)
	}
	result.MarkedRead = len(messagesResp.Messages)
	result.WaitExtendedSeconds = markReadResp.WaitExtendedSeconds

	return result, nil
}

// History fetches all messages in a conversation.
func History(ctx context.Context, client *aweb.Client, targetAlias string) (*HistoryResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, aweb.ChatHistoryParams{
		SessionID: sessionID,
		Limit:     1000,
	})
	if err != nil {
		return nil, fmt.Errorf("getting messages: %w", err)
	}

	result := &HistoryResult{
		SessionID: sessionID,
		Messages:  make([]Event, len(messagesResp.Messages)),
	}
	for i, m := range messagesResp.Messages {
		result.Messages[i] = Event{
			Type:      "message",
			FromAgent: m.FromAgent,
			Body:      m.Body,
			Timestamp: m.Timestamp,
		}
	}

	return result, nil
}

// Pending lists conversations with unread messages.
func Pending(ctx context.Context, client *aweb.Client) (*PendingResult, error) {
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	result := &PendingResult{
		Pending:         make([]PendingConversation, len(resp.Pending)),
		MessagesWaiting: resp.MessagesWaiting,
	}
	for i, p := range resp.Pending {
		result.Pending[i] = PendingConversation{
			SessionID:            p.SessionID,
			Participants:         p.Participants,
			LastMessage:          p.LastMessage,
			LastFrom:             p.LastFrom,
			UnreadCount:          p.UnreadCount,
			LastActivity:         p.LastActivity,
			SenderWaiting:        p.SenderWaiting,
			TimeRemainingSeconds: p.TimeRemainingSeconds,
		}
	}

	return result, nil
}

// HangOn sends a hang-on message requesting more time to reply.
func HangOn(ctx context.Context, client *aweb.Client, targetAlias string, message string) (*HangOnResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	msgResp, err := client.ChatSendMessage(ctx, sessionID, &aweb.ChatSendMessageRequest{
		Body:   message,
		HangOn: true,
	})
	if err != nil {
		return nil, fmt.Errorf("sending hang-on message: %w", err)
	}

	return &HangOnResult{
		SessionID:          sessionID,
		TargetAgent:        targetAlias,
		Message:            message,
		ExtendsWaitSeconds: msgResp.ExtendsWaitSeconds,
	}, nil
}

// ShowPending shows the pending conversation with a specific agent.
func ShowPending(ctx context.Context, client *aweb.Client, targetAlias string) (*SendResult, error) {
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
