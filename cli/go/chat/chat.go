// ABOUTME: Chat protocol functions composing low-level aweb-go client methods.
// ABOUTME: Provides Send, Open, History, Pending, ExtendWait, and ShowPending.

package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func classifyChatTargets(targets []string) (aliases []string, dids []string, addresses []string) {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		switch {
		case strings.HasPrefix(target, "did:"):
			dids = append(dids, target)
		case strings.Contains(target, "/"):
			addresses = append(addresses, target)
		default:
			aliases = append(aliases, target)
		}
	}
	return aliases, dids, addresses
}

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
	if v, ok := data["reply_to_message_id"].(string); ok {
		ev.ReplyToMessageID = v
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

func addressHandle(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "did:") {
		return ""
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func exactParticipantMatch(participants []string, participantAddresses []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, participant := range participants {
		if strings.TrimSpace(participant) == target {
			return true
		}
	}
	for _, participant := range participantAddresses {
		if strings.TrimSpace(participant) == target {
			return true
		}
	}
	return false
}

func uniqueHandleParticipantMatch(participants []string, _ []string, target string) bool {
	handle := addressHandle(target)
	if handle == "" {
		return false
	}
	for _, participant := range participants {
		if strings.TrimSpace(participant) == handle {
			return true
		}
	}
	return false
}

func normalizeSessionTarget(ctx context.Context, client *awid.Client, target string) string {
	target = strings.TrimSpace(target)
	if target == "" || !strings.HasPrefix(target, "did:") || client == nil {
		return target
	}
	identity, err := client.ResolveIdentity(ctx, target)
	if err != nil || identity == nil {
		return target
	}
	if address := strings.TrimSpace(identity.Address); address != "" {
		return address
	}
	if handle := strings.TrimSpace(identity.Handle); handle != "" {
		return handle
	}
	return target
}

// findSession finds the session ID for a conversation with targetAlias.
// Checks pending first (captures sender_waiting), falls back to listing sessions.
//
// Selection priority for pending sessions:
//  1. sender_waiting sessions over non-waiting (urgent conversations first)
//  2. smallest participant count (1:1 over group)
//  3. most recent LastActivity (tiebreaker)
//
// Selection priority for fallback (all sessions):
//  1. smallest participant count
//  2. most recent CreatedAt (tiebreaker)
func findSession(ctx context.Context, client *awid.Client, targetAlias string) (sessionID string, senderWaiting bool, err error) {
	targetAlias = normalizeSessionTarget(ctx, client, targetAlias)
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}

	selectPending := func(match func([]string, []string, string) bool, requireUnique bool) (string, bool, error) {
		var bestPendingID string
		var bestPendingWaiting bool
		var bestPendingActivity string
		bestPendingSize := 0
		matchCount := 0
		for _, p := range pendingResp.Pending {
			if !match(p.Participants, p.ParticipantAddresses, targetAlias) {
				continue
			}
			matchCount++
			better := bestPendingSize == 0
			if !better {
				// Prefer sender_waiting over non-waiting.
				if p.SenderWaiting && !bestPendingWaiting {
					better = true
				} else if !p.SenderWaiting && bestPendingWaiting {
					better = false
				} else if len(p.Participants) < bestPendingSize {
					better = true
				} else if len(p.Participants) == bestPendingSize && p.LastActivity > bestPendingActivity {
					better = true
				}
			}
			if better {
				bestPendingID = p.SessionID
				bestPendingWaiting = p.SenderWaiting
				bestPendingSize = len(p.Participants)
				bestPendingActivity = p.LastActivity
			}
		}
		if requireUnique && matchCount > 1 {
			return "", false, fmt.Errorf("multiple conversations match %s; run `aw chat pending` to choose one", targetAlias)
		}
		if bestPendingID != "" {
			return bestPendingID, bestPendingWaiting, nil
		}
		return "", false, nil
	}
	bestPendingID, bestPendingWaiting, err := selectPending(exactParticipantMatch, false)
	if err != nil {
		return "", false, err
	}
	if bestPendingID != "" {
		return bestPendingID, bestPendingWaiting, nil
	}
	bestPendingID, bestPendingWaiting, err = selectPending(uniqueHandleParticipantMatch, true)
	if err != nil {
		return "", false, err
	}
	if bestPendingID != "" {
		return bestPendingID, bestPendingWaiting, nil
	}

	// Fallback to listing all sessions.
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	selectSession := func(match func([]string, []string, string) bool, requireUnique bool) (string, error) {
		var bestSessionID string
		var bestSessionCreated string
		bestSessionSize := 0
		matchCount := 0
		for _, s := range sessionsResp.Sessions {
			if !match(s.Participants, s.ParticipantAddresses, targetAlias) {
				continue
			}
			matchCount++
			better := bestSessionSize == 0
			if !better {
				if len(s.Participants) < bestSessionSize {
					better = true
				} else if len(s.Participants) == bestSessionSize && s.CreatedAt > bestSessionCreated {
					better = true
				}
			}
			if better {
				bestSessionID = s.SessionID
				bestSessionSize = len(s.Participants)
				bestSessionCreated = s.CreatedAt
			}
		}
		if requireUnique && matchCount > 1 {
			return "", fmt.Errorf("multiple conversations match %s; run `aw chat pending` to choose one", targetAlias)
		}
		return bestSessionID, nil
	}
	bestSessionID, err := selectSession(exactParticipantMatch, false)
	if err != nil {
		return "", false, err
	}
	if bestSessionID != "" {
		return bestSessionID, false, nil
	}
	bestSessionID, err = selectSession(uniqueHandleParticipantMatch, true)
	if err != nil {
		return "", false, err
	}
	if bestSessionID != "" {
		return bestSessionID, false, nil
	}

	return "", false, fmt.Errorf("no conversation found with %s", targetAlias)
}

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
			ReplyToMessageID:        m.ReplyToMessageID,
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

func markReadBestEffort(ctx context.Context, client *awid.Client, sessionID, messageID string) bool {
	if client == nil || sessionID == "" || strings.TrimSpace(messageID) == "" {
		return false
	}
	req := &awid.ChatMarkReadRequest{UpToMessageID: messageID}
	if _, err := client.ChatMarkRead(ctx, sessionID, req); err == nil {
		return true
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
	}
	_, err := client.ChatMarkRead(ctx, sessionID, req)
	return err == nil
}

// markLastRead marks the last received message as read (best-effort).
// This prevents the notify hook from showing messages that were already
// delivered via SSE during send-and-wait or listen.
func markLastRead(ctx context.Context, client *awid.Client, sessionID string, events []Event) {
	if sessionID == "" {
		return
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == "message" && events[i].MessageID != "" {
			_ = markReadBestEffort(ctx, client, sessionID, events[i].MessageID)
			return
		}
	}
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
	waitStart := time.Now()

	// The server deadline is a safety net for orphaned connections —
	// the local waitTimer manages actual wait semantics.
	stream, err := openStream(ctx, sessionID, time.Now().Add(maxStreamDeadline), after)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if isCleanEOF(err) {
			if client != nil {
				_, _ = client.ChatHistory(ctx, awid.ChatHistoryParams{
					SessionID: sessionID,
					Limit:     1,
				})
			}
			result.WaitedSeconds = int(time.Since(waitStart).Seconds())
			return result, nil
		}
		return nil, fmt.Errorf("connecting to SSE: %w", err)
	}
	events, streamCleanup := streamToChannel(ctx, stream)
	defer streamCleanup()

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

func isCleanEOF(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, io.EOF)
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

	// Compute the actual wait duration so the server can track it.
	waitSeconds := opts.Wait
	if opts.StartConversation && !opts.WaitExplicit {
		waitSeconds = 300
	}

	aliases, dids, addresses := classifyChatTargets(targets)
	req := &awid.ChatCreateSessionRequest{
		ToAliases:   aliases,
		ToDIDs:      dids,
		ToAddresses: addresses,
		Message:     message,
		Leaving:   opts.Leaving,
	}
	if waitSeconds > 0 {
		req.WaitSeconds = &waitSeconds
	}
	createResp, err := client.ChatCreateSession(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}

	return sendCommon(ctx, client, client.ChatStream, sendResponse{
		SessionID:        createResp.SessionID,
		MessageID:        createResp.MessageID,
		TargetsConnected: createResp.TargetsConnected,
		TargetsLeft:      createResp.TargetsLeft,
	}, myAlias, targets, message, waitSeconds, opts, &sentAt, callback)
}

// sendCommon handles the post-send wait logic after a message has been created.
// resolvedWait is the actual wait duration in seconds, already accounting for
// StartConversation upgrades. This must match what was sent to the server.
func sendCommon(ctx context.Context, client *awid.Client, openStream streamOpener, resp sendResponse, myAlias string, targets []string, message string, resolvedWait int, opts SendOptions, after *time.Time, callback StatusCallback) (*SendResult, error) {
	result := &SendResult{
		SessionID:   resp.SessionID,
		Status:      "sent",
		TargetAgent: strings.Join(targets, ", "),
		Events:      []Event{},
	}
	targetStatusNames := make([][]string, 0, len(targets))
	for _, target := range targets {
		targetStatusNames = append(targetStatusNames, normalizedChatTargetNames(ctx, client, target))
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
		for _, targetNames := range targetStatusNames {
			if chatTargetNameListContains(targetNames, leftAlias) {
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
	for _, targetNames := range targetStatusNames {
		found := false
		for _, alias := range resp.TargetsConnected {
			if chatTargetNameListContains(targetNames, alias) {
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

	// Build message acceptor: skip replays, accept only from targets.
	// The gate opens when we see our sent message by ID. If the server
	// didn't return a message ID (sentMessageID==""), the gate starts open.
	sentMessageID := resp.MessageID
	seenSentMessage := sentMessageID == ""
	acceptor := func(ev Event) (accept, skip bool) {
		if !seenSentMessage {
			if ev.MessageID == sentMessageID {
				seenSentMessage = true
			}
			return false, true
		}
		for _, target := range targets {
			if chatEventMatchesTarget(ev, target) {
				return true, false
			}
		}
		return false, false
	}

	waitResult, err := waitForMessage(ctx, client, openStream, resp.SessionID, resolvedWait, after, callback, acceptor)
	if err != nil {
		return nil, err
	}

	markLastRead(ctx, client, resp.SessionID, waitResult.Events)

	result.Status = waitResult.Status
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

	markLastRead(ctx, client, sessionID, result.Events)

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
		SenderWaiting: senderWaiting,
	}

	if len(messagesResp.Messages) == 0 {
		result.UnreadWasEmpty = true
		return result, nil
	}

	filteredMessages := FilterDeliveredMessages(messagesResp.Messages)
	result.Messages = buildMessages(filteredMessages)

	if ids := DeliveredMessageIDs(messagesResp.Messages); len(ids) > 0 {
		_ = SaveDeliveredIDs(ids)
	}

	lastMessageID := messagesResp.Messages[len(messagesResp.Messages)-1].MessageID
	if markReadBestEffort(ctx, client, sessionID, lastMessageID) {
		result.MarkedRead = len(messagesResp.Messages)
	}
	if len(result.Messages) == 0 {
		result.UnreadWasEmpty = true
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
			ParticipantAddresses: p.ParticipantAddresses,
			LastMessage:          p.LastMessage,
			LastFrom:             p.LastFrom,
			LastFromAddress:      p.LastFromAddress,
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
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	for _, p := range pendingResp.Pending {
		if p.SessionID != sessionID {
			continue
		}
		return &SendResult{
			SessionID:     p.SessionID,
			Status:        "pending",
			TargetAgent:   targetAlias,
			Reply:         p.LastMessage,
			SenderWaiting: p.SenderWaiting,
			Events: []Event{
				{
					Type:        "message",
					FromAgent:   p.LastFrom,
					FromAddress: p.LastFromAddress,
					Body:        p.LastMessage,
					Timestamp:   p.LastActivity,
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("no pending conversation with %s", targetAlias)
}

func chatEventMatchesTarget(ev Event, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, candidate := range []string{
		strings.TrimSpace(ev.FromAgent),
		strings.TrimSpace(ev.FromAddress),
		strings.TrimSpace(ev.FromStableID),
		strings.TrimSpace(ev.FromDID),
	} {
		if candidate != "" && candidate == target {
			return true
		}
	}
	return false
}

func normalizedChatTargetNames(ctx context.Context, client *awid.Client, target string) []string {
	names := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range names {
			if existing == value {
				return
			}
		}
		names = append(names, value)
	}

	appendUnique(target)
	normalized := normalizeSessionTarget(ctx, client, target)
	appendUnique(normalized)
	appendUnique(addressHandle(target))
	appendUnique(addressHandle(normalized))
	return names
}

func chatTargetNameListContains(candidates []string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if candidate == value {
			return true
		}
	}
	return false
}
