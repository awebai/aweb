package main

import (
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

// formatVerificationTag returns a warning string for non-verified messages.
// Returns empty string for verified or unset status.
// ALL CAPS for active security failures; lowercase for informational (no signature present).
func formatVerificationTag(status awid.VerificationStatus) string {
	switch status {
	case awid.Failed:
		return " [VERIFICATION FAILED]"
	case awid.IdentityMismatch:
		return " [IDENTITY MISMATCH]"
	case awid.Unverified:
		return " [unverified]"
	default:
		return ""
	}
}

// formatContactTag returns a contact annotation.
// nil means the server didn't report it (no tag); false means not a contact.
func formatContactTag(isContact *bool) string {
	if isContact == nil {
		return ""
	}
	if !*isContact {
		return " [not in contacts]"
	}
	return ""
}

// formatChatEventLine formats a single chat event as "[HH:MM:SS] agent: body" with tags.
func formatChatEventLine(m chat.Event) string {
	tags := formatVerificationTag(m.VerificationStatus) + formatContactTag(m.IsContact)
	from := preferredIdentityLabel(m.FromAgent, m.FromAddress, "")
	ts := ""
	if m.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, m.Timestamp); err == nil {
			ts = t.Format("15:04:05")
		}
	}
	if ts != "" {
		return fmt.Sprintf("[%s] %s%s: %s\n", ts, from, tags, m.Body)
	}
	return fmt.Sprintf("%s%s: %s\n", from, tags, m.Body)
}

// --- introspect/whoami ---

func formatIntrospect(v any) string {
	out := v.(introspectOutput)
	var sb strings.Builder
	if routing := awid.RoutingHandle(out.Alias, out.Address, out.Lifetime); routing != "" {
		sb.WriteString(fmt.Sprintf("Routing:   %s\n", routing))
	}
	if out.Domain != "" {
		sb.WriteString(fmt.Sprintf("Domain:    %s\n", out.Domain))
	}
	if address := awid.PublicAddress(out.Address, out.Lifetime); address != "" {
		sb.WriteString(fmt.Sprintf("Address:   %s\n", address))
	}
	if out.HumanName != "" {
		sb.WriteString(fmt.Sprintf("Human:     %s\n", out.HumanName))
	}
	if out.AgentType != "" {
		sb.WriteString(fmt.Sprintf("Type:      %s\n", out.AgentType))
	}
	if out.AccessMode != "" {
		sb.WriteString(fmt.Sprintf("Access:    %s\n", out.AccessMode))
	}
	if out.DID != "" {
		sb.WriteString(fmt.Sprintf("DID:       %s\n", out.DID))
	}
	if out.StableID != "" {
		sb.WriteString(fmt.Sprintf("Stable ID: %s\n", out.StableID))
	}
	if out.Custody != "" {
		sb.WriteString(fmt.Sprintf("Custody:   %s\n", out.Custody))
	}
	if out.Lifetime != "" {
		sb.WriteString(fmt.Sprintf("Identity:  %s\n", awid.DescribeIdentityClass(out.Lifetime)))
	}
	return sb.String()
}

// --- mail ---

func formatMailInbox(v any) string {
	resp := v.(*awid.InboxResponse)
	if len(resp.Messages) == 0 {
		return "No messages.\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MAILS: %d\n\n", len(resp.Messages)))
	for _, msg := range resp.Messages {
		subj := strings.TrimSpace(msg.Subject)
		if subj != "" {
			subj = " — " + subj
		}
		tags := formatVerificationTag(msg.VerificationStatus) + formatContactTag(msg.IsContact)
		sb.WriteString(fmt.Sprintf("- %s%s%s: %s\n", preferredIdentityLabel(msg.FromAlias, msg.FromAddress, ""), subj, tags, msg.Body))
	}
	return sb.String()
}

// --- chat ---

func formatChatSend(v any) string {
	result := v.(*chat.SendResult)
	var sb strings.Builder

	writeChatLine := func(prefix, agent, ts string) {
		timeAgo := ""
		if ts != "" {
			timeAgo = formatTimeAgo(ts)
		}
		if timeAgo != "" {
			sb.WriteString(fmt.Sprintf("%s: %s — %s\n", prefix, agent, timeAgo))
		} else {
			sb.WriteString(fmt.Sprintf("%s: %s\n", prefix, agent))
		}
	}

	// Prefer tags/timestamp from the reply message event, not from auxiliary
	// events like read_receipt (which are typically unsigned and should not
	// influence verification display).
	pickTagEvent := func() *chat.Event {
		// Prefer a message event matching the reply body (when present).
		if strings.TrimSpace(result.Reply) != "" {
			for i := len(result.Events) - 1; i >= 0; i-- {
				ev := &result.Events[i]
				if ev.Type == "message" && strings.TrimSpace(ev.Body) == strings.TrimSpace(result.Reply) {
					return ev
				}
			}
		}
		// Otherwise, use the most recent message event.
		for i := len(result.Events) - 1; i >= 0; i-- {
			ev := &result.Events[i]
			if ev.Type == "message" {
				return ev
			}
		}
		// Fallback: any event, if present.
		if len(result.Events) > 0 {
			return &result.Events[0]
		}
		return nil
	}
	tagEvent := pickTagEvent()

	timestamp := ""
	tags := ""
	if tagEvent != nil {
		timestamp = tagEvent.Timestamp
		tags = formatVerificationTag(tagEvent.VerificationStatus) + formatContactTag(tagEvent.IsContact)
	}
	replyFrom := preferredIdentityLabel(
		func() string {
			if tagEvent == nil {
				return ""
			}
			return tagEvent.FromAgent
		}(),
		func() string {
			if tagEvent == nil {
				return ""
			}
			return tagEvent.FromAddress
		}(),
		result.TargetAgent,
	)

	switch result.Status {
	case "replied":
		writeChatLine("Chat from", replyFrom+tags, timestamp)
		sb.WriteString(fmt.Sprintf("Body: %s\n", result.Reply))
		return sb.String()

	case "sender_left":
		writeChatLine("Chat from", replyFrom+tags, timestamp)
		sb.WriteString(fmt.Sprintf("Body: %s\n", result.Reply))
		sb.WriteString(fmt.Sprintf("Note: %s has left the exchange\n", result.TargetAgent))
		return sb.String()

	case "pending":
		incomingReply := true
		if tagEvent != nil {
			incomingReply = false
			target := strings.TrimSpace(result.TargetAgent)
			if target == "" {
				incomingReply = true
			}
			if strings.EqualFold(strings.TrimSpace(tagEvent.FromAgent), target) || strings.EqualFold(strings.TrimSpace(tagEvent.FromAddress), target) {
				incomingReply = true
			}
		}

		if incomingReply {
			writeChatLine("Chat from", replyFrom+tags, timestamp)
			if result.SenderWaiting {
				sb.WriteString("Status: WAITING for your reply\n")
			}
			sb.WriteString(fmt.Sprintf("Body: %s\n", result.Reply))
			sb.WriteString(fmt.Sprintf("Next: Run \"aw chat send-and-wait %s \\\"your reply\\\"\"\n", result.TargetAgent))
		} else {
			writeChatLine("Chat to", result.TargetAgent, timestamp)
			sb.WriteString(fmt.Sprintf("Body: %s\n", result.Reply))
			sb.WriteString(fmt.Sprintf("Awaiting reply from %s.\n", result.TargetAgent))
		}
		return sb.String()

	case "sent":
		sb.WriteString(fmt.Sprintf("Message sent to %s\n", result.TargetAgent))
		if result.TargetNotConnected {
			sb.WriteString(fmt.Sprintf("Note: %s was not connected.\n", result.TargetAgent))
		}
		return sb.String()

	case "timeout":
		sb.WriteString(fmt.Sprintf("Message sent to %s\n", result.TargetAgent))
		if result.TargetNotConnected {
			sb.WriteString(fmt.Sprintf("Note: %s was not connected.\n", result.TargetAgent))
		}
		sb.WriteString(fmt.Sprintf("Waited %ds — no reply\n", result.WaitedSeconds))
		return sb.String()

	case "targets_left":
		sb.WriteString(fmt.Sprintf("Message sent to %s\n", result.TargetAgent))
		sb.WriteString(fmt.Sprintf("%s previously left the conversation.\n", result.TargetAgent))
		sb.WriteString(fmt.Sprintf("To start a new exchange, run: \"aw chat send-and-wait %s \\\"message\\\" --start-conversation\"\n", result.TargetAgent))
		return sb.String()
	}

	// Fallback: show message events.
	messageIndex := 0
	for _, event := range result.Events {
		if event.Type != "message" {
			continue
		}
		if messageIndex > 0 {
			sb.WriteString("\n---\n\n")
		}
		tags := formatVerificationTag(event.VerificationStatus) + formatContactTag(event.IsContact)
		writeChatLine("Chat from", preferredIdentityLabel(event.FromAgent, event.FromAddress, "")+tags, event.Timestamp)
		sb.WriteString(fmt.Sprintf("Body: %s\n", event.Body))
		messageIndex++
	}

	if sb.Len() == 0 {
		sb.WriteString("No chat events.\n")
	}

	return sb.String()
}

func formatChatPending(v any) string {
	result := v.(*chat.PendingResult)
	if len(result.Pending) == 0 {
		return "No pending conversations\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CHATS: %d unread conversation(s)\n\n", len(result.Pending)))

	for _, p := range result.Pending {
		openHint := ""
		displayFrom := preferredIdentityLabel(p.LastFrom, p.LastFromAddress, "")
		openTarget := ""
		if len(p.Participants) == 1 {
			openTarget = strings.TrimSpace(p.Participants[0])
			if len(p.ParticipantAddresses) == 1 && strings.TrimSpace(p.ParticipantAddresses[0]) != "" {
				openTarget = strings.TrimSpace(p.ParticipantAddresses[0])
			}
		}
		if openTarget != "" {
			openHint = fmt.Sprintf(" — Run \"aw chat open %s\"", openTarget)
		}

		if p.SenderWaiting {
			timeInfo := ""
			if p.TimeRemainingSeconds != nil && *p.TimeRemainingSeconds < 60 && *p.TimeRemainingSeconds > 0 {
				timeInfo = fmt.Sprintf(" (%ds left)", *p.TimeRemainingSeconds)
			}
			sb.WriteString(fmt.Sprintf("  CHAT WAITING: %s%s (unread: %d)%s\n", displayFrom, timeInfo, p.UnreadCount, openHint))
		} else {
			sb.WriteString(fmt.Sprintf("  CHAT: %s (unread: %d)%s\n", displayFrom, p.UnreadCount, openHint))
		}
	}

	return sb.String()
}

func formatChatOpen(v any) string {
	result := v.(*chat.OpenResult)
	if len(result.Messages) == 0 {
		if result.UnreadWasEmpty {
			return fmt.Sprintf("No unread chat messages for %s\n", result.TargetAgent)
		}
		return "No unread chat messages\n"
	}

	var sb strings.Builder
	if result.MarkedRead > 0 {
		sb.WriteString(fmt.Sprintf("Unread chat messages (%d marked as read):\n\n", result.MarkedRead))
	} else {
		sb.WriteString(fmt.Sprintf("Unread chat messages (%d):\n\n", len(result.Messages)))
	}
	if result.SenderWaiting {
		sb.WriteString(fmt.Sprintf("Status: %s is WAITING for your reply\n\n", result.TargetAgent))
	}

	for i, m := range result.Messages {
		if i > 0 {
			sb.WriteString("\n---\n\n")
		}
		sb.WriteString(formatChatEventLine(m))
	}

	sb.WriteString(fmt.Sprintf("\nNext: Run \"aw chat send-and-wait %s \\\"your reply\\\"\"", result.TargetAgent))
	if result.SenderWaiting {
		sb.WriteString(fmt.Sprintf(" or \"aw chat extend-wait %s \\\"message\\\"\"", result.TargetAgent))
	}
	sb.WriteString("\n")

	return sb.String()
}

func formatChatHistory(v any) string {
	result := v.(*chat.HistoryResult)
	if len(result.Messages) == 0 {
		return "No messages in conversation\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Conversation history (%d messages):\n\n", len(result.Messages)))

	for _, m := range result.Messages {
		sb.WriteString(formatChatEventLine(m))
	}

	return sb.String()
}

func formatChatExtendWait(v any) string {
	result := v.(*chat.ExtendWaitResult)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Sent extend-wait to %s\n", result.TargetAgent))
	sb.WriteString(fmt.Sprintf("Message: %s\n", result.Message))
	if result.ExtendsWaitSeconds > 0 {
		minutes := result.ExtendsWaitSeconds / 60
		sb.WriteString(fmt.Sprintf("%s's wait extended by %d min\n", result.TargetAgent, minutes))
	}
	return sb.String()
}

// --- locks ---

func formatLockAcquire(v any) string {
	resp := v.(*aweb.ReservationAcquireResponse)
	return fmt.Sprintf("Locked %s\n", resp.ResourceKey)
}

func formatLockRenew(v any) string {
	resp := v.(*aweb.ReservationRenewResponse)
	remaining := ttlRemainingSeconds(resp.ExpiresAt, time.Now())
	return fmt.Sprintf("Renewed %s (expires in %s)\n", resp.ResourceKey, formatDuration(remaining))
}

func formatLockRelease(v any) string {
	resp := v.(*aweb.ReservationReleaseResponse)
	return fmt.Sprintf("Released %s\n", resp.ResourceKey)
}

func formatLockRevoke(v any) string {
	resp := v.(*aweb.ReservationRevokeResponse)
	return fmt.Sprintf("Revoked %d lock(s)\n", resp.RevokedCount)
}

func formatLockList(v any) string {
	resp := v.(*aweb.ReservationListResponse)
	if len(resp.Reservations) == 0 {
		return "No active locks.\n"
	}
	var sb strings.Builder
	now := time.Now()
	for _, r := range resp.Reservations {
		sb.WriteString(fmt.Sprintf("- %s — %s (expires in %s)\n", r.ResourceKey, r.HolderAlias, formatDuration(ttlRemainingSeconds(r.ExpiresAt, now))))
	}
	return sb.String()
}

// --- contacts ---

func formatContactsList(v any) string {
	resp := v.(*awid.ContactListResponse)
	if len(resp.Contacts) == 0 {
		return "No contacts.\n"
	}
	var sb strings.Builder
	for _, c := range resp.Contacts {
		label := ""
		if c.Label != "" {
			label = " [" + c.Label + "]"
		}
		sb.WriteString(fmt.Sprintf("- %s%s\n", c.ContactAddress, label))
	}
	return sb.String()
}

func formatContactAdd(v any) string {
	resp := v.(*awid.ContactCreateResponse)
	return fmt.Sprintf("Added contact %s\n", resp.ContactAddress)
}

// --- network ---

func formatDirectoryGet(v any) string {
	resp := v.(*awid.NetworkDirectoryAgent)
	handle := resp.Alias
	if resp.Name != "" {
		handle = resp.Name
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Identity:     %s/%s\n", resp.Domain, handle))
	if resp.Description != "" {
		sb.WriteString(fmt.Sprintf("Description:  %s\n", resp.Description))
	}
	if len(resp.Capabilities) > 0 {
		sb.WriteString(fmt.Sprintf("Capabilities: %s\n", strings.Join(resp.Capabilities, ", ")))
	}
	return sb.String()
}

func formatDirectorySearch(v any) string {
	resp := v.(*awid.NetworkDirectoryResponse)
	if len(resp.Agents) == 0 {
		return "No identities found.\n"
	}
	var sb strings.Builder
	for _, a := range resp.Agents {
		handle := a.Alias
		if a.Name != "" {
			handle = a.Name
		}
		desc := ""
		if a.Description != "" {
			desc = " — " + a.Description
		}
		sb.WriteString(fmt.Sprintf("- %s/%s%s\n", a.Domain, handle, desc))
	}
	return sb.String()
}
