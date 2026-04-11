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
	from := preferredIdentityDisplayLabel(m.FromAgent, m.FromAddress, m.FromStableID, m.FromDID, "")
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

func preferredIdentityDisplayLabel(alias string, address string, stableID string, did string, fallback string) string {
	label := preferredIdentityLabel(alias, address, "")
	if label != "" {
		return label
	}
	stableID = strings.TrimSpace(stableID)
	if stableID != "" {
		return stableID
	}
	did = strings.TrimSpace(did)
	if did != "" {
		return did
	}
	return strings.TrimSpace(fallback)
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
		sb.WriteString(fmt.Sprintf("- %s%s%s: %s\n", preferredIdentityDisplayLabel(msg.FromAlias, msg.FromAddress, msg.FromStableID, msg.FromDID, ""), subj, tags, msg.Body))
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
	replyFrom := preferredIdentityDisplayLabel(
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
		func() string {
			if tagEvent == nil {
				return ""
			}
			return tagEvent.FromStableID
		}(),
		func() string {
			if tagEvent == nil {
				return ""
			}
			return tagEvent.FromDID
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
			if strings.TrimSpace(result.TargetAgent) == "" {
				incomingReply = true
			}
			if chatEventMatchesDisplayTarget(tagEvent, result.TargetAgent) {
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
		writeChatLine("Chat from", preferredIdentityDisplayLabel(event.FromAgent, event.FromAddress, event.FromStableID, event.FromDID, "")+tags, event.Timestamp)
		sb.WriteString(fmt.Sprintf("Body: %s\n", event.Body))
		messageIndex++
	}

	if sb.Len() == 0 {
		sb.WriteString("No chat events.\n")
	}

	return sb.String()
}

func formatChatTargetNames(value string) []string {
	names := []string{}
	appendUnique := func(candidate string) {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return
		}
		for _, existing := range names {
			if strings.EqualFold(existing, candidate) {
				return
			}
		}
		names = append(names, candidate)
	}

	appendUnique(value)
	value = strings.TrimSpace(value)
	if value != "" && strings.HasPrefix(value, "did:aw:") {
		appendUnique(strings.TrimPrefix(value, "did:aw:"))
	}
	if value != "" && !strings.HasPrefix(value, "did:") {
		parts := strings.SplitN(value, "/", 2)
		if len(parts) == 2 {
			appendUnique(parts[1])
		}
	}
	return names
}

func formatChatTargetListsOverlap(left []string, right []string) bool {
	for _, leftValue := range left {
		for _, rightValue := range right {
			if strings.EqualFold(strings.TrimSpace(leftValue), strings.TrimSpace(rightValue)) {
				return true
			}
		}
	}
	return false
}

func chatEventMatchesDisplayTarget(ev *chat.Event, target string) bool {
	if ev == nil {
		return false
	}
	targetNames := formatChatTargetNames(target)
	if len(targetNames) == 0 {
		return false
	}
	eventNames := []string{}
	for _, value := range []string{
		ev.FromAgent,
		ev.FromAddress,
		ev.FromDID,
		ev.FromStableID,
	} {
		eventNames = append(eventNames, formatChatTargetNames(value)...)
	}
	return formatChatTargetListsOverlap(targetNames, eventNames)
}

func pendingParticipantLabel(p chat.PendingConversation, idx int) string {
	alias := ""
	if idx < len(p.Participants) {
		alias = strings.TrimSpace(p.Participants[idx])
	}
	address := ""
	if idx < len(p.ParticipantAddresses) {
		address = strings.TrimSpace(p.ParticipantAddresses[idx])
	}
	did := ""
	if idx < len(p.ParticipantDIDs) {
		did = strings.TrimSpace(p.ParticipantDIDs[idx])
	}
	return preferredIdentityDisplayLabel(alias, address, "", did, "")
}

func pendingParticipantCount(p chat.PendingConversation) int {
	count := len(p.Participants)
	if len(p.ParticipantAddresses) > count {
		count = len(p.ParticipantAddresses)
	}
	if len(p.ParticipantDIDs) > count {
		count = len(p.ParticipantDIDs)
	}
	return count
}

func pendingIdentityStrength(address string, stableID string, did string, alias string) int {
	if strings.TrimSpace(address) != "" {
		return 4
	}
	if strings.TrimSpace(stableID) != "" {
		return 3
	}
	did = strings.TrimSpace(did)
	if did != "" {
		if strings.HasPrefix(did, "did:aw:") {
			return 3
		}
		return 2
	}
	if strings.TrimSpace(alias) != "" {
		return 1
	}
	return 0
}

func preferredPendingSenderLabel(p chat.PendingConversation, selfAlias string, selfDIDs ...string) string {
	lastFrom := preferredIdentityDisplayLabel(
		strings.TrimSpace(p.LastFrom),
		strings.TrimSpace(p.LastFromAddress),
		strings.TrimSpace(p.LastFromStableID),
		strings.TrimSpace(p.LastFromDID),
		"",
	)
	lastFromStrength := pendingIdentityStrength(
		p.LastFromAddress,
		p.LastFromStableID,
		p.LastFromDID,
		p.LastFrom,
	)

	count := pendingParticipantCount(p)

	candidate := ""
	candidateStrength := 0
	for idx := 0; idx < count; idx++ {
		alias := ""
		if idx < len(p.Participants) {
			alias = strings.TrimSpace(p.Participants[idx])
		}
		address := ""
		if idx < len(p.ParticipantAddresses) {
			address = strings.TrimSpace(p.ParticipantAddresses[idx])
		}
		did := ""
		if idx < len(p.ParticipantDIDs) {
			did = strings.TrimSpace(p.ParticipantDIDs[idx])
		}
		participant := pendingParticipantLabel(p, idx)
		if participant == "" || notifyIdentityMatchesSelf(participant, selfAlias, selfDIDs...) {
			continue
		}
		if candidate != "" && !strings.EqualFold(candidate, participant) {
			return lastFrom
		}
		candidate = participant
		candidateStrength = pendingIdentityStrength(address, "", did, alias)
	}
	if candidate != "" && candidateStrength > lastFromStrength {
		return candidate
	}
	return lastFrom
}

func pendingOpenTarget(p chat.PendingConversation) string {
	if pendingParticipantCount(p) != 1 {
		return ""
	}
	if len(p.ParticipantAddresses) == 1 && strings.TrimSpace(p.ParticipantAddresses[0]) != "" {
		return strings.TrimSpace(p.ParticipantAddresses[0])
	}
	if len(p.ParticipantDIDs) == 1 && strings.TrimSpace(p.ParticipantDIDs[0]) != "" {
		return strings.TrimSpace(p.ParticipantDIDs[0])
	}
	if len(p.Participants) == 1 {
		return strings.TrimSpace(p.Participants[0])
	}
	return ""
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
		displayFrom := preferredPendingSenderLabel(p, "")
		openTarget := pendingOpenTarget(p)
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
