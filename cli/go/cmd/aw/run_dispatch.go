package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
	awrun "github.com/awebai/aw/run"
)

type runWakeResolution struct {
	Skip         bool
	CycleContext string
}

type runWakeResolver func(context.Context, awid.AgentEvent) (runWakeResolution, error)

type runDispatcher struct {
	workPromptSuffix  string
	commsPromptSuffix string
	resolveWake       runWakeResolver
}

func newRunDispatcher(settings awrun.Settings, resolveWake runWakeResolver) awrun.Dispatcher {
	return runDispatcher{
		workPromptSuffix:  strings.TrimSpace(settings.WorkPromptSuffix),
		commsPromptSuffix: strings.TrimSpace(settings.CommsPromptSuffix),
		resolveWake:       resolveWake,
	}
}

func (d runDispatcher) Next(ctx context.Context, autofeed bool, wakeEvent *awid.AgentEvent) (awrun.DispatchDecision, error) {
	if wakeEvent == nil {
		return awrun.DispatchDecision{Skip: true}, nil
	}

	switch wakeEvent.Type {
	case awid.AgentEventActionableMail, awid.AgentEventActionableChat:
		resolved := runWakeResolution{
			CycleContext: formatFallbackCommsContext(*wakeEvent),
		}
		if d.resolveWake != nil {
			var err error
			resolved, err = d.resolveWake(ctx, *wakeEvent)
			if err != nil {
				return awrun.DispatchDecision{}, err
			}
		}
		if resolved.Skip {
			return awrun.DispatchDecision{Skip: true, WaitSeconds: awrun.DefaultWaitSeconds}, nil
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(resolved.CycleContext, d.commsPromptSuffix),
			DisplayLines: awrun.SplitDisplayText(awrun.DisplayKindCommunication, strings.TrimSpace(resolved.CycleContext)),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
		if !autofeed {
			return awrun.DispatchDecision{Skip: true}, nil
		}
		return awrun.DispatchDecision{
			CycleContext: joinPromptSections(formatWorkWakePrompt(*wakeEvent), d.workPromptSuffix),
			DisplayLines: formatWorkWakeDisplay(*wakeEvent),
			WaitSeconds:  awrun.DefaultWaitSeconds,
		}, nil
	default:
		return awrun.DispatchDecision{Skip: true}, nil
	}
}

func newRunWakeValidator(client *aweb.Client, selfAlias string) runWakeResolver {
	if client == nil || client.Client == nil {
		return nil
	}
	selfAlias = strings.TrimSpace(selfAlias)
	return func(ctx context.Context, evt awid.AgentEvent) (runWakeResolution, error) {
		switch evt.Type {
		case awid.AgentEventActionableChat:
			return resolveChatWakeForAlias(ctx, client, selfAlias, evt)
		case awid.AgentEventActionableMail:
			return resolveMailWakeForAlias(ctx, client, selfAlias, evt)
		case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
			return runWakeResolution{CycleContext: formatWorkWakePrompt(evt)}, nil
		default:
			return runWakeResolution{}, nil
		}
	}
}

func resolveChatWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (runWakeResolution, error) {
	selfAlias := ""
	if client != nil && client.Client != nil {
		selfAlias = handleFromAddress(client.Address())
	}
	return resolveChatWakeForAlias(ctx, client, selfAlias, evt)
}

func resolveMailWake(ctx context.Context, client *aweb.Client, evt awid.AgentEvent) (runWakeResolution, error) {
	selfAlias := ""
	if client != nil && client.Client != nil {
		selfAlias = handleFromAddress(client.Address())
	}
	return resolveMailWakeForAlias(ctx, client, selfAlias, evt)
}

func resolveChatWakeForAlias(ctx context.Context, client *aweb.Client, selfAlias string, evt awid.AgentEvent) (runWakeResolution, error) {
	sessionID := strings.TrimSpace(evt.SessionID)
	if sessionID == "" {
		return runWakeResolution{CycleContext: formatFallbackCommsContext(evt)}, nil
	}
	messageID := strings.TrimSpace(evt.MessageID)
	if messageID != "" {
		limit := evt.UnreadCount
		if limit <= 0 {
			limit = 20
		} else if limit > 100 {
			limit = 100
		}
		history, err := client.ChatHistory(ctx, awid.ChatHistoryParams{
			SessionID:  sessionID,
			UnreadOnly: true,
			Limit:      limit,
		})
		if err == nil {
			filtered := chat.FilterDeliveredMessages(history.Messages)
			if ids := chat.DeliveredMessageIDs(history.Messages); len(ids) > 0 {
				_ = chat.SaveDeliveredIDs(ids)
			}
			markChatHistoryRead(ctx, client, sessionID, history.Messages)
			for _, msg := range filtered {
				if strings.TrimSpace(msg.MessageID) != messageID {
					continue
				}
				if chatMessageFromSelf(msg, selfAlias, selfIdentityDIDs(client)...) {
					return runWakeResolution{Skip: true}, nil
				}
				return runWakeResolution{
					CycleContext: formatIncomingChatContext(
						preferredWakeIdentityLabel(
							strings.TrimSpace(msg.FromAgent),
							strings.TrimSpace(msg.FromAddress),
							strings.TrimSpace(msg.FromStableID),
							strings.TrimSpace(msg.FromDID),
							preferredWakeIdentityLabel(
								strings.TrimSpace(evt.FromAlias),
								strings.TrimSpace(evt.FromAddress),
								strings.TrimSpace(evt.FromStableID),
								strings.TrimSpace(evt.FromDID),
								"",
							),
						),
						msg.Body,
					),
				}, nil
			}
			if len(history.Messages) > 0 && len(filtered) == 0 {
				return runWakeResolution{Skip: true}, nil
			}
		}
	}
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return runWakeResolution{}, fmt.Errorf("check pending chat for wake %s: %w", sessionID, err)
	}
	for _, pending := range resp.Pending {
		if strings.TrimSpace(pending.SessionID) != sessionID {
			continue
		}
		alias := strings.TrimSpace(evt.FromAlias)
		if alias == "" {
			alias = strings.TrimSpace(pending.LastFrom)
		}
		// Mark as read — fetch unread history to find the last message ID.
		histResp, _ := client.ChatHistory(ctx, awid.ChatHistoryParams{
			SessionID:  sessionID,
			UnreadOnly: true,
			Limit:      100,
		})
		if histResp != nil {
			filtered := chat.FilterDeliveredMessages(histResp.Messages)
			if ids := chat.DeliveredMessageIDs(histResp.Messages); len(ids) > 0 {
				_ = chat.SaveDeliveredIDs(ids)
			}
			markChatHistoryRead(ctx, client, sessionID, histResp.Messages)
			if latest := latestIncomingChatMessage(filtered, selfAlias, selfIdentityDIDs(client)...); latest != nil {
				return runWakeResolution{
					CycleContext: formatIncomingChatContext(
						preferredWakeIdentityLabel(
							strings.TrimSpace(latest.FromAgent),
							strings.TrimSpace(latest.FromAddress),
							strings.TrimSpace(latest.FromStableID),
							strings.TrimSpace(latest.FromDID),
							preferredWakeIdentityLabel(
								strings.TrimSpace(evt.FromAlias),
								strings.TrimSpace(evt.FromAddress),
								strings.TrimSpace(evt.FromStableID),
								strings.TrimSpace(evt.FromDID),
								"",
							),
						),
						latest.Body,
					),
				}, nil
			}
			if len(histResp.Messages) > 0 {
				return runWakeResolution{Skip: true}, nil
			}
		}
		displayFromAddress := strings.TrimSpace(pending.LastFromAddress)
		if displayFromAddress == "" {
			displayFromAddress = strings.TrimSpace(evt.FromAddress)
		}
		displayFromStableID := strings.TrimSpace(pending.LastFromStableID)
		if displayFromStableID == "" {
			displayFromStableID = strings.TrimSpace(evt.FromStableID)
		}
		displayFromDID := strings.TrimSpace(pending.LastFromDID)
		if displayFromDID == "" {
			displayFromDID = strings.TrimSpace(evt.FromDID)
		}
		derivedPending := pending
		derivedPending.LastFrom = alias
		derivedPending.LastFromStableID = displayFromStableID
		derivedPending.LastFromDID = displayFromDID
		derivedPending.LastFromAddress = displayFromAddress
		if pendingChatSenderFromSelf(derivedPending, selfAlias, client.Address(), selfIdentityDIDs(client)...) {
			return runWakeResolution{Skip: true}, nil
		}
		displayFrom := preferredPendingSenderLabel(chat.PendingConversation{
			Participants:         pending.Participants,
			ParticipantDIDs:      pending.ParticipantDIDs,
			ParticipantAddresses: pending.ParticipantAddresses,
			LastFrom:             alias,
			LastFromStableID:     displayFromStableID,
			LastFromDID:          displayFromDID,
			LastFromAddress:      displayFromAddress,
		}, selfAlias, selfIdentityDIDs(client)...)
		return runWakeResolution{
			CycleContext: formatIncomingChatContext(
				displayFrom,
				pending.LastMessage,
			),
		}, nil
	}
	return runWakeResolution{Skip: true}, nil
}

func selfIdentityDIDs(client *aweb.Client) []string {
	if client == nil || client.Client == nil {
		return nil
	}
	dids := []string{}
	for _, value := range []string{client.StableID(), client.DID()} {
		value = strings.TrimSpace(value)
		if value != "" && !slices.Contains(dids, value) {
			dids = append(dids, value)
		}
	}
	return dids
}

func pendingIdentityCount(pending awid.ChatPendingItem) int {
	count := len(pending.Participants)
	if len(pending.ParticipantAddresses) > count {
		count = len(pending.ParticipantAddresses)
	}
	if len(pending.ParticipantDIDs) > count {
		count = len(pending.ParticipantDIDs)
	}
	return count
}

func pendingStableAlias(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "did:aw:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "did:aw:"))
}

func pendingIdentityByAlias(pending awid.ChatPendingItem, alias string) (address, stableID, did string) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "", "", ""
	}
	matches := 0
	for idx := 0; idx < pendingIdentityCount(pending); idx++ {
		participantAlias := ""
		if idx < len(pending.Participants) {
			participantAlias = strings.TrimSpace(pending.Participants[idx])
		}
		participantAddress := ""
		if idx < len(pending.ParticipantAddresses) {
			participantAddress = strings.TrimSpace(pending.ParticipantAddresses[idx])
		}
		participantDID := ""
		if idx < len(pending.ParticipantDIDs) {
			participantDID = strings.TrimSpace(pending.ParticipantDIDs[idx])
		}
		if !strings.EqualFold(participantAlias, alias) &&
			!strings.EqualFold(handleFromAddress(participantAddress), alias) &&
			!strings.EqualFold(pendingStableAlias(participantDID), alias) {
			continue
		}
		matches++
		if matches > 1 {
			return "", "", ""
		}
		address = participantAddress
		if strings.HasPrefix(participantDID, "did:aw:") {
			stableID = participantDID
			did = ""
		} else {
			stableID = ""
			did = participantDID
		}
	}
	return address, stableID, did
}

func chatMessageFromSelf(msg awid.ChatMessage, selfAlias string, selfDIDs ...string) bool {
	return identityMatchesSelf(
		strings.TrimSpace(msg.FromAgent),
		strings.TrimSpace(msg.FromAddress),
		strings.TrimSpace(msg.FromStableID),
		strings.TrimSpace(msg.FromDID),
		selfAlias,
		selfDIDs...,
	)
}

func pendingChatSenderFromSelf(pending awid.ChatPendingItem, selfAlias string, selfAddress string, selfDIDs ...string) bool {
	mappedAddress, mappedStableID, mappedDID := pendingIdentityByAlias(pending, pending.LastFrom)
	lastFromStableID := strings.TrimSpace(pending.LastFromStableID)
	if lastFromStableID == "" {
		lastFromStableID = mappedStableID
	}
	if lastFromStableID != "" {
		for _, selfDID := range selfDIDs {
			if selfDID != "" && strings.EqualFold(lastFromStableID, selfDID) {
				return true
			}
		}
		return false
	}
	lastFromDID := strings.TrimSpace(pending.LastFromDID)
	if lastFromDID == "" {
		lastFromDID = mappedDID
	}
	if lastFromDID != "" {
		for _, selfDID := range selfDIDs {
			if selfDID != "" && strings.EqualFold(lastFromDID, selfDID) {
				return true
			}
		}
		return false
	}
	lastFromAddress := strings.TrimSpace(pending.LastFromAddress)
	if lastFromAddress == "" {
		lastFromAddress = mappedAddress
	}
	if lastFromAddress != "" {
		selfAddress = strings.TrimSpace(selfAddress)
		if selfAddress != "" {
			return strings.EqualFold(lastFromAddress, selfAddress)
		}
		selfAlias = strings.TrimSpace(selfAlias)
		if selfAlias != "" && len(selfDIDs) == 0 {
			return strings.EqualFold(handleFromAddress(lastFromAddress), selfAlias)
		}
		return false
	}
	if len(selfDIDs) > 0 {
		return false
	}
	return strings.TrimSpace(selfAlias) != "" && strings.EqualFold(strings.TrimSpace(pending.LastFrom), strings.TrimSpace(selfAlias))
}

func identityMatchesSelf(alias, address, stableID, did, selfAlias string, selfDIDs ...string) bool {
	hasIdentity := stableID != "" || did != ""
	for _, selfDID := range selfDIDs {
		if selfDID != "" && (strings.EqualFold(stableID, selfDID) || strings.EqualFold(did, selfDID)) {
			return true
		}
	}
	if len(selfDIDs) > 0 && hasIdentity {
		return false
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(handleFromAddress(address), selfAlias) {
		return true
	}
	return strings.EqualFold(alias, selfAlias)
}

func latestIncomingChatMessage(messages []awid.ChatMessage, selfAlias string, selfDIDs ...string) *awid.ChatMessage {
	for i := len(messages) - 1; i >= 0; i-- {
		if chatMessageFromSelf(messages[i], selfAlias, selfDIDs...) {
			continue
		}
		return &messages[i]
	}
	return nil
}

func preferredSenderLabel(alias string, address string, fallback string) string {
	alias = strings.TrimSpace(alias)
	if alias != "" {
		return alias
	}
	address = strings.TrimSpace(address)
	if address != "" {
		return address
	}
	return strings.TrimSpace(fallback)
}

func preferredIdentityLabel(alias string, address string, fallback string) string {
	address = strings.TrimSpace(address)
	if address != "" {
		return address
	}
	return preferredSenderLabel(alias, address, fallback)
}

func preferredWakeIdentityLabel(alias string, address string, stableID string, did string, fallback string) string {
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

func resolveMailWakeForAlias(ctx context.Context, client *aweb.Client, selfAlias string, evt awid.AgentEvent) (runWakeResolution, error) {
	messageID := strings.TrimSpace(evt.MessageID)
	resp, err := client.Inbox(ctx, awid.InboxParams{UnreadOnly: true})
	if err != nil {
		return runWakeResolution{}, fmt.Errorf("check unread mail for wake %s: %w", messageID, err)
	}
	for _, msg := range resp.Messages {
		if messageID != "" && strings.TrimSpace(msg.MessageID) != messageID {
			continue
		}
		if mailMessageFromSelf(msg, selfAlias, selfIdentityDIDs(client)...) {
			if msg.MessageID != "" {
				_, _ = client.AckMessage(ctx, msg.MessageID)
			}
			return runWakeResolution{Skip: true}, nil
		}
		if strings.TrimSpace(msg.FromAlias) == "" &&
			strings.TrimSpace(msg.FromAddress) == "" &&
			strings.TrimSpace(msg.FromStableID) == "" &&
			strings.TrimSpace(msg.FromDID) == "" &&
			identityMatchesSelf(
				strings.TrimSpace(evt.FromAlias),
				strings.TrimSpace(evt.FromAddress),
				strings.TrimSpace(evt.FromStableID),
				strings.TrimSpace(evt.FromDID),
				selfAlias,
				selfIdentityDIDs(client)...,
			) {
			if msg.MessageID != "" {
				_, _ = client.AckMessage(ctx, msg.MessageID)
			}
			return runWakeResolution{Skip: true}, nil
		}
		// Mark as read — seeing the full content means it's read.
		if msg.MessageID != "" {
			_, _ = client.AckMessage(ctx, msg.MessageID)
		}
		return runWakeResolution{
			CycleContext: formatIncomingMailContext(
				preferredWakeIdentityLabel(
					strings.TrimSpace(msg.FromAlias),
					strings.TrimSpace(msg.FromAddress),
					strings.TrimSpace(msg.FromStableID),
					strings.TrimSpace(msg.FromDID),
					preferredWakeIdentityLabel(
						strings.TrimSpace(evt.FromAlias),
						strings.TrimSpace(evt.FromAddress),
						strings.TrimSpace(evt.FromStableID),
						strings.TrimSpace(evt.FromDID),
						"",
					),
				),
				msg.Subject,
				msg.Body,
			),
		}, nil
	}
	if messageID == "" {
		return runWakeResolution{CycleContext: formatFallbackCommsContext(evt)}, nil
	}
	return runWakeResolution{Skip: true}, nil
}

func mailMessageFromSelf(msg awid.InboxMessage, selfAlias string, selfDIDs ...string) bool {
	hasMessageIdentity := strings.TrimSpace(msg.FromStableID) != "" || strings.TrimSpace(msg.FromDID) != ""
	for _, did := range selfDIDs {
		if did != "" && (strings.EqualFold(strings.TrimSpace(msg.FromStableID), did) || strings.EqualFold(strings.TrimSpace(msg.FromDID), did)) {
			return true
		}
	}
	if len(selfDIDs) > 0 && hasMessageIdentity {
		return false
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(handleFromAddress(strings.TrimSpace(msg.FromAddress)), selfAlias) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(msg.FromAlias), selfAlias)
}

func joinPromptSections(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, "\n\n")
}

func formatFallbackCommsContext(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventActionableChat:
		return formatIncomingChatContext(preferredIdentityDisplayLabel(evt.FromAlias, evt.FromAddress, evt.FromStableID, evt.FromDID, ""), "")
	case awid.AgentEventActionableMail:
		return formatIncomingMailContext(preferredIdentityDisplayLabel(evt.FromAlias, evt.FromAddress, evt.FromStableID, evt.FromDID, ""), evt.Subject, "")
	default:
		return ""
	}
}

func formatIncomingChatContext(fromAlias string, body string) string {
	alias := formatWakeAlias(fromAlias)
	body = strings.TrimSpace(body)
	if body == "" {
		return awrun.FormatCommLabel("from", alias, "chat")
	}
	return formatIncomingCommBlock(awrun.FormatCommLabel("from", alias, "chat"), "", body)
}

func formatIncomingMailContext(fromAlias string, subject string, body string) string {
	alias := formatWakeAlias(fromAlias)
	subject = strings.TrimSpace(subject)
	body = strings.TrimSpace(body)
	switch {
	case subject != "" && body != "":
		return formatIncomingMailBlock(awrun.FormatCommLabel("from", alias, "mail"), subject, body)
	case subject != "":
		return fmt.Sprintf("%s: %s", awrun.FormatCommLabel("from", alias, "mail"), subject)
	case body != "":
		return formatIncomingCommBlock(awrun.FormatCommLabel("from", alias, "mail"), "", body)
	default:
		return awrun.FormatCommLabel("from", alias, "mail")
	}
}

func formatIncomingCommBlock(head string, subject string, body string) string {
	lines := commBodyLines(body)
	if len(lines) == 0 {
		if subject == "" {
			return head
		}
		return fmt.Sprintf("%s: %s", head, subject)
	}

	first := lines[0]
	if subject != "" {
		first = subject + " — " + first
	}

	formatted := []string{fmt.Sprintf("%s: %s", head, first)}
	for _, line := range lines[1:] {
		formatted = append(formatted, "   "+line)
	}
	return strings.Join(formatted, "\n")
}

func formatIncomingMailBlock(head string, subject string, body string) string {
	formatted := []string{fmt.Sprintf("%s: %s", head, subject)}
	for _, line := range commBodyLines(body) {
		formatted = append(formatted, "   "+line)
	}
	return strings.Join(formatted, "\n")
}

func markChatHistoryRead(ctx context.Context, client *aweb.Client, sessionID string, messages []awid.ChatMessage) {
	if len(messages) == 0 {
		return
	}
	lastMsgID := messages[len(messages)-1].MessageID
	if lastMsgID != "" {
		req := &awid.ChatMarkReadRequest{UpToMessageID: lastMsgID}
		if _, err := client.ChatMarkRead(ctx, sessionID, req); err == nil {
			return
		}
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		_, _ = client.ChatMarkRead(ctx, sessionID, req)
	}
}

func commBodyLines(body string) []string {
	body = strings.ReplaceAll(strings.TrimSpace(body), "\r", "")
	if body == "" {
		return nil
	}
	lines := strings.Split(body, "\n")
	formatted := make([]string, 0, len(lines))
	for _, line := range lines {
		formatted = append(formatted, strings.TrimRight(line, " "))
	}
	return formatted
}

func formatWorkWakePrompt(evt awid.AgentEvent) string {
	switch evt.Type {
	case awid.AgentEventWorkAvailable:
		return fmt.Sprintf(
			"Wake reason: work is available%s. Check ready work, claim the most appropriate task if needed, and continue the task-oriented cycle.",
			formatWakeTask(evt),
		)
	case awid.AgentEventClaimUpdate:
		status := ""
		if value := strings.TrimSpace(evt.Status); value != "" {
			status = fmt.Sprintf(" Status: %s.", value)
		}
		return fmt.Sprintf(
			"Wake reason: a claim changed%s.%s Review the updated claim state and adjust coordination before continuing.",
			formatWakeTask(evt),
			status,
		)
	case awid.AgentEventClaimRemoved:
		return fmt.Sprintf(
			"Wake reason: a claim was removed%s. Re-check ready work and coordination state before continuing.",
			formatWakeTask(evt),
		)
	default:
		return ""
	}
}

func formatWorkWakeDisplay(evt awid.AgentEvent) []awrun.DisplayLine {
	var text string
	switch evt.Type {
	case awid.AgentEventWorkAvailable:
		text = "● work available" + formatWakeTask(evt)
	case awid.AgentEventClaimUpdate:
		text = "● claim changed" + formatWakeTask(evt)
		if status := strings.TrimSpace(evt.Status); status != "" {
			text += " — " + status
		}
	case awid.AgentEventClaimRemoved:
		text = "● claim removed" + formatWakeTask(evt)
	default:
		return nil
	}
	return awrun.SplitDisplayText(awrun.DisplayKindTaskActivity, text)
}

func formatWakeAlias(alias string) string {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return "another agent"
	}
	return alias
}

func formatWakeTask(evt awid.AgentEvent) string {
	title := strings.TrimSpace(evt.Title)
	taskID := strings.TrimSpace(evt.TaskID)
	switch {
	case title != "" && taskID != "":
		return fmt.Sprintf(": %s (%s)", title, taskID)
	case title != "":
		return fmt.Sprintf(": %s", title)
	case taskID != "":
		return fmt.Sprintf(" (%s)", taskID)
	default:
		return ""
	}
}
