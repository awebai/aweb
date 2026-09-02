package main

import (
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Participant identification shared by the aweb mail delegates: given one
// message and this workspace's selection, which side of it is us and which is
// the correspondent. Both `aw beads-mail` (record §8: a named recipient on
// --reply-to is VERIFIED against the conversation, never used to route it) and
// `aw gc-mail` (design record §6: a reply's "to" is the conversation's
// counterparty, since gc prints reply.To) need exactly this, so it lives once.

func delegateMailMessageSideIdentifiers(alias, address, did, stableID string) []string {
	var identifiers []string
	for _, candidate := range []string{address, alias, did, stableID} {
		if value := strings.TrimSpace(candidate); value != "" {
			identifiers = append(identifiers, value)
		}
	}
	return identifiers
}

func delegateMailSelectionIdentifiers(sel *awconfig.Selection) []string {
	if sel == nil {
		return nil
	}
	return delegateMailMessageSideIdentifiers(sel.Alias, selectionAddress(sel), sel.DID, sel.StableID)
}

func delegateMailIdentifiersOverlap(left, right []string) bool {
	for _, value := range left {
		if delegateMailValueAmong(value, right) {
			return true
		}
	}
	return false
}

// delegateMailCounterpartyIdentifiers identifies the side of the source message
// that is not this workspace. If old or rotated message data cannot identify
// the local side, all non-empty participants remain the conservative fallback;
// an entirely blank legacy row is unverifiable and deliberately fails open.
func delegateMailCounterpartyIdentifiers(msg *awid.InboxMessage, sel *awconfig.Selection) ([]string, bool) {
	if msg == nil {
		return nil, false
	}
	from := delegateMailMessageSideIdentifiers(msg.FromAlias, msg.FromAddress, msg.FromDID, msg.FromStableID)
	to := delegateMailMessageSideIdentifiers(msg.ToAlias, msg.ToAddress, msg.ToDID, msg.ToStableID)
	all := append(append([]string{}, from...), to...)
	if len(all) == 0 {
		return nil, false
	}
	self := delegateMailSelectionIdentifiers(sel)
	fromIsSelf := delegateMailIdentifiersOverlap(from, self)
	toIsSelf := delegateMailIdentifiersOverlap(to, self)
	switch {
	case fromIsSelf && !toIsSelf:
		return to, true
	case toIsSelf && !fromIsSelf:
		return from, true
	case fromIsSelf && toIsSelf:
		return nil, true
	default:
		return all, true
	}
}

func delegateMailReplyToTargetMatches(msg *awid.InboxMessage, sel *awconfig.Selection, target string) (known, matches bool) {
	participants, known := delegateMailCounterpartyIdentifiers(msg, sel)
	if !known {
		return false, true
	}
	// A conversation continuation always routes to the other side. Naming
	// ourselves through an address, alias, or DID would make the disclosure
	// line lie even though our identity is naturally one of the participants.
	if delegateMailValueAmong(target, delegateMailSelectionIdentifiers(sel)) {
		return true, false
	}
	return true, delegateMailValueAmong(target, participants)
}

func delegateMailValueAmong(value string, candidates []string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range candidates {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func delegateMailCounterpartyLabel(msg *awid.InboxMessage, sel *awconfig.Selection) string {
	if participants, known := delegateMailCounterpartyIdentifiers(msg, sel); known {
		for _, candidate := range participants {
			if strings.TrimSpace(candidate) != "" {
				return strings.TrimSpace(candidate)
			}
		}
	}
	return "an unidentified correspondent"
}

// --- comm-log writes --------------------------------------------------------
//
// Both delegates record their traffic in the same workspace comm log and
// interaction log as `aw mail`, so `aw log` shows delegate mail alongside
// everything else. The bodies moved here unchanged when `aw gc-mail` needed
// them.

func delegateMailAppendSendLogs(sel *awconfig.Selection, resp *awid.SendMessageResponse, to, subject, body string) {
	from := preferredIdentityDisplayLabel(
		"",
		selectionAddress(sel),
		strings.TrimSpace(sel.StableID),
		strings.TrimSpace(sel.DID),
		"",
	)
	appendCommLog(defaultLogsDir(), commLogNameForSelection(sel), &CommLogEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Dir:            "send",
		Channel:        "mail",
		MessageID:      resp.MessageID,
		ConversationID: resp.ConversationID,
		From:           from,
		To:             to,
		Subject:        subject,
		Body:           body,
	})
	appendInteractionLogForCWD(&InteractionEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		Kind:           interactionKindMailOut,
		MessageID:      resp.MessageID,
		ConversationID: resp.ConversationID,
		To:             to,
		Subject:        subject,
		Text:           body,
	})
}

func delegateMailLogReceived(sel *awconfig.Selection, msg *awid.InboxMessage) {
	if msg.ReadAt != nil {
		return
	}
	from := preferredIdentityDisplayLabel(msg.FromAlias, msg.FromAddress, msg.FromStableID, msg.FromDID, "")
	to := preferredIdentityDisplayLabel(msg.ToAlias, msg.ToAddress, msg.ToStableID, msg.ToDID, "")
	appendCommLog(defaultLogsDir(), commLogNameForSelection(sel), &CommLogEntry{
		Timestamp:      msg.CreatedAt,
		Dir:            "recv",
		Channel:        "mail",
		MessageID:      msg.MessageID,
		ConversationID: msg.ConversationID,
		From:           from,
		To:             to,
		Subject:        msg.Subject,
		Body:           msg.Body,
	})
}
