// ABOUTME: Chat protocol functions composing low-level aweb-go client methods.
// ABOUTME: Provides Send, Open, History, Pending, Listen, and ShowPending.

package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/identityutil"
)

const DefaultWait = 120 // Default wait timeout in seconds for replies
const maxOpenUnreadMessages = 1000

// maxStreamDeadline is the server-side SSE connection safety net.
// The local waitTimer manages actual wait semantics; this just prevents
// orphaned server connections. Must exceed any possible wait extension chain.
const maxStreamDeadline = 15 * time.Minute

// MaxSendTimeout is the maximum duration a Send() call can take,
// accounting for all possible wait extensions.
const MaxSendTimeout = 16 * time.Minute

func classifyChatTargets(targets []string) (aliases []string, dids []string, addresses []string) {
	for _, target := range targets {
		target = awid.NormalizeHostedHandleAddress(target)
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
		ev.VerificationStatus = awid.Failed
		return ev
	}

	// Decode proof integers independently of the display/event JSON map.
	var proof struct {
		IDChain awid.ReceivedIDChain `json:"id_chain"`
	}
	if err := json.Unmarshal([]byte(sseEvent.Data), &proof); err != nil {
		ev.VerificationStatus = awid.Failed
		return ev
	}
	ev.IDChain = proof.IDChain

	if raw, ok := data["sender_membership"]; ok {
		encoded, err := json.Marshal(raw)
		if err == nil {
			_ = json.Unmarshal(encoded, &ev.SenderMembership)
		}
	}
	ev.Agent = stringField(data, "agent")
	ev.SessionID = stringField(data, "session_id")
	ev.Seq = int64(numberField(data, "seq"))
	ev.MessageID = stringField(data, "message_id")
	if v, ok := data["from_agent"].(string); ok {
		ev.FromAgent = v
	} else {
		ev.FromAgent = stringField(data, "from")
	}
	ev.FromAddress = stringField(data, "from_address")
	ev.ToAddress = stringField(data, "to_address")
	ev.Body = stringField(data, "body")
	ev.ContentMode = stringField(data, "content_mode")
	ev.MessageVersion = int(numberField(data, "message_version"))
	if encryptedData, ok := data["encrypted_envelope"].(map[string]any); ok {
		raw, err := json.Marshal(encryptedData)
		if err == nil {
			var encrypted awid.E2EEMessageEnvelope
			if json.Unmarshal(raw, &encrypted) == nil {
				ev.Encrypted = &encrypted
			}
		}
	}
	ev.By = stringField(data, "by")
	ev.Reason = stringField(data, "reason")
	if ev.Reason == "" {
		ev.Reason = stringField(data, "detail")
	}
	ev.Timestamp = stringField(data, "timestamp")
	ev.SenderLeaving = boolField(data, "sender_leaving")
	ev.SenderWaiting = boolField(data, "sender_waiting")
	ev.ReaderAlias = stringField(data, "reader_alias")
	ev.ExtendWait = boolField(data, "hang_on")
	ev.ExtendsWaitSeconds = int(numberField(data, "extends_wait_seconds"))
	ev.ReplyToMessageID = stringField(data, "reply_to_message_id")
	ev.FromDID = stringField(data, "from_did")
	ev.ToDID = stringField(data, "to_did")
	ev.FromStableID = stringField(data, "from_stable_id")
	ev.ToStableID = stringField(data, "to_stable_id")
	ev.Signature = stringField(data, "signature")
	ev.SigningKeyID = stringField(data, "signing_key_id")
	ev.SignedPayload = stringField(data, "signed_payload")
	if v, ok := data["is_contact"].(bool); ok {
		ev.IsContact = &v
	}
	if announcement, ok := data["rotation_announcement"].(map[string]any); ok {
		ev.RotationAnnouncement = &awid.RotationAnnouncement{
			OldDID:          stringField(announcement, "old_did"),
			NewDID:          stringField(announcement, "new_did"),
			Timestamp:       stringField(announcement, "timestamp"),
			OldKeySignature: stringField(announcement, "old_key_signature"),
		}
	}
	if announcement, ok := data["replacement_announcement"].(map[string]any); ok {
		ev.ReplacementAnnouncement = &awid.ReplacementAnnouncement{
			Address:             stringField(announcement, "address"),
			OldDID:              stringField(announcement, "old_did"),
			NewDID:              stringField(announcement, "new_did"),
			ControllerDID:       stringField(announcement, "controller_did"),
			Timestamp:           stringField(announcement, "timestamp"),
			ControllerSignature: stringField(announcement, "controller_signature"),
		}
	}

	return ev
}

// stringField, numberField and boolField read one SSE event field leniently:
// a missing field or one of another JSON type reads as the zero value, so one
// malformed field does not discard the rest of the event.
func stringField(data map[string]any, key string) string {
	v, _ := data[key].(string)
	return v
}

func numberField(data map[string]any, key string) float64 {
	v, _ := data[key].(float64)
	return v
}

func boolField(data map[string]any, key string) bool {
	v, _ := data[key].(bool)
	return v
}

// verifyStreamMessage verifies a message received on the live stream with the
// same rule chat history uses (awid.Client.VerifyReceivedChatMessage), as
// read from the conversation sessionID. An
// event whose row could not be decoded keeps its Failed status.
func verifyStreamMessage(ctx context.Context, client *awid.Client, sessionID string, ev *Event, participants []awid.ChatParticipant) error {
	if ev.VerificationStatus == awid.Failed {
		return nil
	}
	m := awid.ChatMessage{
		IDChain:                 ev.IDChain,
		SenderMembership:        ev.SenderMembership,
		MessageID:               ev.MessageID,
		ConversationID:          ev.SessionID,
		FromAgent:               ev.FromAgent,
		FromAddress:             ev.FromAddress,
		ToAddress:               ev.ToAddress,
		Body:                    ev.Body,
		ContentMode:             ev.ContentMode,
		MessageVersion:          ev.MessageVersion,
		Encrypted:               ev.Encrypted,
		Timestamp:               ev.Timestamp,
		SenderLeaving:           ev.SenderLeaving,
		ReplyToMessageID:        ev.ReplyToMessageID,
		FromDID:                 ev.FromDID,
		ToDID:                   ev.ToDID,
		FromStableID:            ev.FromStableID,
		ToStableID:              ev.ToStableID,
		Signature:               ev.Signature,
		SigningKeyID:            ev.SigningKeyID,
		SignedPayload:           ev.SignedPayload,
		RotationAnnouncement:    ev.RotationAnnouncement,
		ReplacementAnnouncement: ev.ReplacementAnnouncement,
		IsContact:               ev.IsContact,
	}
	if err := client.VerifyReceivedChatMessage(ctx, &m, sessionID, chatEventTrustAddress(*ev, participants)); err != nil {
		return err
	}
	ev.FromDID, ev.ToDID = m.FromDID, m.ToDID
	ev.FromStableID, ev.ToStableID = m.FromStableID, m.ToStableID
	ev.FromAddress, ev.ToAddress = m.FromAddress, m.ToAddress
	ev.Body = m.Body
	ev.Attachments, ev.AttachmentsAvailable = m.Attachments, m.AttachmentsAvailable
	ev.VerificationStatus, ev.IsContact = m.VerificationStatus, m.IsContact
	return nil
}

func addressHandle(value string) string {
	return identityutil.HandleFromAddress(value)
}

func stableAlias(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "did:aw:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "did:aw:"))
}

type chatParticipantRow struct {
	Alias    string
	Address  string
	DID      string
	StableID string
}

func newChatParticipantRow(alias string, address string, did string) chatParticipantRow {
	row := chatParticipantRow{
		Alias:   strings.TrimSpace(alias),
		Address: strings.TrimSpace(address),
		DID:     strings.TrimSpace(did),
	}
	if strings.HasPrefix(row.DID, "did:aw:") {
		row.StableID = row.DID
	}
	return row
}

func chatParticipantRows(participants []string, participantDIDs []string, participantAddresses []string) []chatParticipantRow {
	maxLen := len(participants)
	if len(participantDIDs) > maxLen {
		maxLen = len(participantDIDs)
	}
	if len(participantAddresses) > maxLen {
		maxLen = len(participantAddresses)
	}
	rows := make([]chatParticipantRow, 0, maxLen)
	for i := 0; i < maxLen; i++ {
		alias := ""
		if i < len(participants) {
			alias = participants[i]
		}
		address := ""
		if i < len(participantAddresses) {
			address = participantAddresses[i]
		}
		did := ""
		if i < len(participantDIDs) {
			did = participantDIDs[i]
		}
		rows = append(rows, newChatParticipantRow(alias, address, did))
	}
	return rows
}

func chatParticipantRowFromParticipant(participant awid.ChatParticipant) chatParticipantRow {
	return newChatParticipantRow(participant.Alias, participant.Address, participant.DID)
}

func (row chatParticipantRow) identityValues() []string {
	return []string{row.Alias, row.Address, row.DID}
}

func (row chatParticipantRow) matchesTarget(target string) bool {
	for _, candidate := range row.identityValues() {
		if chatIdentityMatches(candidate, target, handlesEitherWay) {
			return true
		}
	}
	return false
}

func (row chatParticipantRow) matchesSessionTarget(target string) bool {
	for _, candidate := range row.identityValues() {
		if chatIdentityMatches(candidate, target, candidateHandleForBareTarget) {
			return true
		}
	}
	return false
}

func (row chatParticipantRow) matchesStrongIdentity(kind string, target string) bool {
	switch kind {
	case "address":
		return chatIdentityMatches(row.Address, target, handlesEitherWay)
	case "did":
		return chatIdentityMatches(row.DID, target, handlesEitherWay)
	default:
		return false
	}
}

func (row chatParticipantRow) concreteIdentityKey() string {
	if row.StableID != "" {
		return row.StableID
	}
	if row.DID != "" {
		return row.DID
	}
	return row.Address
}

func (row chatParticipantRow) label() string {
	if row.Address != "" {
		return row.Address
	}
	if row.StableID != "" {
		return row.StableID
	}
	if row.DID != "" {
		return row.DID
	}
	return row.Alias
}

func preferredChatIdentityLabel(alias string, address string, stableID string, did string) string {
	row := newChatParticipantRow(alias, address, did)
	if stableID = strings.TrimSpace(stableID); stableID != "" {
		row.StableID = stableID
	}
	return row.label()
}

// handleMatching is when an address's handle (its name after the domain)
// may stand in for an identity value.
type handleMatching int

const (
	// handlesEitherWay: a handle on either side matches the other value.
	handlesEitherWay handleMatching = iota
	// candidateHandleForBareTarget: only a candidate address's handle
	// matches, and only a bare target name; a DID or address target matches
	// only exactly (session lookup).
	candidateHandleForBareTarget
)

// chatIdentityMatches is the one comparison of a participant identity value
// with a target: equal ignoring case, through a stable alias, or through an
// address handle as handles allows (chat/IDENTITY_RULES.md).
func chatIdentityMatches(candidate string, target string, handles handleMatching) bool {
	candidate = strings.TrimSpace(candidate)
	target = strings.TrimSpace(target)
	if candidate == "" || target == "" {
		return false
	}
	if strings.EqualFold(candidate, target) {
		return true
	}
	if alias := stableAlias(candidate); alias != "" && strings.EqualFold(alias, target) {
		return true
	}
	if alias := stableAlias(target); alias != "" && strings.EqualFold(alias, candidate) {
		return true
	}
	if handles == candidateHandleForBareTarget {
		if strings.HasPrefix(target, "did:") || strings.Contains(target, "/") {
			return false
		}
		handle := addressHandle(candidate)
		return handle != "" && strings.EqualFold(handle, target)
	}
	if handle := addressHandle(candidate); handle != "" && strings.EqualFold(handle, target) {
		return true
	}
	if handle := addressHandle(target); handle != "" && strings.EqualFold(handle, candidate) {
		return true
	}
	return false
}

func exactParticipantMatch(participants []string, participantDIDs []string, participantAddresses []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, row := range chatParticipantRows(participants, participantDIDs, participantAddresses) {
		if row.matchesSessionTarget(target) {
			return true
		}
	}
	return false
}

func participantIdentityCount(participants []string, participantDIDs []string, participantAddresses []string) int {
	return len(chatParticipantRows(participants, participantDIDs, participantAddresses))
}

func pendingParticipantIdentityByLastFrom(participants []string, participantDIDs []string, participantAddresses []string, lastFrom string) (address, stableID, did string) {
	lastFrom = strings.TrimSpace(lastFrom)
	if lastFrom == "" {
		return "", "", ""
	}
	matchAddress := ""
	matchStableID := ""
	matchDID := ""
	matches := 0
	for _, row := range chatParticipantRows(participants, participantDIDs, participantAddresses) {
		if !row.matchesSessionTarget(lastFrom) {
			continue
		}
		matches++
		if matches > 1 {
			return "", "", ""
		}
		matchAddress = row.Address
		if row.StableID != "" {
			matchStableID = row.StableID
			matchDID = ""
		} else {
			matchStableID = ""
			matchDID = row.DID
		}
	}
	return matchAddress, matchStableID, matchDID
}

func unanimousChatRowValue(rows []chatParticipantRow, pick func(chatParticipantRow) string) string {
	candidate := ""
	for _, row := range rows {
		value := strings.TrimSpace(pick(row))
		if value == "" {
			continue
		}
		if candidate != "" && !strings.EqualFold(candidate, value) {
			return ""
		}
		candidate = value
	}
	return candidate
}

func unanimousPendingParticipantIdentity(participants []string, participantDIDs []string, participantAddresses []string) (address, stableID, did string) {
	rows := chatParticipantRows(participants, participantDIDs, participantAddresses)
	address = unanimousChatRowValue(rows, func(row chatParticipantRow) string { return row.Address })
	stableID = unanimousChatRowValue(rows, func(row chatParticipantRow) string { return row.StableID })
	if stableID == "" {
		did = unanimousChatRowValue(rows, func(row chatParticipantRow) string {
			if row.StableID != "" {
				return ""
			}
			return row.DID
		})
	}
	return address, stableID, did
}

func matchedParticipantIdentityKeys(participants []string, participantDIDs []string, participantAddresses []string, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	keys := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range keys {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		keys = append(keys, value)
	}
	for _, row := range chatParticipantRows(participants, participantDIDs, participantAddresses) {
		if !row.matchesSessionTarget(target) {
			continue
		}
		if key := row.concreteIdentityKey(); key != "" {
			appendUnique(key)
		}
	}
	return keys
}

func normalizeMatchedIdentityKeys(ctx context.Context, client *awid.Client, keys []string) []string {
	if len(keys) == 0 || client == nil {
		return keys
	}
	normalized := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range normalized {
			if strings.EqualFold(existing, value) {
				return
			}
		}
		normalized = append(normalized, value)
	}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if identity, err := client.ResolveIdentity(ctx, key); err == nil && identity != nil {
			if stableID := strings.TrimSpace(identity.StableID); stableID != "" {
				appendUnique(stableID)
				continue
			}
			if did := strings.TrimSpace(identity.DID); did != "" {
				appendUnique(did)
				continue
			}
		}
		appendUnique(key)
	}
	return normalized
}

func uniqueHandleParticipantMatch(participants []string, _ []string, _ []string, target string) bool {
	handle := addressHandle(target)
	if handle == "" {
		return false
	}
	for _, participant := range participants {
		if strings.EqualFold(strings.TrimSpace(participant), handle) {
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
	if did := strings.TrimSpace(identity.DID); did != "" {
		return did
	}
	return target
}

func sessionActivity(session awid.ChatSessionItem) string {
	if strings.TrimSpace(session.LastActivity) != "" {
		return session.LastActivity
	}
	return session.CreatedAt
}

// lookupSession is the one session lookup every chat command uses
// (IDENTITY_RULES.md): a DID the caller confirmed for target is a strong
// identity and selects alone; otherwise target is matched as given, a bare
// alias only when it names exactly one participant.
func lookupSession(ctx context.Context, client *awid.Client, target, confirmedDID string, choice sessionChoice) (sessionID string, senderWaiting bool, err error) {
	if did := strings.TrimSpace(confirmedDID); did != "" {
		return findSessionByConfirmedDID(ctx, client, did, choice)
	}
	return findSessionWithOptions(ctx, client, target, choice)
}

// sessionChoice is how a lookup chooses among sessions that match its target.
type sessionChoice int

const (
	// latestSession picks the most recently active matching session.
	latestSession sessionChoice = iota
	// waitingSessionFirst prefers a session whose other party is waiting.
	waitingSessionFirst
)

// findSessionWithOptions finds the session ID for a conversation with targetAlias.
// Checks pending first (captures sender_waiting), falls back to listing sessions;
// choice sets the pending priority below (waitingSessionFirst) or takes the
// latest session (latestSession).
//
// Selection priority for pending sessions:
//  1. sender_waiting sessions over non-waiting (urgent conversations first)
//  2. smallest participant count (1:1 over group)
//  3. most recent LastActivity (tiebreaker)
//
// Selection priority for fallback (all sessions):
//  1. smallest participant count
//  2. most recent LastActivity, falling back to CreatedAt (tiebreaker)
func findSessionWithOptions(ctx context.Context, client *awid.Client, targetAlias string, choice sessionChoice) (sessionID string, senderWaiting bool, err error) {
	rawTarget := strings.TrimSpace(targetAlias)
	targetAlias = normalizeSessionTarget(ctx, client, rawTarget)
	bareAliasTarget := rawTarget != "" &&
		!strings.HasPrefix(rawTarget, "did:") &&
		!strings.Contains(rawTarget, "/") &&
		!strings.Contains(rawTarget, "~")
	currentTeamID := ""
	if client != nil {
		currentTeamID = client.TeamID()
	}
	requireUniqueExact := strings.HasPrefix(rawTarget, "did:") &&
		targetAlias != "" &&
		targetAlias != rawTarget &&
		!strings.Contains(targetAlias, "/")
	requireUniqueConcreteAlias := bareAliasTarget
	// Session selection needs routing metadata, not decrypted previews from
	// every pending conversation (including unrelated ones).
	var pendingResp awid.ChatPendingResponse
	if err := client.Get(ctx, "/v1/chat/pending", &pendingResp); err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}
	matchesSelectedTeam := func(itemTeamID string) bool {
		if !bareAliasTarget || currentTeamID == "" || strings.TrimSpace(itemTeamID) == "" {
			return true
		}
		return strings.EqualFold(strings.TrimSpace(itemTeamID), currentTeamID)
	}
	if requireUniqueConcreteAlias {
		// A bare alias must name one concrete participant across every
		// conversation, pending or not, before any of them is chosen.
		sessionsResp, err := client.ChatListSessions(ctx)
		if err != nil {
			return "", false, fmt.Errorf("listing chat sessions: %w", err)
		}
		identityKeys := []string{}
		appendKeys := func(participants, participantDIDs, participantAddresses []string) {
			identityKeys = appendUniqueFold(identityKeys, matchedParticipantIdentityKeys(participants, participantDIDs, participantAddresses, targetAlias)...)
		}
		for _, p := range pendingResp.Pending {
			if matchesSelectedTeam(p.TeamID) {
				appendKeys(p.Participants, p.ParticipantDIDs, p.ParticipantAddresses)
			}
		}
		for _, item := range sessionsResp.Sessions {
			if matchesSelectedTeam(item.TeamID) {
				appendKeys(item.Participants, item.ParticipantDIDs, item.ParticipantAddresses)
			}
		}
		if len(identityKeys) > 1 {
			identityKeys = normalizeMatchedIdentityKeys(ctx, client, identityKeys)
		}
		if len(identityKeys) > 1 {
			return "", false, ambiguousConversation(targetAlias)
		}
	}

	selectAmong := func(candidates []sessionCandidate, rule candidateRule) (sessionCandidate, error) {
		var best sessionCandidate
		matchCount := 0
		identityKeys := []string{}
		for _, candidate := range candidates {
			if !matchesSelectedTeam(candidate.teamID) || !rule.match(candidate.participants, candidate.participantDIDs, candidate.participantAddresses, targetAlias) {
				continue
			}
			matchCount++
			if rule.trackIdentity {
				identityKeys = appendUniqueFold(identityKeys, matchedParticipantIdentityKeys(candidate.participants, candidate.participantDIDs, candidate.participantAddresses, targetAlias)...)
			}
			if candidate.betterThan(best, choice) {
				best = candidate
			}
		}
		if rule.requireUnique && matchCount > 1 {
			if rule.trackIdentity && len(identityKeys) > 1 {
				identityKeys = normalizeMatchedIdentityKeys(ctx, client, identityKeys)
			}
			if !(rule.trackIdentity && len(identityKeys) == 1) {
				return sessionCandidate{}, ambiguousConversation(targetAlias)
			}
		}
		if requireUniqueConcreteAlias && rule.trackIdentity && len(identityKeys) > 1 {
			identityKeys = normalizeMatchedIdentityKeys(ctx, client, identityKeys)
		}
		if requireUniqueConcreteAlias && rule.trackIdentity && len(identityKeys) > 1 {
			return sessionCandidate{}, ambiguousConversation(targetAlias)
		}
		return best, nil
	}
	rules := []candidateRule{{match: exactParticipantMatch, requireUnique: requireUniqueExact, trackIdentity: true}}
	if bareAliasTarget {
		rules = append(rules, candidateRule{match: uniqueHandleParticipantMatch, requireUnique: true})
	}
	pending := pendingCandidates(pendingResp.Pending)
	for _, rule := range rules {
		best, err := selectAmong(pending, rule)
		if err != nil {
			return "", false, err
		}
		if best.sessionID != "" {
			return best.sessionID, best.senderWaiting, nil
		}
	}

	// Fallback to listing all sessions.
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	listed := listedCandidates(sessionsResp.Sessions)
	for _, rule := range rules {
		best, err := selectAmong(listed, rule)
		if err != nil {
			return "", false, err
		}
		if best.sessionID != "" {
			return best.sessionID, false, nil
		}
	}

	return "", false, fmt.Errorf("no conversation found with %s", targetAlias)
}

// ErrAmbiguousConversation says a target matches more than one conversation
// and the caller must choose.
var ErrAmbiguousConversation = errors.New("multiple conversations match")

func ambiguousConversation(target string) error {
	return fmt.Errorf("%w %s; run `aw chat pending` to choose one", ErrAmbiguousConversation, target)
}

// sessionCandidate is one conversation a lookup may select: a pending item
// or a listed session.
type sessionCandidate struct {
	sessionID            string
	teamID               string
	participants         []string
	participantDIDs      []string
	participantAddresses []string
	senderWaiting        bool
	activity             string
	size                 int
}

func pendingCandidates(items []awid.ChatPendingItem) []sessionCandidate {
	out := make([]sessionCandidate, 0, len(items))
	for _, p := range items {
		out = append(out, sessionCandidate{sessionID: p.SessionID, teamID: p.TeamID, participants: p.Participants,
			participantDIDs: p.ParticipantDIDs, participantAddresses: p.ParticipantAddresses, senderWaiting: p.SenderWaiting,
			activity: p.LastActivity, size: participantIdentityCount(p.Participants, p.ParticipantDIDs, p.ParticipantAddresses)})
	}
	return out
}

func listedCandidates(items []awid.ChatSessionItem) []sessionCandidate {
	out := make([]sessionCandidate, 0, len(items))
	for _, s := range items {
		out = append(out, sessionCandidate{sessionID: s.SessionID, teamID: s.TeamID, participants: s.Participants,
			participantDIDs: s.ParticipantDIDs, participantAddresses: s.ParticipantAddresses,
			activity: sessionActivity(s), size: participantIdentityCount(s.Participants, s.ParticipantDIDs, s.ParticipantAddresses)})
	}
	return out
}

// betterThan ranks candidates: a session whose other party is waiting first
// when the choice says so, then the fewest participants (1:1 over group),
// then the latest activity. Any candidate beats none.
func (c sessionCandidate) betterThan(best sessionCandidate, choice sessionChoice) bool {
	if best.sessionID == "" {
		return true
	}
	if choice == waitingSessionFirst && c.senderWaiting != best.senderWaiting {
		return c.senderWaiting
	}
	if c.size != best.size {
		return c.size < best.size
	}
	return c.activity > best.activity
}

// candidateRule is how one lookup pass matches candidates against its target.
type candidateRule struct {
	match func(participants, participantDIDs, participantAddresses []string, target string) bool
	// requireUnique refuses more than one match, unless every match names
	// one concrete identity.
	requireUnique bool
	// trackIdentity collects the concrete identities the matches name.
	trackIdentity bool
}

// appendUniqueFold appends the non-empty values not already present,
// ignoring case.
func appendUniqueFold(keys []string, values ...string) []string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		duplicate := false
		for _, existing := range keys {
			duplicate = duplicate || strings.EqualFold(existing, value)
		}
		if !duplicate {
			keys = append(keys, value)
		}
	}
	return keys
}

// findSessionByConfirmedDID selects a conversation with the participant the
// caller confirmed by did, with the priorities of findSession. A strong
// identity is available, so only strong identities match (IDENTITY_RULES.md):
// did, the identity's other DID and its address, as resolved for did. A bare
// alias, which any participant may hold, is no fallback here.
func findSessionByConfirmedDID(ctx context.Context, client *awid.Client, did string, choice sessionChoice) (sessionID string, senderWaiting bool, err error) {
	dids := []string{did}
	address := ""
	// Resolution only widens the match to the same identity's other DID and
	// its address. When it fails, did alone matches: a session may then be
	// missed, and a new one is started with the confirmed participant, but
	// another participant's session is never chosen.
	if identity, err := client.ResolveIdentity(ctx, did); err == nil && identity != nil {
		dids = append(dids, strings.TrimSpace(identity.StableID), strings.TrimSpace(identity.DID))
		address = strings.TrimSpace(identity.Address)
	}
	hasParticipant := func(participants, participantDIDs, participantAddresses []string) bool {
		for _, row := range chatParticipantRows(participants, participantDIDs, participantAddresses) {
			if address != "" && strings.EqualFold(row.Address, address) {
				return true
			}
			for _, candidate := range dids {
				if candidate != "" && strings.EqualFold(row.DID, candidate) {
					return true
				}
			}
		}
		return false
	}
	var pendingResp awid.ChatPendingResponse
	if err := client.Get(ctx, "/v1/chat/pending", &pendingResp); err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}
	var best sessionCandidate
	for _, candidate := range pendingCandidates(pendingResp.Pending) {
		if hasParticipant(candidate.participants, candidate.participantDIDs, candidate.participantAddresses) && candidate.betterThan(best, choice) {
			best = candidate
		}
	}
	if best.sessionID != "" {
		return best.sessionID, best.senderWaiting, nil
	}
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	for _, candidate := range listedCandidates(sessionsResp.Sessions) {
		if hasParticipant(candidate.participants, candidate.participantDIDs, candidate.participantAddresses) && candidate.betterThan(best, choice) {
			best = candidate
		}
	}
	if best.sessionID != "" {
		return best.sessionID, false, nil
	}
	return "", false, fmt.Errorf("no conversation found with %s", did)
}

// buildMessages converts ChatMessage slice to Event slice.
func buildMessages(messages []awid.ChatMessage) []Event {
	events := make([]Event, len(messages))
	for i, m := range messages {
		events[i] = Event{
			IDChain:                 m.IDChain,
			SignedPayload:           m.SignedPayload,
			Type:                    "message",
			SenderMembership:        m.SenderMembership,
			MessageID:               m.MessageID,
			FromAgent:               m.FromAgent,
			FromAddress:             m.FromAddress,
			ToAddress:               m.ToAddress,
			Body:                    m.Body,
			Attachments:             m.Attachments,
			AttachmentsAvailable:    m.AttachmentsAvailable,
			ContentMode:             m.ContentMode,
			MessageVersion:          m.MessageVersion,
			Encrypted:               m.Encrypted,
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

// markReadBestEffort acknowledges the presented messages, retrying once. It
// reports whether the acknowledgement landed and, when it did not, why. A
// caller that has nothing to acknowledge gets (false, nil): no attempt was made
// and nothing failed. Returning the error is what lets a caller distinguish a
// mark-read that failed from one that was never needed; discarding it made
// every failure other than the unread-snapshot overflow invisible.
func markReadBestEffort(ctx context.Context, client *awid.Client, sessionID string, messageIDs []string) (bool, error) {
	if client == nil || sessionID == "" {
		return false, nil
	}
	presentedIDs := make([]string, 0, len(messageIDs))
	for _, messageID := range messageIDs {
		if messageID = strings.TrimSpace(messageID); messageID != "" {
			presentedIDs = append(presentedIDs, messageID)
		}
	}
	if len(presentedIDs) == 0 {
		return false, nil
	}
	req := &awid.ChatMarkReadRequest{MessageIDs: presentedIDs}
	if _, err := client.ChatMarkRead(ctx, sessionID, req); err == nil {
		return true, nil
	} else if status, ok := awid.HTTPStatusCode(err); ok && status >= 400 && status < 500 {
		// ChatMarkRead already performed the one compatibility fallback when
		// eligible. Do not repeat malformed or rejected requests at this layer.
		return false, fmt.Errorf("marking %d message(s) read: %w", len(presentedIDs), err)
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, fmt.Errorf("marking %d message(s) read: %w", len(presentedIDs), ctx.Err())
	case <-timer.C:
	}
	if _, err := client.ChatMarkRead(ctx, sessionID, req); err != nil {
		return false, fmt.Errorf("marking %d message(s) read: %w", len(presentedIDs), err)
	}
	return true, nil
}

// markPresentedRead marks every received message presented by the wait result as
// read (best-effort). This prevents the notify hook from showing messages that
// were already delivered via SSE during send-and-wait or listen.
func markPresentedRead(ctx context.Context, client *awid.Client, sessionID string, events []Event) {
	messageIDs := make([]string, 0, len(events))
	for _, event := range events {
		if event.Type == EventMessage && event.MessageID != "" {
			messageIDs = append(messageIDs, event.MessageID)
		}
	}
	// Send and Listen stay best-effort: a failed acknowledgement must not fail
	// the call, and the messages are simply re-presented next time.
	_, _ = markReadBestEffort(ctx, client, sessionID, messageIDs)
}

// streamOpener opens an SSE stream for a chat session.
// afterSeq > 0 resumes after that session number. Otherwise after controls
// replay: non-nil replays messages after that timestamp; nil skips replay.
type streamOpener func(ctx context.Context, sessionID string, deadline time.Time, after *time.Time, afterSeq int64) (*awid.SSEStream, error)

func clientStreamOpener(client *awid.Client) streamOpener {
	return func(ctx context.Context, sessionID string, deadline time.Time, after *time.Time, afterSeq int64) (*awid.SSEStream, error) {
		if afterSeq > 0 {
			return client.ChatStreamAfterSeq(ctx, sessionID, deadline, afterSeq)
		}
		return client.ChatStream(ctx, sessionID, deadline, after)
	}
}

// minStreamReopenInterval paces reopening a stream that ended early.
const minStreamReopenInterval = time.Second

// eventDisposition is what a wait does with one received message event.
type eventDisposition int

const (
	// skipEvent drops the event silently, such as the replay of the
	// sender's own message.
	skipEvent eventDisposition = iota
	// collectEvent keeps the event among those the wait presents and goes on
	// waiting.
	collectEvent
	// acceptEvent keeps the event as the awaited reply.
	acceptEvent
)

// messageAcceptor decides the disposition of a received message event
// during the wait loop.
type messageAcceptor func(ev Event) eventDisposition

// waitForMessage opens an SSE stream and waits for a message matching the acceptor.
// Handles read receipts, extend-wait messages, and wait extensions.
// after controls SSE replay: non-nil replays messages after that timestamp; nil skips replay.
//
// The server ends a stream at its lifetime cap (300 s). While the wait runs,
// an ended stream is reopened after the last session number seen, or, when
// none was seen, replaying from after (or from when the wait began), so
// nothing committed while it was closed is lost.
func waitForMessage(ctx context.Context, client *awid.Client, openStream streamOpener, sessionID string, participants []awid.ChatParticipant, selfAlias string, waitSeconds int, after *time.Time, callback StatusCallback, accept messageAcceptor) (*SendResult, error) {
	result := &SendResult{
		SessionID: sessionID,
		Status:    SendTimeout,
		Events:    []Event{},
	}

	waitTimeout := time.Duration(waitSeconds) * time.Second
	waitDeadline := time.Now().Add(waitTimeout)
	waitStart := time.Now()

	replayAfter := after
	if replayAfter == nil {
		replayAfter = &waitStart
	}
	var lastSeq int64
	// A server without session numbers replays a reopened stream by
	// timestamp; a message already seen is not presented again.
	seenMessages := map[string]bool{}

	// The server deadline is a safety net for orphaned connections —
	// the local waitTimer manages actual wait semantics.
	stream, err := openStream(ctx, sessionID, time.Now().Add(maxStreamDeadline), after, 0)
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
	streamOpenedAt := time.Now()
	events, streamCleanup := streamToChannel(ctx, stream)
	defer func() { streamCleanup() }()
	var reopen <-chan time.Time

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
		case <-reopen:
			reopen = nil
			resumeAfter := replayAfter
			if lastSeq > 0 {
				resumeAfter = nil
			}
			stream, err := openStream(ctx, sessionID, time.Now().Add(maxStreamDeadline), resumeAfter, lastSeq)
			if err != nil {
				// The wait is still running, so a failed reopen, EOF
				// included, is an error rather than a timeout.
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, fmt.Errorf("reconnecting to SSE: %w", err)
			}
			streamOpenedAt = time.Now()
			events, streamCleanup = streamToChannel(ctx, stream)
		case sr, ok := <-events:
			if !ok || sr.err != nil {
				// The stream ended while the wait runs: reopen it, at most
				// once per minStreamReopenInterval.
				streamCleanup()
				streamCleanup = func() {}
				events = nil
				reopen = time.After(max(0, minStreamReopenInterval-time.Since(streamOpenedAt)))
				continue
			}

			chatEvent := parseSSEEvent(sr.event)
			if chatEvent.Seq > lastSeq {
				lastSeq = chatEvent.Seq
			}
			if chatEvent.Type == EventMessage && chatEvent.MessageID != "" {
				if seenMessages[chatEvent.MessageID] {
					continue
				}
				seenMessages[chatEvent.MessageID] = true
			}
			if awid.IsAuthorityTerminalEvent(chatEvent.Type) {
				detail := strings.TrimSpace(chatEvent.Reason)
				if detail == "" {
					detail = strings.TrimSpace(chatEvent.Body)
				}
				if detail == "" {
					detail = chatEvent.Type
				}
				if chatEvent.Type == EventVerificationUnavailable {
					detail = "identity grant verification unavailable; retry"
				}
				return nil, fmt.Errorf("chat stream closed: %s", detail)
			}
			if chatEvent.Type == EventMessage {
				if err := verifyStreamMessage(ctx, client, sessionID, &chatEvent, participants); err != nil {
					return nil, err
				}
			}

			if chatEvent.Type == EventReadReceipt {
				readerLabel := inferReadReceiptLabel(ctx, client, selfAlias, chatEvent.ReaderAlias, participants)
				if readerLabel != "" {
					chatEvent.ReaderAlias = readerLabel
				}
				result.Events = append(result.Events, chatEvent)
				if callback != nil {
					callback("read_receipt", fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				if chatEvent.ExtendsWaitSeconds > 0 {
					extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				continue
			}

			if chatEvent.Type == EventMessage {
				disposition := accept(chatEvent)
				if disposition == skipEvent {
					continue
				}

				result.Events = append(result.Events, chatEvent)

				if disposition != acceptEvent {
					continue
				}

				if chatEvent.ExtendWait {
					from := chatEventSenderLabel(chatEvent, participants)
					if callback != nil {
						callback("extend_wait", fmt.Sprintf("%s: %s", from, chatEvent.Body))
					}
					if chatEvent.ExtendsWaitSeconds > 0 {
						extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s requested more time", from))
					}
					continue
				}

				result.SenderWaiting = chatEvent.SenderWaiting

				if chatEvent.SenderLeaving {
					result.Status = SendSenderLeft
					result.Reply = chatEvent.Body
					return result, nil
				}

				result.Status = SendReplied
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
	Participants     []awid.ChatParticipant
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
	if opts.StartConversation && !opts.WaitExplicit && !opts.Leaving {
		waitSeconds = 300
	}

	aliases, dids, addresses := classifyChatTargets(targets)
	req := &awid.ChatCreateSessionRequest{
		ToAliases:          aliases,
		ToDIDs:             dids,
		ToAddresses:        addresses,
		Message:            message,
		Leaving:            opts.Leaving,
		EncryptE2EE:        opts.Encryption() == E2EERequired,
		ConfirmedRecipient: opts.ConfirmedRecipient,
	}
	if waitSeconds > 0 {
		req.WaitSeconds = &waitSeconds
	}
	if len(targets) == 1 && !opts.StartConversation && shouldProbeExistingSession(targets[0]) {
		if sessionID, _, findErr := lookupSession(ctx, client, targets[0], opts.RecipientDID, latestSession); findErr == nil && sessionID != "" {
			encrypt, err := ContinuationEncrypted(ctx, client, sessionID, opts.Encryption(), callback)
			if err != nil {
				return nil, err
			}
			msgResp, err := client.ChatSendMessage(ctx, sessionID, &awid.ChatSendMessageRequest{
				Body:        message,
				Leaving:     opts.Leaving,
				EncryptE2EE: encrypt,
			})
			if err != nil {
				return nil, fmt.Errorf("sending message: %w", err)
			}
			return sendCommon(ctx, client, clientStreamOpener(client), sendResponse{
				SessionID: sessionID,
				MessageID: msgResp.MessageID,
			}, myAlias, targets, message, waitSeconds, opts, &sentAt, callback)
		} else if errors.Is(findErr, ErrAmbiguousConversation) {
			return nil, findErr
		}
	}
	createResp, err := client.ChatCreateSession(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}

	return sendCommon(ctx, client, clientStreamOpener(client), sendResponse{
		SessionID:        createResp.SessionID,
		MessageID:        createResp.MessageID,
		Participants:     createResp.Participants,
		TargetsConnected: createResp.TargetsConnected,
		TargetsLeft:      createResp.TargetsLeft,
	}, myAlias, targets, message, waitSeconds, opts, &sentAt, callback)
}

func shouldProbeExistingSession(target string) bool {
	// Every non-empty target may name an existing session. Lookup reuses its
	// session ID or reports ambiguity before a new conversation is created.
	return strings.TrimSpace(target) != ""
}

// sendCommon handles the post-send wait logic after a message has been created.
// resolvedWait is the actual wait duration in seconds, already accounting for
// StartConversation upgrades. This must match what was sent to the server.
func sendCommon(ctx context.Context, client *awid.Client, openStream streamOpener, resp sendResponse, myAlias string, targets []string, message string, resolvedWait int, opts SendOptions, after *time.Time, callback StatusCallback) (*SendResult, error) {
	result := &SendResult{
		SessionID:   resp.SessionID,
		MessageID:   resp.MessageID,
		Status:      SendSent,
		TargetAgent: strings.Join(targets, ", "),
		Events:      []Event{},
	}
	targetStatusNames := make([][]string, 0, len(targets))
	for _, target := range targets {
		targetStatusNames = append(targetStatusNames, normalizedChatTargetNames(ctx, client, target, resp.Participants))
	}

	if opts.Leaving {
		return result, nil
	}

	if opts.Wait == 0 {
		return result, nil
	}

	leftNames := chatNameLists(ctx, client, resp.TargetsLeft, resp.Participants)
	targetHasLeft := false
	for _, targetNames := range targetStatusNames {
		if overlapsAny(targetNames, leftNames) {
			targetHasLeft = true
			break
		}
	}
	if targetHasLeft && !opts.StartConversation {
		result.Status = SendTargetsLeft
		return result, nil
	}

	// Target connection status is informational.
	connectedNames := chatNameLists(ctx, client, resp.TargetsConnected, resp.Participants)
	for _, targetNames := range targetStatusNames {
		if !overlapsAny(targetNames, connectedNames) {
			result.TargetNotConnected = true
			break
		}
	}

	acceptor := targetReplyAcceptor(resp.MessageID, opts, resp.Participants, targetStatusNames)
	waitResult, err := waitForMessage(ctx, client, openStream, resp.SessionID, resp.Participants, myAlias, resolvedWait, after, callback, acceptor)
	if err != nil {
		return nil, err
	}

	markPresentedRead(ctx, client, resp.SessionID, waitResult.Events)

	result.Status = waitResult.Status
	result.Reply = waitResult.Reply
	result.Events = waitResult.Events
	result.SenderWaiting = waitResult.SenderWaiting
	result.WaitedSeconds = waitResult.WaitedSeconds
	return result, nil
}

// chatNameLists resolves each alias to its normalized chat names once.
func chatNameLists(ctx context.Context, client *awid.Client, aliases []string, participants []awid.ChatParticipant) [][]string {
	lists := make([][]string, 0, len(aliases))
	for _, alias := range aliases {
		lists = append(lists, normalizedChatTargetNames(ctx, client, alias, participants))
	}
	return lists
}

// overlapsAny reports whether names shares a name with any of lists.
func overlapsAny(names []string, lists [][]string) bool {
	for _, other := range lists {
		if chatTargetNameListsOverlap(names, other) {
			return true
		}
	}
	return false
}

// targetReplyAcceptor skips replays and accepts only a reply from a target.
// The gate opens when the stream shows the sent message by ID; with no
// message ID from the server it starts open.
func targetReplyAcceptor(sentMessageID string, opts SendOptions, participants []awid.ChatParticipant, targetStatusNames [][]string) func(Event) eventDisposition {
	seenSentMessage := sentMessageID == ""
	return func(ev Event) eventDisposition {
		if !seenSentMessage {
			if ev.MessageID == sentMessageID {
				seenSentMessage = true
			}
			return skipEvent
		}
		if !eventMayBeTargetReply(ev, opts) {
			return collectEvent
		}
		eventNames := normalizedChatEventNames(ev, participants)
		for _, targetNames := range targetStatusNames {
			if chatTargetNameListsOverlap(targetNames, eventNames) {
				return acceptEvent
			}
		}
		return collectEvent
	}
}

// eventMayBeTargetReply reports whether ev can be the reply the sender waits
// for, before its names are compared with the target's. When the caller
// confirmed its one target's identity, only a message signed by that
// identity is its reply: the strong tier decides, and a matching name does
// not (chat/IDENTITY_RULES.md:38-40). A reply that fails verification is
// still accepted and shown with its failure tag, so the failure is seen.
func eventMayBeTargetReply(ev Event, opts SendOptions) bool {
	confirmed := []string{strings.TrimSpace(opts.RecipientDID)}
	if opts.ConfirmedRecipient != nil {
		confirmed = append(confirmed, strings.TrimSpace(opts.ConfirmedRecipient.DID), strings.TrimSpace(opts.ConfirmedRecipient.StableID))
	}
	anyConfirmed := false
	for _, did := range confirmed {
		if did == "" {
			continue
		}
		anyConfirmed = true
		if did == strings.TrimSpace(ev.FromStableID) || did == strings.TrimSpace(ev.FromDID) {
			return true
		}
	}
	return !anyConfirmed
}

// Listen waits for a message in an existing conversation without sending.
// Returns on any message in the session (not filtered by sender).
func Listen(ctx context.Context, client *awid.Client, targetAlias string, waitSeconds int, callback StatusCallback) (*SendResult, error) {
	return ListenConfirmed(ctx, client, targetAlias, waitSeconds, callback, "")
}

// ListenConfirmed is Listen in the session selected by confirmedDID, the DID
// the caller confirmed for targetAlias, when one is given (lookupSession).
func ListenConfirmed(ctx context.Context, client *awid.Client, targetAlias string, waitSeconds int, callback StatusCallback, confirmedDID string) (*SendResult, error) {
	sessionID, _, err := lookupSession(ctx, client, targetAlias, confirmedDID, waitingSessionFirst)
	if err != nil {
		return nil, err
	}

	acceptAll := func(ev Event) eventDisposition { return acceptEvent }

	result, err := waitForMessage(ctx, client, clientStreamOpener(client), sessionID, nil, "", waitSeconds, nil, callback, acceptAll)
	if err != nil {
		return nil, err
	}

	markPresentedRead(ctx, client, sessionID, result.Events)

	result.TargetAgent = targetAlias
	return result, nil
}

// Open fetches unread messages for a conversation and marks them as read.
func Open(ctx context.Context, client *awid.Client, targetAlias string) (*OpenResult, error) {
	return OpenConfirmed(ctx, client, targetAlias, "")
}

// OpenConfirmed is Open in the session selected by confirmedDID, the DID the
// caller confirmed for targetAlias, when one is given (lookupSession).
func OpenConfirmed(ctx context.Context, client *awid.Client, targetAlias string, confirmedDID string) (*OpenResult, error) {
	sessionID, senderWaiting, err := lookupSession(ctx, client, targetAlias, confirmedDID, waitingSessionFirst)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, awid.ChatHistoryParams{
		SessionID:  sessionID,
		UnreadOnly: true,
		Limit:      maxOpenUnreadMessages + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("getting unread messages: %w", err)
	}
	if len(messagesResp.Messages) > maxOpenUnreadMessages {
		return nil, fmt.Errorf("more than %d unread messages; refusing to acknowledge an incomplete snapshot", maxOpenUnreadMessages)
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

	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	filteredMessages, err := FilterDeliveredMessagesForDir(workingDir, messagesResp.Messages)
	if err != nil {
		return nil, err
	}
	result.Messages = buildMessages(filteredMessages)

	if ids := DeliveredMessageIDs(messagesResp.Messages); len(ids) > 0 {
		if err := SaveDeliveredIDsForDir(workingDir, ids); err != nil {
			result.ReceiptError = err.Error()
		}
	}

	presentedIDs := make([]string, 0, len(messagesResp.Messages))
	for _, message := range messagesResp.Messages {
		presentedIDs = append(presentedIDs, message.MessageID)
	}
	// Open stays best-effort too - it still returns the messages it presented -
	// but it reports a failed acknowledgement instead of silently presenting
	// them as unmarked. This is separate from the overflow refusal above, which
	// declines to acknowledge at all and returns an error.
	if marked, err := markReadBestEffort(ctx, client, sessionID, presentedIDs); marked {
		result.MarkedRead = len(messagesResp.Messages)
	} else if err != nil {
		result.MarkReadError = err.Error()
	}
	if len(result.Messages) == 0 {
		result.UnreadWasEmpty = true
	}

	return result, nil
}

// History fetches all messages in a conversation.
func History(ctx context.Context, client *awid.Client, targetAlias string) (*HistoryResult, error) {
	return HistoryWithOptions(ctx, client, targetAlias, false, 1000)
}

// HistoryWithOptions resolves a recipient before fetching the selected history
// page. Filters reach the server before any message is decrypted.
func HistoryWithOptions(ctx context.Context, client *awid.Client, targetAlias string, unreadOnly bool, limit int) (*HistoryResult, error) {
	return HistoryConfirmed(ctx, client, targetAlias, unreadOnly, limit, "")
}

// HistoryConfirmed is HistoryWithOptions for the session selected by
// confirmedDID, the DID the caller confirmed for targetAlias, when one is
// given (lookupSession).
func HistoryConfirmed(ctx context.Context, client *awid.Client, targetAlias string, unreadOnly bool, limit int, confirmedDID string) (*HistoryResult, error) {
	sessionID, _, err := lookupSession(ctx, client, targetAlias, confirmedDID, latestSession)
	if err != nil {
		return nil, err
	}

	return HistoryBySession(ctx, client, sessionID, "", unreadOnly, limit)
}

// HistoryBySession fetches messages by explicit session id. It is used by local
// notification clients that already received an event with the canonical session
// and message ids and must not resolve by alias.
func HistoryBySession(ctx context.Context, client *awid.Client, sessionID string, messageID string, unreadOnly bool, limit int) (*HistoryResult, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, errors.New("session id is required")
	}
	if limit <= 0 {
		limit = 1000
	}
	messagesResp, err := client.ChatHistory(ctx, awid.ChatHistoryParams{
		SessionID:  sessionID,
		MessageID:  strings.TrimSpace(messageID),
		UnreadOnly: unreadOnly,
		Limit:      limit,
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
		mappedAddress, mappedStableID, mappedDID := pendingParticipantIdentityByLastFrom(
			p.Participants,
			p.ParticipantDIDs,
			p.ParticipantAddresses,
			p.LastFrom,
		)
		lastFromAddress := strings.TrimSpace(p.LastFromAddress)
		if lastFromAddress == "" {
			lastFromAddress = mappedAddress
		}
		lastFromStableID := strings.TrimSpace(p.LastFromStableID)
		lastFromDID := strings.TrimSpace(p.LastFromDID)
		if lastFromStableID == "" && lastFromDID == "" {
			lastFromStableID = mappedStableID
			lastFromDID = mappedDID
		}
		result.Pending = append(result.Pending, PendingConversation{
			SessionID:            p.SessionID,
			Participants:         p.Participants,
			ParticipantDIDs:      p.ParticipantDIDs,
			ParticipantAddresses: p.ParticipantAddresses,
			LastMessage:          p.LastMessage,
			LastFrom:             p.LastFrom,
			LastFromStableID:     lastFromStableID,
			LastFromDID:          lastFromDID,
			LastFromAddress:      lastFromAddress,
			UnreadCount:          p.UnreadCount,
			LastActivity:         p.LastActivity,
			SenderWaiting:        p.SenderWaiting,
			TimeRemainingSeconds: p.TimeRemainingSeconds,
		})
	}

	return result, nil
}

// ExtendWaitOptions configures ExtendWaitWithOptions.
type ExtendWaitOptions struct {
	// EncryptE2EE is the released (aw-v1.36.58) way to require encryption;
	// true is E2EE: E2EERequired, whatever E2EE says.
	EncryptE2EE bool
	// RecipientDID is the DID the caller confirmed for targetAlias; the
	// session is then selected by this strong identity only.
	RecipientDID string
	// E2EE is how the message chooses end-to-end encryption.
	E2EE E2EEChoice
}

// Encryption is the end-to-end encryption choice the options make.
func (o ExtendWaitOptions) Encryption() E2EEChoice {
	return encryptionChoice(o.EncryptE2EE, o.E2EE)
}

// ExtendWait tells the target its wait is extended, in the session found for
// targetAlias. encryptE2EE, when given and true, requires encryption; otherwise
// the session's encryption carries over.
func ExtendWait(ctx context.Context, client *awid.Client, targetAlias string, message string, encryptE2EE ...bool) (*ExtendWaitResult, error) {
	return ExtendWaitWithOptions(ctx, client, targetAlias, message, ExtendWaitOptions{EncryptE2EE: len(encryptE2EE) > 0 && encryptE2EE[0]})
}

// ContinuationEncrypted reports whether a message to an existing session is
// end-to-end encrypted, by awid.ContinuationEncryption from the session's
// stored rows (read unless --e2ee decides alone) and whether this client can
// encrypt. A plaintext send into an encrypted session, or into one whose
// encryption cannot be read, is announced through status.
func ContinuationEncrypted(ctx context.Context, client *awid.Client, sessionID string, choice E2EEChoice, status StatusCallback) (bool, error) {
	var reading awid.ConversationEncryptionReading
	if choice != E2EERequired {
		var err error
		if reading, err = client.ChatSessionEncryption(ctx, sessionID); err != nil {
			return false, fmt.Errorf("reading whether the conversation is end-to-end encrypted: %w", err)
		}
	}
	decision := awid.ContinuationEncryption(reading, choice, client.E2EESendUnavailable())
	if decision.Notice != "" && status != nil {
		status("plaintext", decision.Notice)
	}
	return decision.Encrypt, nil
}

func ExtendWaitWithOptions(ctx context.Context, client *awid.Client, targetAlias string, message string, opts ExtendWaitOptions) (*ExtendWaitResult, error) {
	return ExtendWaitWithStatus(ctx, client, targetAlias, message, opts, nil)
}

// ExtendWaitWithStatus is ExtendWaitWithOptions with status lines, such as the
// --plaintext notice, sent to status.
func ExtendWaitWithStatus(ctx context.Context, client *awid.Client, targetAlias string, message string, opts ExtendWaitOptions, status StatusCallback) (*ExtendWaitResult, error) {
	sessionID, _, err := lookupSession(ctx, client, targetAlias, opts.RecipientDID, waitingSessionFirst)
	if err != nil {
		return nil, err
	}

	encrypt, err := ContinuationEncrypted(ctx, client, sessionID, opts.Encryption(), status)
	if err != nil {
		return nil, err
	}
	msgResp, err := client.ChatSendMessage(ctx, sessionID, &awid.ChatSendMessageRequest{
		Body:        message,
		ExtendWait:  true,
		EncryptE2EE: encrypt,
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
	return ShowPendingConfirmed(ctx, client, targetAlias, "")
}

// ShowPendingConfirmed is ShowPending for the session selected by
// confirmedDID, the DID the caller confirmed for targetAlias, when one is
// given (lookupSession).
func ShowPendingConfirmed(ctx context.Context, client *awid.Client, targetAlias string, confirmedDID string) (*SendResult, error) {
	sessionID, _, err := lookupSession(ctx, client, targetAlias, confirmedDID, waitingSessionFirst)
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
		mappedAddress, mappedStableID, mappedDID := pendingParticipantIdentityByLastFrom(
			p.Participants,
			p.ParticipantDIDs,
			p.ParticipantAddresses,
			p.LastFrom,
		)
		fromAddress := strings.TrimSpace(p.LastFromAddress)
		if fromAddress == "" {
			fromAddress = mappedAddress
		}
		if fromAddress == "" {
			unanimousAddress, _, _ := unanimousPendingParticipantIdentity(
				p.Participants,
				p.ParticipantDIDs,
				p.ParticipantAddresses,
			)
			fromAddress = unanimousAddress
		}
		fromStableID := ""
		fromDID := ""
		if value := strings.TrimSpace(p.LastFromStableID); value != "" {
			fromStableID = value
		}
		if fromStableID == "" && fromDID == "" {
			fromStableID = mappedStableID
			fromDID = mappedDID
		}
		if fromStableID == "" {
			if value := strings.TrimSpace(p.LastFromDID); value != "" {
				if strings.HasPrefix(value, "did:aw:") {
					fromStableID = value
				} else {
					fromDID = value
				}
			}
		}
		if fromStableID == "" {
			_, unanimousStableID, _ := unanimousPendingParticipantIdentity(
				p.Participants,
				p.ParticipantDIDs,
				p.ParticipantAddresses,
			)
			fromStableID = unanimousStableID
		}
		return &SendResult{
			SessionID:     p.SessionID,
			Status:        SendPending,
			TargetAgent:   targetAlias,
			Reply:         p.LastMessage,
			SenderWaiting: p.SenderWaiting,
			Events: []Event{
				{
					Type:         "message",
					FromAgent:    p.LastFrom,
					FromAddress:  fromAddress,
					FromStableID: fromStableID,
					FromDID:      fromDID,
					Body:         p.LastMessage,
					Timestamp:    p.LastActivity,
				},
			},
		}, nil
	}

	return nil, fmt.Errorf("no pending conversation with %s", targetAlias)
}

func normalizedChatEventNames(ev Event, participants []awid.ChatParticipant) []string {
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

	hasStrongIdentity := strings.TrimSpace(ev.FromAddress) != "" ||
		strings.TrimSpace(ev.FromStableID) != "" ||
		strings.TrimSpace(ev.FromDID) != ""

	for _, value := range []string{
		ev.FromAddress,
		ev.FromStableID,
		ev.FromDID,
		addressHandle(ev.FromAddress),
	} {
		appendUnique(value)
	}

	matchedParticipants := matchingChatParticipantsForEventIdentity(participants, ev)
	for _, match := range matchedParticipants {
		appendUnique(strings.TrimSpace(match.Alias))
		appendUnique(strings.TrimSpace(match.Address))
		appendUnique(strings.TrimSpace(match.DID))
	}
	if !hasStrongIdentity || len(participants) == 0 {
		appendUnique(ev.FromAgent)
	}

	return names
}

func normalizedChatTargetNames(ctx context.Context, client *awid.Client, target string, participants []awid.ChatParticipant) []string {
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
	removeValue := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		filtered := names[:0]
		for _, existing := range names {
			if !strings.EqualFold(existing, value) {
				filtered = append(filtered, existing)
			}
		}
		names = filtered
	}
	appendResolved := func(identifier string) {
		identifier = strings.TrimSpace(identifier)
		if identifier == "" || client == nil {
			return
		}
		if !strings.HasPrefix(identifier, "did:") && !strings.Contains(identifier, "/") {
			return
		}
		identity, err := client.ResolveIdentity(ctx, identifier)
		if err != nil || identity == nil {
			return
		}
		appendUnique(strings.TrimSpace(identity.Address))
		appendUnique(strings.TrimSpace(identity.StableID))
		appendUnique(strings.TrimSpace(identity.DID))
	}

	appendUnique(target)
	normalized := normalizeSessionTarget(ctx, client, target)
	appendUnique(normalized)
	appendResolved(target)
	appendResolved(normalized)
	participantAliasIsUnique := func(alias string) bool {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			return false
		}
		matches := 0
		for _, participant := range participants {
			if strings.EqualFold(strings.TrimSpace(participant.Alias), alias) {
				matches++
				if matches > 1 {
					return false
				}
			}
		}
		return matches == 1
	}
	appendParticipant := func(participant awid.ChatParticipant) {
		if alias := strings.TrimSpace(participant.Alias); participantAliasIsUnique(alias) {
			appendUnique(alias)
		}
		appendUnique(strings.TrimSpace(participant.Address))
		appendUnique(strings.TrimSpace(participant.DID))
	}
	matchedParticipants := []awid.ChatParticipant{}
	for _, participant := range participants {
		if chatParticipantMatchesSessionTarget(participant, target) || chatParticipantMatchesSessionTarget(participant, normalized) {
			matchedParticipants = append(matchedParticipants, participant)
		}
	}
	if len(matchedParticipants) == 1 {
		appendParticipant(matchedParticipants[0])
	} else if len(matchedParticipants) > 1 {
		if !strings.HasPrefix(strings.TrimSpace(target), "did:") && !strings.Contains(strings.TrimSpace(target), "/") {
			removeValue(target)
		}
		if normalized != target && !strings.HasPrefix(strings.TrimSpace(normalized), "did:") && !strings.Contains(strings.TrimSpace(normalized), "/") {
			removeValue(normalized)
		}
	} else if len(matchedParticipants) == 0 {
		handleMatches := []awid.ChatParticipant{}
		for _, candidate := range []string{addressHandle(target), addressHandle(normalized)} {
			if candidate == "" {
				continue
			}
			handleMatches = handleMatches[:0]
			for _, participant := range participants {
				for _, identity := range []string{
					strings.TrimSpace(participant.Alias),
					addressHandle(strings.TrimSpace(participant.Address)),
					stableAlias(strings.TrimSpace(participant.DID)),
				} {
					if identity != "" && strings.EqualFold(identity, candidate) {
						handleMatches = append(handleMatches, participant)
						break
					}
				}
			}
			if len(handleMatches) == 1 {
				appendParticipant(handleMatches[0])
				break
			}
		}
		if len(participants) == 0 {
			appendUnique(addressHandle(target))
			appendUnique(addressHandle(normalized))
		}
	}
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

func chatTargetNameListsOverlap(left []string, right []string) bool {
	for _, candidate := range right {
		if chatTargetNameListContains(left, candidate) {
			return true
		}
	}
	return false
}

func chatEventSenderLabel(ev Event, participants []awid.ChatParticipant) string {
	for _, participant := range matchingChatParticipantsForEventIdentity(participants, ev) {
		if value := preferredChatIdentityLabel(
			strings.TrimSpace(participant.Alias),
			strings.TrimSpace(participant.Address),
			func() string {
				row := chatParticipantRowFromParticipant(participant)
				if row.StableID != "" {
					return row.StableID
				}
				return strings.TrimSpace(ev.FromStableID)
			}(),
			func() string {
				row := chatParticipantRowFromParticipant(participant)
				if row.DID != "" {
					return row.DID
				}
				return strings.TrimSpace(ev.FromDID)
			}(),
		); value != "" {
			return value
		}
	}
	if value := strings.TrimSpace(ev.FromAddress); value != "" {
		return value
	}
	if value := strings.TrimSpace(ev.FromStableID); value != "" {
		return value
	}
	if value := strings.TrimSpace(ev.FromDID); value != "" {
		return value
	}
	return strings.TrimSpace(ev.FromAgent)
}

func chatEventTrustAddress(ev Event, participants []awid.ChatParticipant) string {
	for _, participant := range matchingChatParticipantsForEventIdentity(participants, ev) {
		if value := strings.TrimSpace(participant.Address); value != "" {
			return value
		}
		if value := strings.TrimSpace(participant.Alias); value != "" {
			return value
		}
	}
	if value := strings.TrimSpace(ev.FromAddress); value != "" {
		return value
	}
	return strings.TrimSpace(ev.FromAgent)
}

func inferReadReceiptLabel(ctx context.Context, client *awid.Client, selfAlias string, readerAlias string, participants []awid.ChatParticipant) string {
	readerAlias = strings.TrimSpace(readerAlias)
	if readerAlias != "" {
		return readerAlias
	}
	candidates := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range candidates {
			if existing == value {
				return
			}
		}
		candidates = append(candidates, value)
	}
	for _, participant := range participants {
		if chatParticipantMatchesSelf(participant, client, selfAlias) {
			continue
		}
		appendUnique(chatParticipantLabel(ctx, client, participant))
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	return ""
}

func chatParticipantMatchesSelf(participant awid.ChatParticipant, client *awid.Client, selfAlias string) bool {
	selfAlias = strings.TrimSpace(selfAlias)
	selfAddress := ""
	selfStableID := ""
	selfDID := ""
	if client != nil {
		selfAddress = strings.TrimSpace(client.Address())
		selfStableID = strings.TrimSpace(client.StableID())
		selfDID = strings.TrimSpace(client.ParticipantDID())
	}
	row := chatParticipantRowFromParticipant(participant)
	return identityutil.MatchesSelfStrict(
		row.Alias,
		row.Address,
		row.StableID,
		row.DID,
		selfAlias,
		selfAddress,
		selfStableID,
		selfDID,
	)
}

func chatParticipantLabel(ctx context.Context, client *awid.Client, participant awid.ChatParticipant) string {
	row := chatParticipantRowFromParticipant(participant)
	if row.Address != "" {
		return row.Address
	}
	if row.StableID != "" {
		return row.StableID
	}
	if row.DID != "" && client != nil {
		if identity, err := client.ResolveIdentity(ctx, row.DID); err == nil && identity != nil {
			if value := strings.TrimSpace(identity.Address); value != "" {
				return value
			}
			if value := strings.TrimSpace(identity.StableID); value != "" {
				return value
			}
			if value := strings.TrimSpace(identity.DID); value != "" {
				return value
			}
		}
	}
	if row.DID != "" {
		return row.DID
	}
	return row.Alias
}

func chatParticipantMatchesTarget(participant awid.ChatParticipant, target string) bool {
	return chatParticipantRowFromParticipant(participant).matchesTarget(target)
}

func chatParticipantMatchesSessionTarget(participant awid.ChatParticipant, target string) bool {
	return chatParticipantRowFromParticipant(participant).matchesSessionTarget(target)
}

func matchingChatParticipantsForEventIdentity(participants []awid.ChatParticipant, ev Event) []awid.ChatParticipant {
	type candidateSpec struct {
		value  string
		strong bool
		kind   string
	}
	hasStrongIdentity := strings.TrimSpace(ev.FromAddress) != "" ||
		strings.TrimSpace(ev.FromStableID) != "" ||
		strings.TrimSpace(ev.FromDID) != ""
	matchParticipants := func(candidate candidateSpec) []awid.ChatParticipant {
		candidate.value = strings.TrimSpace(candidate.value)
		if candidate.value == "" {
			return nil
		}
		matches := []awid.ChatParticipant{}
		if candidate.strong {
			for _, participant := range participants {
				if chatParticipantRowFromParticipant(participant).matchesStrongIdentity(candidate.kind, candidate.value) {
					matches = append(matches, participant)
				}
			}
			return matches
		}
		for _, participant := range participants {
			if chatParticipantMatchesTarget(participant, candidate.value) {
				matches = append(matches, participant)
			}
		}
		return matches
	}

	candidates := []candidateSpec{
		{value: ev.FromAddress, strong: true, kind: "address"},
		{value: ev.FromStableID, strong: true, kind: "did"},
		{value: ev.FromDID, strong: true, kind: "did"},
	}
	if !hasStrongIdentity {
		candidates = append(candidates, candidateSpec{value: ev.FromAgent})
	}
	for _, candidate := range candidates {
		if matches := matchParticipants(candidate); len(matches) > 0 {
			return matches
		}
	}
	return nil
}
