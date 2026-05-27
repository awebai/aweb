package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (c *Client) namespaceSlug() string {
	parts := strings.SplitN(c.address, "/", 2)
	if len(parts) == 2 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func (c *Client) toAddressForAliases(aliases []string) string {
	return deterministicTargetList(aliases)
}

func deterministicTargetList(values []string) string {
	if len(values) == 0 {
		return ""
	}
	clean := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	sort.Strings(clean)
	var b strings.Builder
	for i, value := range clean {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(value)
	}
	return b.String()
}

func removeOneSelfIdentifier(values []string, selfIDs ...string) []string {
	if len(values) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(values))
	removedSelf := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !removedSelf {
			for _, selfID := range selfIDs {
				selfID = strings.TrimSpace(selfID)
				if selfID != "" && strings.EqualFold(value, selfID) {
					removedSelf = true
					value = ""
					break
				}
			}
		}
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func (c *Client) toAddressForSession(ctx context.Context, sessionID string, preferAddress bool) (string, error) {
	if sessionID == "" {
		return "", nil
	}
	resp, err := c.ChatListSessions(ctx)
	if err != nil {
		return "", err
	}
	for _, s := range resp.Sessions {
		if s.SessionID != sessionID {
			continue
		}
		otherDIDs, otherAddresses := OtherConversationParticipants(
			s.ParticipantDIDs,
			s.ParticipantAddresses,
			c.stableID,
			c.did,
			c.address,
		)
		if preferAddress {
			if len(otherDIDs) == 1 && isLocalDIDKey(otherDIDs[0]) {
				return otherDIDs[0], nil
			}
			if toAddr := c.toAddressForAliases(otherAddresses); toAddr != "" {
				return toAddr, nil
			}
			if selfAlias := c.addressAlias(); selfAlias != "" {
				if toAlias := c.toAddressForAliases(removeOneSelfIdentifier(s.Participants, selfAlias)); toAlias != "" {
					return toAlias, nil
				}
			}
		}
		if len(otherDIDs) == 1 {
			return otherDIDs[0], nil
		}
		if toAddr := c.toAddressForAliases(otherAddresses); toAddr != "" {
			return toAddr, nil
		}
		selfAlias := c.addressAlias()
		if selfAlias == "" {
			return "", nil
		}
		others := make([]string, 0, len(s.Participants))
		removedSelf := false
		for _, a := range s.Participants {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if a == selfAlias && !removedSelf {
				removedSelf = true
				continue
			}
			others = append(others, a)
		}
		sort.Strings(others)
		return c.toAddressForAliases(others), nil
	}
	return "", nil
}

// OtherConversationParticipants removes the caller's single participant row
// from paired DID/address participant lists and returns the remaining values.
func OtherConversationParticipants(participantDIDs, participantAddresses []string, selfStableID, selfDID, selfAddress string) ([]string, []string) {
	selfDIDs := []string{selfStableID, selfDID}
	selfAddress = strings.TrimSpace(selfAddress)
	maxLen := len(participantDIDs)
	if len(participantAddresses) > maxLen {
		maxLen = len(participantAddresses)
	}
	otherDIDs := make([]string, 0, len(participantDIDs))
	otherAddresses := make([]string, 0, len(participantAddresses))
	removedSelf := false
	for i := 0; i < maxLen; i++ {
		did := ""
		if i < len(participantDIDs) {
			did = strings.TrimSpace(participantDIDs[i])
		}
		address := ""
		if i < len(participantAddresses) {
			address = strings.TrimSpace(participantAddresses[i])
		}
		isSelf := false
		if !removedSelf && selfAddress != "" && address != "" && strings.EqualFold(address, selfAddress) {
			isSelf = true
		}
		if !removedSelf && !isSelf {
			for _, selfDID := range selfDIDs {
				selfDID = strings.TrimSpace(selfDID)
				if selfDID != "" && did != "" && strings.EqualFold(did, selfDID) {
					isSelf = true
					break
				}
			}
		}
		if isSelf {
			removedSelf = true
			continue
		}
		if did != "" {
			otherDIDs = append(otherDIDs, did)
		}
		if address != "" {
			otherAddresses = append(otherAddresses, address)
		}
	}
	return otherDIDs, otherAddresses
}

type ChatCreateSessionRequest struct {
	SessionID      string               `json:"session_id,omitempty"`
	ToAliases      []string             `json:"to_aliases,omitempty"`
	ToDIDs         []string             `json:"to_dids,omitempty"`
	ToAddresses    []string             `json:"to_addresses,omitempty"`
	Message        string               `json:"message"`
	ContentMode    string               `json:"content_mode,omitempty"`
	MessageVersion int                  `json:"message_version,omitempty"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	Leaving        bool                 `json:"leaving,omitempty"`
	WaitSeconds    *int                 `json:"wait_seconds,omitempty"`
	ReplyTo        string               `json:"reply_to,omitempty"`
	FromDID        string               `json:"from_did,omitempty"`
	Signature      string               `json:"signature,omitempty"`
	Timestamp      string               `json:"timestamp,omitempty"`
	MessageID      string               `json:"message_id,omitempty"`
	SignedPayload  string               `json:"signed_payload,omitempty"`
	EncryptE2EE    bool                 `json:"-"`
}

type ChatCreateSessionResponse struct {
	SessionID        string            `json:"session_id"`
	MessageID        string            `json:"message_id"`
	Participants     []ChatParticipant `json:"participants"`
	SSEURL           string            `json:"sse_url"`
	TargetsConnected []string          `json:"targets_connected"`
	TargetsLeft      []string          `json:"targets_left"`
}

type ChatParticipant struct {
	AgentID string `json:"agent_id"`
	Alias   string `json:"alias"`
	DID     string `json:"did,omitempty"`
	Address string `json:"address,omitempty"`
}

func (c *Client) ChatCreateSession(ctx context.Context, req *ChatCreateSessionRequest) (*ChatCreateSessionResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req
	if c.signingKey != nil && strings.TrimSpace(payload.SessionID) == "" {
		sessionID, err := GenerateUUID4()
		if err != nil {
			return nil, err
		}
		payload.SessionID = sessionID
	}
	if payload.EncryptE2EE {
		if err := c.prepareE2EEChatCreate(ctx, &payload); err != nil {
			return nil, err
		}
		var out ChatCreateSessionResponse
		if err := c.Post(ctx, "/v1/chat/sessions", &payload, &out); err != nil {
			return nil, err
		}
		return &out, nil
	}

	to := strings.Join(payload.ToAliases, ",")
	directIdentityTargets := len(payload.ToDIDs) > 0 || len(payload.ToAddresses) > 0
	if len(payload.ToDIDs) > 0 {
		targets := append([]string(nil), payload.ToDIDs...)
		sort.Strings(targets)
		to = strings.Join(targets, ",")
	} else if len(payload.ToAddresses) > 0 {
		targets := append([]string(nil), payload.ToAddresses...)
		sort.Strings(targets)
		to = strings.Join(targets, ",")
	}
	from := c.address
	if c.signingKey != nil {
		if len(payload.ToAddresses) > 0 {
			targets := append([]string(nil), payload.ToAddresses...)
			sort.Strings(targets)
			to = strings.Join(targets, ",")
		} else if toAddr := c.toAddressForAliases(payload.ToAliases); toAddr != "" {
			to = toAddr
		}
		from = c.signedPayloadFrom(false, !directIdentityTargets)
	}
	env := &MessageEnvelope{
		From:                    from,
		To:                      to,
		Type:                    "chat",
		Body:                    payload.Message,
		ConversationID:          strings.TrimSpace(payload.SessionID),
		WaitSeconds:             payload.WaitSeconds,
		ReplyTo:                 payload.ReplyTo,
		SenderLeaving:           payload.Leaving,
		RequireRecipientBinding: len(payload.ToAddresses) == 1 && c.requireRecipientBinding,
	}
	if len(payload.ToDIDs) == 1 {
		env.ToDID = strings.TrimSpace(payload.ToDIDs[0])
	}
	sf, err := c.signEnvelope(ctx, env)
	if err != nil {
		return nil, err
	}
	if c.signingKey != nil {
		payload.FromDID = sf.FromDID
		payload.Signature = sf.Signature
		payload.Timestamp = sf.Timestamp
		payload.MessageID = sf.MessageID
		payload.SignedPayload = sf.SignedPayload
	}

	var out ChatCreateSessionResponse
	if err := c.Post(ctx, "/v1/chat/sessions", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) prepareE2EEChatCreate(ctx context.Context, payload *ChatCreateSessionRequest) error {
	if c == nil || payload == nil {
		return errors.New("aweb: request is required")
	}
	if c.signingKey == nil || strings.TrimSpace(c.did) == "" {
		return errors.New("E2E messaging requires a local self-custodial signing key")
	}
	if c.e2eeEncryptionKey == nil {
		return errors.New("E2E messaging requires a local encryption key; upgrade aw and run `aw id encryption-key setup`, or pass --plaintext only for explicit server-readable messaging")
	}
	recipients, err := c.e2eeChatRecipients(ctx, payload.ToAliases, payload.ToDIDs, payload.ToAddresses)
	if err != nil {
		return err
	}
	messageID, err := GenerateUUID4()
	if err != nil {
		return err
	}
	if strings.TrimSpace(payload.MessageID) != "" {
		messageID = strings.TrimSpace(payload.MessageID)
	}
	sessionID := strings.TrimSpace(payload.SessionID)
	if sessionID == "" {
		sessionID, err = GenerateUUID4()
		if err != nil {
			return err
		}
		payload.SessionID = sessionID
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := EncryptE2EEChat(E2EEEncryptMessageParams{
		Sender: E2EESenderKey{
			Address:       c.e2eeAddress(),
			DID:           c.did,
			StableID:      c.stableID,
			TeamID:        c.teamID,
			EncryptionKey: c.e2eeEncryptionKey,
			SigningKey:    c.signingKey,
		},
		Recipients:       recipients,
		Body:             payload.Message,
		MessageID:        messageID,
		ConversationID:   sessionID,
		ReplyToMessageID: payload.ReplyTo,
		CreatedAt:        now,
	})
	if err != nil {
		return err
	}
	payload.MessageID = envelope.MessageID
	payload.Timestamp = envelope.CreatedAt
	payload.FromDID = c.did
	payload.ContentMode = ContentModeEncryptedV2
	payload.MessageVersion = E2EEMessageVersion
	payload.Encrypted = envelope
	payload.Message = ""
	payload.Signature = ""
	payload.SignedPayload = ""
	return nil
}

func (c *Client) prepareE2EEChatSend(ctx context.Context, sessionID string, payload *ChatSendMessageRequest) error {
	if c == nil || payload == nil {
		return errors.New("aweb: request is required")
	}
	if c.signingKey == nil || strings.TrimSpace(c.did) == "" {
		return errors.New("E2E messaging requires a local self-custodial signing key")
	}
	if c.e2eeEncryptionKey == nil {
		return errors.New("E2E messaging requires a local encryption key; upgrade aw and run `aw id encryption-key setup`, or pass --plaintext only for explicit server-readable messaging")
	}
	recipients, err := c.e2eeChatRecipientsForSession(ctx, sessionID)
	if err != nil {
		return err
	}
	messageID, err := GenerateUUID4()
	if err != nil {
		return err
	}
	if strings.TrimSpace(payload.MessageID) != "" {
		messageID = strings.TrimSpace(payload.MessageID)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := EncryptE2EEChat(E2EEEncryptMessageParams{
		Sender: E2EESenderKey{
			Address:       c.e2eeAddress(),
			DID:           c.did,
			StableID:      c.stableID,
			TeamID:        c.teamID,
			EncryptionKey: c.e2eeEncryptionKey,
			SigningKey:    c.signingKey,
		},
		Recipients:       recipients,
		Body:             payload.Body,
		MessageID:        messageID,
		ConversationID:   strings.TrimSpace(sessionID),
		ReplyToMessageID: payload.ReplyTo,
		CreatedAt:        now,
	})
	if err != nil {
		return err
	}
	payload.MessageID = envelope.MessageID
	payload.Timestamp = envelope.CreatedAt
	payload.FromDID = c.did
	payload.ContentMode = ContentModeEncryptedV2
	payload.MessageVersion = E2EEMessageVersion
	payload.Encrypted = envelope
	payload.Body = ""
	payload.Signature = ""
	payload.SignedPayload = ""
	return nil
}

func (c *Client) e2eeChatRecipientsForSession(ctx context.Context, sessionID string) ([]E2EERecipientKey, error) {
	to, err := c.toAddressForSession(ctx, sessionID, true)
	if err != nil {
		return nil, err
	}
	aliases, dids, addresses := classifyE2EEChatTargets(to)
	if len(addresses) > 0 || len(aliases) > 0 || hasGlobalDIDTarget(dids) {
		return c.e2eeChatRecipients(ctx, aliases, dids, addresses)
	}
	if len(dids) > 0 {
		if recipients, ok, err := c.learnedE2EEChatRecipients(ctx, sessionID); err != nil {
			return nil, err
		} else if ok {
			return recipients, nil
		}
	}
	return c.e2eeChatRecipients(ctx, aliases, dids, addresses)
}

func hasGlobalDIDTarget(dids []string) bool {
	for _, did := range dids {
		if strings.HasPrefix(strings.TrimSpace(did), "did:aw:") {
			return true
		}
	}
	return false
}

func isLocalDIDKey(did string) bool {
	return strings.HasPrefix(strings.TrimSpace(did), "did:key:")
}

func (c *Client) learnedE2EEChatRecipients(ctx context.Context, sessionID string) ([]E2EERecipientKey, bool, error) {
	history, err := c.ChatHistory(ctx, ChatHistoryParams{SessionID: sessionID, Limit: 50})
	if err != nil {
		return nil, false, err
	}
	recipients := make([]E2EERecipientKey, 0, 1)
	seen := map[string]bool{}
	for _, msg := range history.Messages {
		recipient, ok, err := c.learnedE2EERecipientFromEnvelope(msg.Encrypted)
		if err != nil {
			return nil, true, err
		}
		if !ok {
			continue
		}
		key := strings.TrimSpace(recipient.DID)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		recipients = append(recipients, recipient)
	}
	if len(recipients) == 0 {
		return nil, false, nil
	}
	return recipients, true, nil
}

func (c *Client) learnedE2EEChatRecipientForDID(ctx context.Context, did string) (E2EERecipientKey, bool, error) {
	did = strings.TrimSpace(did)
	if !isLocalDIDKey(did) {
		return E2EERecipientKey{}, false, nil
	}
	resp, err := c.ChatListSessions(ctx)
	if err != nil {
		return E2EERecipientKey{}, false, err
	}
	for _, session := range resp.Sessions {
		if !stringSliceContainsFold(session.ParticipantDIDs, did) {
			continue
		}
		recipients, ok, err := c.learnedE2EEChatRecipients(ctx, session.SessionID)
		if err != nil {
			return E2EERecipientKey{}, true, err
		}
		if !ok {
			continue
		}
		for _, recipient := range recipients {
			if strings.EqualFold(strings.TrimSpace(recipient.DID), did) {
				return recipient, true, nil
			}
		}
	}
	return E2EERecipientKey{}, false, nil
}

func stringSliceContainsFold(values []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func classifyE2EEChatTargets(targetList string) (aliases []string, dids []string, addresses []string) {
	for _, raw := range strings.Split(targetList, ",") {
		target := strings.TrimSpace(raw)
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

func (c *Client) e2eeChatRecipients(ctx context.Context, aliases []string, dids []string, addresses []string) ([]E2EERecipientKey, error) {
	recipients := make([]E2EERecipientKey, 0, len(aliases)+len(dids)+len(addresses))
	if len(aliases) > 0 {
		resp, err := c.ListAgents(ctx)
		if err != nil {
			return nil, err
		}
		agentsByAlias := map[string]AgentView{}
		for _, agent := range resp.Agents {
			agentsByAlias[strings.TrimSpace(agent.Alias)] = agent
		}
		for _, alias := range aliases {
			agent, ok := agentsByAlias[strings.TrimSpace(alias)]
			if !ok {
				return nil, fmt.Errorf("recipient agent not found: %s", alias)
			}
			recipient, err := c.e2eeRecipientFromAgent(ctx, agent)
			if err != nil {
				return nil, err
			}
			recipients = append(recipients, recipient)
		}
	}
	for _, target := range addresses {
		identity, err := c.ResolveIdentity(ctx, target)
		if err != nil {
			return nil, err
		}
		if identity.EncryptionKey == nil {
			return nil, errors.New("recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext")
		}
		recipients = append(recipients, E2EERecipientKey{
			Address:        strings.TrimSpace(identity.Address),
			DID:            strings.TrimSpace(identity.DID),
			StableID:       strings.TrimSpace(identity.StableID),
			EncryptionKey:  identity.EncryptionKey,
			DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		})
	}
	for _, target := range dids {
		identity, err := c.ResolveIdentity(ctx, target)
		if err != nil {
			return nil, err
		}
		if identity.EncryptionKey == nil {
			if recipient, ok, err := c.learnedE2EEChatRecipientForDID(ctx, target); err != nil {
				return nil, err
			} else if ok {
				recipients = append(recipients, recipient)
				continue
			}
			return nil, errors.New("recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext")
		}
		recipients = append(recipients, E2EERecipientKey{
			Address:        strings.TrimSpace(identity.Address),
			DID:            strings.TrimSpace(identity.DID),
			StableID:       strings.TrimSpace(identity.StableID),
			EncryptionKey:  identity.EncryptionKey,
			DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		})
	}
	if len(recipients) == 0 {
		return nil, errors.New("E2E chat requires at least one recipient")
	}
	return recipients, nil
}

type ChatPendingResponse struct {
	Pending         []ChatPendingItem `json:"pending"`
	MessagesWaiting int               `json:"messages_waiting"`
}

type ChatPendingItem struct {
	SessionID              string               `json:"session_id"`
	TeamID                 string               `json:"team_id,omitempty"`
	Participants           []string             `json:"participants"`
	ParticipantDIDs        []string             `json:"participant_dids,omitempty"`
	ParticipantAddresses   []string             `json:"participant_addresses,omitempty"`
	LastMessage            string               `json:"last_message"`
	LastMessageContentMode string               `json:"last_message_content_mode,omitempty"`
	LastMessageVersion     int                  `json:"last_message_version,omitempty"`
	LastEncrypted          *E2EEMessageEnvelope `json:"last_encrypted_envelope,omitempty"`
	LastFrom               string               `json:"last_from"`
	LastFromStableID       string               `json:"last_from_stable_id,omitempty"`
	LastFromDID            string               `json:"last_from_did,omitempty"`
	LastFromAddress        string               `json:"last_from_address,omitempty"`
	UnreadCount            int                  `json:"unread_count"`
	LastActivity           string               `json:"last_activity"`
	SenderWaiting          bool                 `json:"sender_waiting"`
	TimeRemainingSeconds   *int                 `json:"time_remaining_seconds"`
}

func (c *Client) ChatPending(ctx context.Context) (*ChatPendingResponse, error) {
	var out ChatPendingResponse
	if err := c.Get(ctx, "/v1/chat/pending", &out); err != nil {
		return nil, err
	}
	for i := range out.Pending {
		item := &out.Pending[i]
		if item.LastMessageContentMode == ContentModeEncryptedV2 || item.LastMessageVersion == E2EEMessageVersion || item.LastEncrypted != nil {
			if item.LastEncrypted == nil {
				return nil, errors.New("encrypted chat pending response is missing encrypted envelope")
			}
			plain, err := c.DecryptE2EEEnvelope(item.LastEncrypted)
			if err != nil {
				return nil, err
			}
			item.LastMessage = plain.Body
		}
	}
	return &out, nil
}

type ChatHistoryResponse struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	MessageID               string                   `json:"message_id"`
	ConversationID          string                   `json:"conversation_id,omitempty"`
	FromAgent               string                   `json:"from_agent"`
	FromAddress             string                   `json:"from_address,omitempty"`
	ToAddress               string                   `json:"to_address,omitempty"`
	Body                    string                   `json:"body"`
	ContentMode             string                   `json:"content_mode,omitempty"`
	MessageVersion          int                      `json:"message_version,omitempty"`
	Encrypted               *E2EEMessageEnvelope     `json:"encrypted_envelope,omitempty"`
	Timestamp               string                   `json:"timestamp"`
	SenderLeaving           bool                     `json:"sender_leaving"`
	ReplyToMessageID        string                   `json:"reply_to_message_id,omitempty"`
	FromDID                 string                   `json:"from_did,omitempty"`
	ToDID                   string                   `json:"to_did,omitempty"`
	FromStableID            string                   `json:"from_stable_id,omitempty"`
	ToStableID              string                   `json:"to_stable_id,omitempty"`
	Signature               string                   `json:"signature,omitempty"`
	SigningKeyID            string                   `json:"signing_key_id,omitempty"`
	SignedPayload           string                   `json:"signed_payload,omitempty"`
	RotationAnnouncement    *RotationAnnouncement    `json:"rotation_announcement,omitempty"`
	ReplacementAnnouncement *ReplacementAnnouncement `json:"replacement_announcement,omitempty"`
	VerificationStatus      VerificationStatus       `json:"verification_status,omitempty"`
	IsContact               *bool                    `json:"is_contact,omitempty"`
}

type ChatHistoryParams struct {
	SessionID  string
	MessageID  string
	UnreadOnly bool
	Limit      int
}

func (c *Client) ChatHistory(ctx context.Context, p ChatHistoryParams) (*ChatHistoryResponse, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(p.SessionID) + "/messages"
	sep := "?"
	if p.UnreadOnly {
		path += sep + "unread_only=true"
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
		sep = "&"
	}
	if strings.TrimSpace(p.MessageID) != "" {
		path += sep + "message_id=" + urlQueryEscape(strings.TrimSpace(p.MessageID))
	}
	var out ChatHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		if m.ContentMode == ContentModeEncryptedV2 || m.MessageVersion == E2EEMessageVersion || m.Encrypted != nil {
			if m.Encrypted == nil {
				return nil, errors.New("encrypted chat response is missing encrypted envelope")
			}
			plain, err := c.DecryptE2EEEnvelope(m.Encrypted)
			if err != nil {
				return nil, err
			}
			m.Body = plain.Body
			m.VerificationStatus = Verified
		}
		if meta, ok := parseSignedEnvelopeMetadata(m.SignedPayload); ok {
			if meta.FromDID != "" {
				m.FromDID = meta.FromDID
			}
			if meta.ToDID != "" {
				m.ToDID = meta.ToDID
			}
			if m.FromStableID == "" {
				m.FromStableID = meta.FromStableID
			}
			if m.ToStableID == "" {
				m.ToStableID = meta.ToStableID
			}
			if m.FromAddress == "" && meta.From != "" {
				m.FromAddress = meta.From
			}
			if m.ToAddress == "" && meta.To != "" {
				m.ToAddress = meta.To
			}
		}
		from := m.FromAgent
		if m.FromAddress != "" {
			from = m.FromAddress
		}
		if m.ContentMode == ContentModeEncryptedV2 {
			// The v2 envelope signature was verified before decrypting above.
		} else if m.SignedPayload != "" {
			m.VerificationStatus, _ = VerifySignedPayload(m.SignedPayload, m.Signature, m.FromDID, m.SigningKeyID)
			if m.VerificationStatus == Verified {
				m.VerificationStatus = SignedPayloadConversationStatus(m.SignedPayload, m.ConversationID)
			}
		} else {
			to := ""
			if m.ToAddress != "" {
				to = m.ToAddress
			}
			env := &MessageEnvelope{
				From:           from,
				FromDID:        m.FromDID,
				To:             to,
				ToDID:          m.ToDID,
				Type:           "chat",
				Body:           m.Body,
				Timestamp:      m.Timestamp,
				FromStableID:   m.FromStableID,
				ToStableID:     m.ToStableID,
				MessageID:      m.MessageID,
				ConversationID: m.ConversationID,
				Signature:      m.Signature,
				SigningKeyID:   m.SigningKeyID,
			}
			m.VerificationStatus, _ = VerifyMessage(env)
			if m.VerificationStatus == Failed && m.ConversationID != "" {
				env.ConversationID = ""
				legacyStatus, _ := VerifyMessage(env)
				if legacyStatus == Verified {
					m.VerificationStatus = VerifiedLegacy
				}
			}
		}
		m.VerificationStatus, m.IsContact = c.NormalizeSenderTrust(ctx, m.VerificationStatus, from, m.FromDID, m.FromStableID, m.RotationAnnouncement, m.ReplacementAnnouncement, m.IsContact)
	}
	return &out, nil
}

type ChatMarkReadRequest struct {
	UpToMessageID string `json:"up_to_message_id"`
}

type ChatMarkReadResponse struct {
	Success        bool `json:"success"`
	MessagesMarked int  `json:"messages_marked"`
}

func (c *Client) ChatMarkRead(ctx context.Context, sessionID string, req *ChatMarkReadRequest) (*ChatMarkReadResponse, error) {
	var out ChatMarkReadResponse
	if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/read", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatStream opens an SSE stream for a session.
//
// deadline is required by the aweb API and must be a future time.
// after controls replay: if non-nil, the server replays only messages created after
// that timestamp; if nil, no replay (server polls from now).
// Uses a dedicated HTTP client without response timeout since SSE connections are long-lived.
func (c *Client) ChatStream(ctx context.Context, sessionID string, deadline time.Time, after *time.Time) (*SSEStream, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(sessionID) + "/stream?deadline=" + urlQueryEscape(deadline.UTC().Format(time.RFC3339Nano))
	if after != nil && !after.IsZero() {
		// Truncate to second precision so the server replay query
		// (WHERE created_at > $after) always includes our sent message.
		// The signed timestamp uses RFC3339 (second precision), but sentAt
		// has nanosecond precision — without truncation the sent message
		// falls before the after boundary and is excluded from the replay.
		// Subtract one second to handle the > (not >=) query and the case
		// where sentAt and the signed timestamp land in the same second.
		path += "&after=" + urlQueryEscape(after.Truncate(time.Second).Add(-time.Second).UTC().Format(time.RFC3339))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if c.teamCertHeader != "" && c.signingKey != nil {
		// Certificate auth: same DIDKey + cert headers as regular requests.
		timestamp := time.Now().UTC().Format(time.RFC3339)
		signPayload := certAuthSignPayload(c.teamID, timestamp, nil)
		sig := ed25519.Sign(c.signingKey, signPayload)
		req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(sig)))
		req.Header.Set("X-AWEB-Timestamp", timestamp)
		req.Header.Set("X-AWID-Team-Certificate", c.teamCertHeader)
	} else if c.signingKey != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		signPayload := identityAuthSignPayload(c.stableID, timestamp, nil)
		sig := ed25519.Sign(c.signingKey, signPayload)
		req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(sig)))
		req.Header.Set("X-AWEB-Timestamp", timestamp)
		if c.stableID != "" {
			req.Header.Set("X-AWEB-DID-AW", c.stableID)
		}
	}

	resp, err := c.sseClient.Do(req)
	if err != nil {
		return nil, err
	}
	if v := resp.Header.Get("X-Latest-Client-Version"); v != "" {
		c.latestClientVersion.Store(v)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return NewSSEStream(resp.Body), nil
}

// ChatSendMessage sends a message in an existing chat session.
type ChatSendMessageRequest struct {
	Body           string               `json:"body"`
	ContentMode    string               `json:"content_mode,omitempty"`
	MessageVersion int                  `json:"message_version,omitempty"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	Leaving        bool                 `json:"leaving,omitempty"`
	ExtendWait     bool                 `json:"hang_on,omitempty"`
	ReplyTo        string               `json:"reply_to,omitempty"`
	FromDID        string               `json:"from_did,omitempty"`
	Signature      string               `json:"signature,omitempty"`
	Timestamp      string               `json:"timestamp,omitempty"`
	MessageID      string               `json:"message_id,omitempty"`
	SignedPayload  string               `json:"signed_payload,omitempty"`
	EncryptE2EE    bool                 `json:"-"`
}

type ChatSendMessageResponse struct {
	MessageID          string `json:"message_id"`
	Delivered          bool   `json:"delivered"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

func (c *Client) ChatSendMessage(ctx context.Context, sessionID string, req *ChatSendMessageRequest) (*ChatSendMessageResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req
	if payload.EncryptE2EE {
		if err := c.prepareE2EEChatSend(ctx, sessionID, &payload); err != nil {
			return nil, err
		}
		var out ChatSendMessageResponse
		if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", &payload, &out); err != nil {
			return nil, err
		}
		return &out, nil
	}

	// In-session messages: include deterministic To for signature verification.
	// (aweb returns to_address for reconstruction; we sign the same value.)
	to := ""
	from := c.address
	targetIsAddress := false
	if c.signingKey != nil {
		if toAddr, err := c.toAddressForSession(ctx, sessionID, false); err == nil {
			to = toAddr
		}
		targetIsAddress = isRoutableAddressTarget(to) && !strings.Contains(to, ",")
		targetIsIdentity := strings.HasPrefix(strings.TrimSpace(to), "did:")
		// In-session continuations may be relayed through federation using the
		// stored participant route. Sign the full address so the remote envelope
		// sender_address can be verified even when the recipient target is a
		// stable did:aw rather than an address.
		from = c.signedPayloadFrom(false, !(targetIsAddress || targetIsIdentity))
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From:                          from,
		To:                            to,
		Type:                          "chat",
		Body:                          payload.Body,
		ConversationID:                strings.TrimSpace(sessionID),
		ReplyTo:                       payload.ReplyTo,
		SenderLeaving:                 payload.Leaving,
		HangOn:                        payload.ExtendWait,
		RequireRecipientBinding:       targetIsAddress && c.requireRecipientBinding,
		AllowStoredRouteGlobalBinding: true,
	})
	if err != nil {
		return nil, err
	}
	if c.signingKey != nil {
		payload.FromDID = sf.FromDID
		payload.Signature = sf.Signature
		payload.Timestamp = sf.Timestamp
		payload.MessageID = sf.MessageID
		payload.SignedPayload = sf.SignedPayload
	}

	var out ChatSendMessageResponse
	if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatListSessions lists chat sessions the authenticated agent participates in.
type ChatSessionItem struct {
	SessionID            string   `json:"session_id"`
	TeamID               string   `json:"team_id,omitempty"`
	Participants         []string `json:"participants"`
	ParticipantDIDs      []string `json:"participant_dids,omitempty"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	CreatedAt            string   `json:"created_at"`
	LastActivity         string   `json:"last_activity,omitempty"`
	SenderWaiting        bool     `json:"sender_waiting,omitempty"`
}

type ChatListSessionsResponse struct {
	Sessions []ChatSessionItem `json:"sessions"`
}

func (c *Client) ChatListSessions(ctx context.Context) (*ChatListSessionsResponse, error) {
	var out ChatListSessionsResponse
	if err := c.Get(ctx, "/v1/chat/sessions", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
