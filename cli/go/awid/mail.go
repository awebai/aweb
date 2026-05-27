package awid

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type MessagePriority string

const (
	PriorityLow    MessagePriority = "low"
	PriorityNormal MessagePriority = "normal"
	PriorityHigh   MessagePriority = "high"
	PriorityUrgent MessagePriority = "urgent"

	ContentModeLegacyPlaintextV1 = "legacy_plaintext_v1"
	ContentModeEncryptedV2       = "encrypted_v2"
)

type SendMessageRequest struct {
	ToAgentID      string               `json:"to_agent_id,omitempty"`
	ToAlias        string               `json:"to_alias,omitempty"`
	ToDID          string               `json:"to_did,omitempty"`
	ToStableID     string               `json:"to_stable_id,omitempty"`
	ToAddress      string               `json:"to_address,omitempty"`
	ConversationID string               `json:"conversation_id,omitempty"`
	Subject        string               `json:"subject,omitempty"`
	Body           string               `json:"body"`
	ContentMode    string               `json:"content_mode,omitempty"`
	MessageVersion int                  `json:"message_version,omitempty"`
	Encrypted      *E2EEMessageEnvelope `json:"encrypted_envelope,omitempty"`
	Priority       MessagePriority      `json:"priority,omitempty"`
	MessageID      string               `json:"message_id,omitempty"`
	Timestamp      string               `json:"timestamp,omitempty"`
	FromDID        string               `json:"from_did,omitempty"`
	Signature      string               `json:"signature,omitempty"`
	SignedPayload  string               `json:"signed_payload,omitempty"`
	EncryptE2EE    bool                 `json:"-"`
	E2EERecipient  *E2EERecipientKey    `json:"-"`
}

type SendMessageResponse struct {
	MessageID      string `json:"message_id"`
	ConversationID string `json:"conversation_id,omitempty"`
	Status         string `json:"status"`
	DeliveredAt    string `json:"delivered_at"`
}

func (c *Client) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	return c.sendMessage(ctx, req, false)
}

func (c *Client) SendMessageByIdentity(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	return c.sendMessage(ctx, req, true)
}

func (c *Client) sendMessage(ctx context.Context, req *SendMessageRequest, identityTarget bool) (*SendMessageResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req
	hasRecipient := strings.TrimSpace(payload.ToAlias) != "" ||
		strings.TrimSpace(payload.ToAgentID) != "" ||
		strings.TrimSpace(payload.ToDID) != "" ||
		strings.TrimSpace(payload.ToStableID) != "" ||
		strings.TrimSpace(payload.ToAddress) != ""
	if !hasRecipient && strings.TrimSpace(payload.ConversationID) != "" {
		target, err := c.targetForMailConversation(ctx, strings.TrimSpace(payload.ConversationID), payload.EncryptE2EE)
		if err != nil {
			return nil, err
		}
		switch target.kind {
		case "address":
			payload.ToAddress = target.value
		case "did":
			if strings.HasPrefix(target.value, "did:aw:") {
				payload.ToStableID = target.value
			} else {
				payload.ToDID = target.value
			}
		case "alias":
			payload.ToAlias = target.value
		case "learned_e2ee":
			payload.E2EERecipient = target.recipient
		}
		hasRecipient = strings.TrimSpace(payload.ToAlias) != "" ||
			strings.TrimSpace(payload.ToAgentID) != "" ||
			strings.TrimSpace(payload.ToDID) != "" ||
			strings.TrimSpace(payload.ToStableID) != "" ||
			strings.TrimSpace(payload.ToAddress) != ""
	}
	initialConversationID := strings.TrimSpace(payload.ConversationID)
	if c.signingKey != nil && initialConversationID == "" && hasRecipient {
		conversationID, err := GenerateUUID4()
		if err != nil {
			return nil, err
		}
		payload.ConversationID = conversationID
	}

	to := payload.ToAlias
	if to == "" {
		to = payload.ToAgentID
	}
	toStableID := strings.TrimSpace(payload.ToStableID)
	toDID := strings.TrimSpace(payload.ToDID)
	if toStableID != "" {
		to = toStableID
	} else if toDID != "" {
		to = toDID
	}
	if strings.TrimSpace(payload.ToAddress) != "" {
		to = strings.TrimSpace(payload.ToAddress)
	}
	if payload.EncryptE2EE {
		if err := c.prepareE2EEMail(ctx, &payload, identityTarget, initialConversationID, hasRecipient); err != nil {
			return nil, err
		}
		var out SendMessageResponse
		if err := c.Post(ctx, "/v1/messages", &payload, &out); err != nil {
			return nil, err
		}
		return &out, nil
	}
	from := c.address
	if c.signingKey != nil {
		from = c.signedPayloadFrom(identityTarget, payload.ToAlias != "" && !strings.Contains(payload.ToAlias, "/"))
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From:                          from,
		To:                            to,
		ToDID:                         toDID,
		ToStableID:                    toStableID,
		Type:                          "mail",
		Priority:                      signedMailPriority(payload.Priority),
		Subject:                       payload.Subject,
		Body:                          payload.Body,
		ConversationID:                strings.TrimSpace(payload.ConversationID),
		RequireRecipientBinding:       strings.TrimSpace(payload.ToAddress) != "" && c.requireRecipientBinding,
		AllowStoredRouteGlobalBinding: initialConversationID != "",
	})
	if err != nil {
		return nil, err
	}
	if c.signingKey != nil {
		payload.FromDID = sf.FromDID
		payload.ToDID = sf.ToDID
		payload.ToStableID = sf.ToStableID
		payload.Signature = sf.Signature
		payload.MessageID = sf.MessageID
		payload.Timestamp = sf.Timestamp
		payload.SignedPayload = sf.SignedPayload
	}

	var out SendMessageResponse
	if err := c.Post(ctx, "/v1/messages", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) prepareE2EEMail(ctx context.Context, payload *SendMessageRequest, identityTarget bool, initialConversationID string, hasRecipient bool) error {
	if c == nil || payload == nil {
		return errors.New("aweb: request is required")
	}
	if c.signingKey == nil || strings.TrimSpace(c.did) == "" {
		return errors.New("E2E messaging requires a local self-custodial signing key")
	}
	if c.e2eeEncryptionKey == nil {
		return errors.New("E2E messaging requires a local encryption key; upgrade aw and run `aw id encryption-key setup`, or pass --plaintext only for explicit server-readable messaging")
	}
	recipient, err := c.e2eeMailRecipient(ctx, payload)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	messageID := strings.TrimSpace(payload.MessageID)
	if messageID == "" {
		messageID, err = GenerateUUID4()
		if err != nil {
			return err
		}
	}
	conversationID := strings.TrimSpace(payload.ConversationID)
	if conversationID == "" && initialConversationID == "" && hasRecipient {
		conversationID, err = GenerateUUID4()
		if err != nil {
			return err
		}
		payload.ConversationID = conversationID
	}
	if conversationID == "" {
		return errors.New("E2E mail requires a conversation_id or explicit recipient")
	}
	fromAddress := c.e2eeAddress()
	envelope, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender: E2EESenderKey{
			Address:       fromAddress,
			DID:           c.did,
			StableID:      c.stableID,
			TeamID:        c.teamID,
			EncryptionKey: c.e2eeEncryptionKey,
			SigningKey:    c.signingKey,
		},
		Recipients:          []E2EERecipientKey{recipient},
		Subject:             payload.Subject,
		Body:                payload.Body,
		MessageID:           messageID,
		ConversationID:      conversationID,
		CreatedAt:           now,
		DeliveryOrigin:      recipient.DeliveryOrigin,
		ObservedInboundMode: recipient.InboundMode,
	})
	if err != nil {
		return err
	}
	payload.MessageID = envelope.MessageID
	payload.Timestamp = envelope.CreatedAt
	payload.FromDID = c.did
	payload.ToDID = envelope.Routing.ToDID
	payload.ToStableID = envelope.Routing.ToStableID
	payload.ConversationID = envelope.ConversationID
	payload.ContentMode = ContentModeEncryptedV2
	payload.MessageVersion = E2EEMessageVersion
	payload.Encrypted = envelope
	payload.Subject = ""
	payload.Body = ""
	payload.Signature = ""
	payload.SignedPayload = ""
	return nil
}

func (c *Client) e2eeMailRecipient(ctx context.Context, payload *SendMessageRequest) (E2EERecipientKey, error) {
	if payload.E2EERecipient != nil {
		return *payload.E2EERecipient, nil
	}
	if strings.TrimSpace(payload.ToAlias) != "" || strings.TrimSpace(payload.ToAgentID) != "" {
		agent, err := c.e2eeRecipientAgent(ctx, strings.TrimSpace(payload.ToAgentID), strings.TrimSpace(payload.ToAlias))
		if err != nil {
			return E2EERecipientKey{}, err
		}
		return c.e2eeRecipientFromAgent(ctx, agent)
	}
	target := strings.TrimSpace(payload.ToAddress)
	if target == "" {
		target = strings.TrimSpace(payload.ToStableID)
	}
	if target == "" {
		target = strings.TrimSpace(payload.ToDID)
	}
	if target == "" {
		return E2EERecipientKey{}, errors.New("E2E mail requires an explicit recipient to resolve an encryption key")
	}
	identity, err := c.ResolveIdentity(ctx, target)
	if err != nil {
		return E2EERecipientKey{}, err
	}
	if identity.EncryptionKey == nil {
		return E2EERecipientKey{}, errors.New("recipient has no published E2E encryption key; ask them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or explicitly send a server-readable upgrade note with --plaintext")
	}
	return E2EERecipientKey{
		Address:        strings.TrimSpace(identity.Address),
		DID:            strings.TrimSpace(identity.DID),
		StableID:       strings.TrimSpace(identity.StableID),
		EncryptionKey:  identity.EncryptionKey,
		DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
	}, nil
}

func (c *Client) e2eeRecipientAgent(ctx context.Context, agentID, alias string) (AgentView, error) {
	resp, err := c.ListAgents(ctx)
	if err != nil {
		return AgentView{}, err
	}
	for _, agent := range resp.Agents {
		if strings.TrimSpace(agentID) != "" && strings.TrimSpace(agent.AgentID) == strings.TrimSpace(agentID) {
			return agent, nil
		}
		if strings.TrimSpace(alias) != "" && strings.TrimSpace(agent.Alias) == strings.TrimSpace(alias) {
			return agent, nil
		}
	}
	return AgentView{}, errors.New("recipient agent not found")
}

type mailConversationTarget struct {
	kind      string
	value     string
	recipient *E2EERecipientKey
	err       error
}

func (c *Client) targetForMailConversation(ctx context.Context, conversationID string, preferAddress bool) (mailConversationTarget, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return mailConversationTarget{}, nil
	}
	if resp, err := c.ListConversationsWithParams(ctx, ConversationListParams{
		Limit:            100,
		ConversationType: "mail",
	}); err == nil {
		for _, item := range resp.Conversations {
			if strings.TrimSpace(item.ConversationID) != conversationID {
				continue
			}
			if target := c.mailConversationItemTarget(item, preferAddress); target.err != nil || target.value != "" || target.recipient != nil {
				if target.err != nil {
					return mailConversationTarget{}, target.err
				}
				if preferAddress && target.kind == "did" && strings.HasPrefix(strings.TrimSpace(target.value), "did:key:") {
					break
				}
				return target, nil
			}
			break
		}
	} else if !httpStatusIs(err, http.StatusNotFound) && !httpStatusIs(err, http.StatusUnprocessableEntity) {
		return mailConversationTarget{}, err
	}
	if resp, err := c.MailConversation(ctx, conversationID, 50); err == nil {
		if target := c.mailInboxTarget(resp.Messages, preferAddress); target.err != nil || target.value != "" || target.recipient != nil {
			if target.err != nil {
				return mailConversationTarget{}, target.err
			}
			return target, nil
		}
	} else if !httpStatusIs(err, http.StatusNotFound) && !httpStatusIs(err, http.StatusForbidden) {
		return mailConversationTarget{}, err
	}
	return mailConversationTarget{}, nil
}

func httpStatusIs(err error, status int) bool {
	code, ok := HTTPStatusCode(err)
	return ok && code == status
}

func (c *Client) mailConversationItemTarget(item ConversationItem, preferAddress bool) mailConversationTarget {
	otherDIDs, otherAddresses := OtherConversationParticipants(
		item.ParticipantDIDs,
		item.ParticipantAddresses,
		c.stableID,
		c.did,
		c.address,
	)
	if preferAddress && len(otherDIDs) == 1 && isLocalDIDKey(otherDIDs[0]) {
		return mailConversationTarget{kind: "did", value: otherDIDs[0]}
	}
	if preferAddress && len(otherAddresses) == 1 {
		return mailConversationTarget{kind: "address", value: otherAddresses[0]}
	}
	if preferAddress {
		if value := c.mailConversationAliasTarget(item.Participants); value != "" {
			if !strings.HasPrefix(strings.TrimSpace(value), "did:") {
				return mailConversationTarget{kind: "alias", value: value}
			}
		}
	}
	if len(otherDIDs) == 1 {
		return mailConversationTarget{kind: "did", value: otherDIDs[0]}
	}
	if len(otherAddresses) == 1 {
		return mailConversationTarget{kind: "address", value: otherAddresses[0]}
	}
	if value := c.mailConversationAliasTarget(item.Participants); value != "" {
		if !strings.HasPrefix(strings.TrimSpace(value), "did:") {
			return mailConversationTarget{kind: "alias", value: value}
		}
	}
	return mailConversationTarget{}
}

func (c *Client) mailConversationAliasTarget(participants []string) string {
	selfAlias := c.addressAlias()
	if selfAlias == "" {
		return ""
	}
	return deterministicTargetList(removeOneSelfIdentifier(participants, selfAlias))
}

func (c *Client) mailInboxTarget(messages []InboxMessage, preferAddress bool) mailConversationTarget {
	for _, msg := range messages {
		if preferAddress {
			addressCandidates := []string{msg.FromAddress, msg.ToAddress}
			if msg.Encrypted != nil {
				addressCandidates = []string{msg.Encrypted.From.Address}
				for _, recipient := range msg.Encrypted.Recipients {
					addressCandidates = append(addressCandidates, recipient.Address)
				}
			}
			for _, candidate := range addressCandidates {
				candidate = strings.TrimSpace(candidate)
				if candidate != "" &&
					!strings.EqualFold(candidate, strings.TrimSpace(c.address)) &&
					!strings.EqualFold(candidate, strings.TrimSpace(c.did)) &&
					!strings.EqualFold(candidate, strings.TrimSpace(c.stableID)) {
					return mailConversationTarget{kind: "address", value: candidate}
				}
			}
			if target := c.learnedE2EEMailTarget([]InboxMessage{msg}); target.err != nil || target.recipient != nil {
				return target
			}
			if alias := c.mailInboxAliasTarget(msg); alias != "" {
				if !strings.HasPrefix(strings.TrimSpace(alias), "did:") {
					return mailConversationTarget{kind: "alias", value: alias}
				}
			}
		}
		for _, candidate := range []string{msg.FromStableID, msg.ToStableID, msg.FromDID, msg.ToDID} {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" &&
				!strings.EqualFold(candidate, strings.TrimSpace(c.stableID)) &&
				!strings.EqualFold(candidate, strings.TrimSpace(c.did)) {
				return mailConversationTarget{kind: "did", value: candidate}
			}
		}
		for _, candidate := range []string{msg.FromAddress, msg.ToAddress} {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" && !strings.EqualFold(candidate, strings.TrimSpace(c.address)) {
				return mailConversationTarget{kind: "address", value: candidate}
			}
		}
	}
	return mailConversationTarget{}
}

func (c *Client) learnedE2EEMailTarget(messages []InboxMessage) mailConversationTarget {
	for _, msg := range messages {
		recipient, ok, err := c.learnedE2EERecipientFromEnvelope(msg.Encrypted)
		if err != nil {
			return mailConversationTarget{kind: "learned_e2ee", err: err}
		}
		if !ok {
			continue
		}
		return mailConversationTarget{kind: "learned_e2ee", recipient: &recipient}
	}
	return mailConversationTarget{}
}

func (c *Client) mailInboxAliasTarget(msg InboxMessage) string {
	selfAlias := c.addressAlias()
	if selfAlias == "" {
		return ""
	}
	return deterministicTargetList(removeOneSelfIdentifier([]string{msg.FromAlias, msg.ToAlias}, selfAlias, c.did, c.stableID))
}

type InboxMessage struct {
	MessageID               string                   `json:"message_id"`
	ConversationID          string                   `json:"conversation_id,omitempty"`
	FromAgentID             string                   `json:"from_agent_id"`
	FromAlias               string                   `json:"from_alias"`
	ToAlias                 string                   `json:"to_alias,omitempty"`
	FromAddress             string                   `json:"from_address,omitempty"`
	ToAddress               string                   `json:"to_address,omitempty"`
	Subject                 string                   `json:"subject"`
	Body                    string                   `json:"body"`
	ContentMode             string                   `json:"content_mode,omitempty"`
	MessageVersion          int                      `json:"message_version,omitempty"`
	Encrypted               *E2EEMessageEnvelope     `json:"encrypted_envelope,omitempty"`
	Priority                MessagePriority          `json:"priority"`
	ThreadID                *string                  `json:"thread_id"`
	ReadAt                  *string                  `json:"read_at"`
	CreatedAt               string                   `json:"created_at"`
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

type InboxResponse struct {
	Messages []InboxMessage `json:"messages"`
}

type ConversationItem struct {
	ConversationType     string   `json:"conversation_type"`
	ConversationID       string   `json:"conversation_id,omitempty"`
	LegacyMessageID      string   `json:"legacy_message_id,omitempty"`
	Status               string   `json:"status,omitempty"`
	Participants         []string `json:"participants,omitempty"`
	ParticipantDIDs      []string `json:"participant_dids,omitempty"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	Subject              string   `json:"subject,omitempty"`
	LastMessageAt        string   `json:"last_message_at,omitempty"`
	LastMessageFrom      string   `json:"last_message_from,omitempty"`
	LastMessagePreview   string   `json:"last_message_preview,omitempty"`
	UnreadCount          int      `json:"unread_count,omitempty"`
}

type ConversationsResponse struct {
	Conversations []ConversationItem `json:"conversations"`
	NextCursor    string             `json:"next_cursor,omitempty"`
}

type ConversationListParams struct {
	Limit              int
	Cursor             string
	ConversationType   string
	ParticipantDID     string
	ParticipantAddress string
}

func (c *Client) ListConversations(ctx context.Context, limit int) (*ConversationsResponse, error) {
	return c.ListConversationsWithParams(ctx, ConversationListParams{Limit: limit})
}

func (c *Client) ListConversationsWithParams(ctx context.Context, params ConversationListParams) (*ConversationsResponse, error) {
	path := "/v1/conversations"
	query := make([]string, 0, 5)
	if params.Limit > 0 {
		query = append(query, "limit="+itoa(params.Limit))
	}
	if strings.TrimSpace(params.Cursor) != "" {
		query = append(query, "cursor="+urlQueryEscape(strings.TrimSpace(params.Cursor)))
	}
	if strings.TrimSpace(params.ConversationType) != "" {
		query = append(query, "conversation_type="+urlQueryEscape(strings.TrimSpace(params.ConversationType)))
	}
	if strings.TrimSpace(params.ParticipantDID) != "" {
		query = append(query, "participant_did="+urlQueryEscape(strings.TrimSpace(params.ParticipantDID)))
	}
	if strings.TrimSpace(params.ParticipantAddress) != "" {
		query = append(query, "participant_address="+urlQueryEscape(strings.TrimSpace(params.ParticipantAddress)))
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}
	var out ConversationsResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type InboxParams struct {
	UnreadOnly bool
	Limit      int
	MessageID  string
}

func (c *Client) MailConversation(ctx context.Context, conversationID string, limit int) (*InboxResponse, error) {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil, errors.New("aweb: conversation_id is required")
	}
	path := "/v1/messages/conversations/" + urlPathEscape(conversationID)
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	var out InboxResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return c.normalizeInboxResponse(ctx, &out)
}

func (c *Client) Inbox(ctx context.Context, p InboxParams) (*InboxResponse, error) {
	path := "/v1/messages/inbox"
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
		sep = "&"
	}
	var out InboxResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return c.normalizeInboxResponse(ctx, &out)
}

func (c *Client) normalizeInboxResponse(ctx context.Context, out *InboxResponse) (*InboxResponse, error) {
	if out == nil {
		return out, nil
	}
	for i := range out.Messages {
		m := &out.Messages[i]
		if m.ContentMode == ContentModeEncryptedV2 || m.MessageVersion == E2EEMessageVersion || m.Encrypted != nil {
			if m.Encrypted == nil {
				return nil, errors.New("encrypted mail response is missing encrypted envelope")
			}
			plain, err := c.DecryptE2EEEnvelope(m.Encrypted)
			if err != nil {
				return nil, err
			}
			m.Subject = plain.Subject
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
		from := m.FromAlias
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
			to := m.ToAlias
			if m.ToAddress != "" {
				to = m.ToAddress
			}
			env := &MessageEnvelope{
				From:           from,
				FromDID:        m.FromDID,
				To:             to,
				ToDID:          m.ToDID,
				Type:           "mail",
				Priority:       signedMailPriority(m.Priority),
				Subject:        m.Subject,
				Body:           m.Body,
				Timestamp:      m.CreatedAt,
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
		m.VerificationStatus = c.checkRecipientBinding(m.VerificationStatus, m.ToDID, m.ToStableID)
		m.VerificationStatus, m.IsContact = c.NormalizeSenderTrust(ctx, m.VerificationStatus, from, m.FromDID, m.FromStableID, m.RotationAnnouncement, m.ReplacementAnnouncement, m.IsContact)
	}
	return out, nil
}

// signedMailPriority normalizes "" and "normal" to the same empty signed value.
// Any verifier that reconstructs a mail envelope from display fields must apply
// the exact same normalization or signature verification will drift.
func signedMailPriority(priority MessagePriority) string {
	switch priority {
	case "", PriorityNormal:
		return ""
	default:
		return string(priority)
	}
}

type AckResponse struct {
	MessageID      string `json:"message_id"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

func (c *Client) AckMessage(ctx context.Context, messageID string) (*AckResponse, error) {
	var out AckResponse
	if err := c.Post(ctx, "/v1/messages/"+urlPathEscape(messageID)+"/ack", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
