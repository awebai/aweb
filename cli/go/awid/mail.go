package awid

import (
	"context"
	"errors"
	"strings"
)

type MessagePriority string

const (
	PriorityLow    MessagePriority = "low"
	PriorityNormal MessagePriority = "normal"
	PriorityHigh   MessagePriority = "high"
	PriorityUrgent MessagePriority = "urgent"
)

type SendMessageRequest struct {
	ToAgentID      string          `json:"to_agent_id,omitempty"`
	ToAlias        string          `json:"to_alias,omitempty"`
	ToDID          string          `json:"to_did,omitempty"`
	ToStableID     string          `json:"to_stable_id,omitempty"`
	ToAddress      string          `json:"to_address,omitempty"`
	ConversationID string          `json:"conversation_id,omitempty"`
	Subject        string          `json:"subject,omitempty"`
	Body           string          `json:"body"`
	Priority       MessagePriority `json:"priority,omitempty"`
	MessageID      string          `json:"message_id,omitempty"`
	Timestamp      string          `json:"timestamp,omitempty"`
	FromDID        string          `json:"from_did,omitempty"`
	Signature      string          `json:"signature,omitempty"`
	SignedPayload  string          `json:"signed_payload,omitempty"`
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
	if c.signingKey != nil && strings.TrimSpace(payload.ConversationID) == "" && hasRecipient {
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
	from := c.address
	if c.signingKey != nil {
		from = c.signedPayloadFrom(identityTarget, payload.ToAlias != "" && !strings.Contains(payload.ToAlias, "/"))
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From:                    from,
		To:                      to,
		ToDID:                   toDID,
		ToStableID:              toStableID,
		Type:                    "mail",
		Priority:                signedMailPriority(payload.Priority),
		Subject:                 payload.Subject,
		Body:                    payload.Body,
		ConversationID:          strings.TrimSpace(payload.ConversationID),
		RequireRecipientBinding: strings.TrimSpace(payload.ToAddress) != "" && c.requireRecipientBinding,
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

func (c *Client) ListConversations(ctx context.Context, limit int) (*ConversationsResponse, error) {
	path := "/v1/conversations"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
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
		if m.SignedPayload != "" {
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
