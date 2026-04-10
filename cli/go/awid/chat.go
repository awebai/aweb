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

func (c *Client) alias() string {
	parts := strings.SplitN(c.address, "/", 2)
	if len(parts) == 2 && parts[1] != "" {
		return parts[1]
	}
	return ""
}

func (c *Client) toAddressForAliases(aliases []string) string {
	if len(aliases) == 0 {
		return ""
	}
	clean := make([]string, 0, len(aliases))
	for _, a := range aliases {
		a = strings.TrimSpace(a)
		if a != "" {
			clean = append(clean, a)
		}
	}
	if len(clean) == 0 {
		return ""
	}
	sort.Strings(clean)
	var b strings.Builder
	for i, a := range clean {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(a)
	}
	return b.String()
}

func (c *Client) toAddressForSession(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", nil
	}
	selfAlias := c.alias()
	if selfAlias == "" {
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
		others := make([]string, 0, len(s.Participants))
		for _, a := range s.Participants {
			if a != "" && a != selfAlias {
				others = append(others, a)
			}
		}
		sort.Strings(others)
		return c.toAddressForAliases(others), nil
	}
	return "", nil
}

type ChatCreateSessionRequest struct {
	ToAliases     []string `json:"to_aliases"`
	ToDIDs        []string `json:"to_dids,omitempty"`
	ToAddresses   []string `json:"to_addresses,omitempty"`
	Message       string   `json:"message"`
	Leaving       bool     `json:"leaving,omitempty"`
	WaitSeconds   *int     `json:"wait_seconds,omitempty"`
	ReplyTo       string   `json:"reply_to,omitempty"`
	FromDID       string   `json:"from_did,omitempty"`
	Signature     string   `json:"signature,omitempty"`
	Timestamp     string   `json:"timestamp,omitempty"`
	MessageID     string   `json:"message_id,omitempty"`
	SignedPayload string   `json:"signed_payload,omitempty"`
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
}

func (c *Client) ChatCreateSession(ctx context.Context, req *ChatCreateSessionRequest) (*ChatCreateSessionResponse, error) {
	if req == nil {
		return nil, errors.New("aweb: request is required")
	}
	payload := *req

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
		if strings.TrimSpace(from) == "" {
			from = c.did
		} else if !directIdentityTargets {
			from = c.alias()
		}
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From: from,
		To:   to,
		Type: "chat",
		Body: payload.Message,
	})
	if err != nil {
		return nil, err
	}
	payload.FromDID = sf.FromDID
	payload.Signature = sf.Signature
	payload.Timestamp = sf.Timestamp
	payload.MessageID = sf.MessageID
	payload.SignedPayload = sf.SignedPayload

	var out ChatCreateSessionResponse
	if err := c.Post(ctx, "/v1/chat/sessions", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ChatPendingResponse struct {
	Pending         []ChatPendingItem `json:"pending"`
	MessagesWaiting int               `json:"messages_waiting"`
}

type ChatPendingItem struct {
	SessionID            string   `json:"session_id"`
	Participants         []string `json:"participants"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	LastFromAddress      string   `json:"last_from_address,omitempty"`
	UnreadCount          int      `json:"unread_count"`
	LastActivity         string   `json:"last_activity"`
	SenderWaiting        bool     `json:"sender_waiting"`
	TimeRemainingSeconds *int     `json:"time_remaining_seconds"`
}

func (c *Client) ChatPending(ctx context.Context) (*ChatPendingResponse, error) {
	var out ChatPendingResponse
	if err := c.Get(ctx, "/v1/chat/pending", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ChatHistoryResponse struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	MessageID               string                   `json:"message_id"`
	FromAgent               string                   `json:"from_agent"`
	FromAddress             string                   `json:"from_address,omitempty"`
	ToAddress               string                   `json:"to_address,omitempty"`
	Body                    string                   `json:"body"`
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
	var out ChatHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
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
		from := m.FromAgent
		if m.FromAddress != "" {
			from = m.FromAddress
		}
		if m.SignedPayload != "" {
			m.VerificationStatus, _ = VerifySignedPayload(m.SignedPayload, m.Signature, m.FromDID, m.SigningKeyID)
		} else {
			to := ""
			if m.ToAddress != "" {
				to = m.ToAddress
			}
			env := &MessageEnvelope{
				From:         from,
				FromDID:      m.FromDID,
				To:           to,
				ToDID:        m.ToDID,
				Type:         "chat",
				Body:         m.Body,
				Timestamp:    m.Timestamp,
				FromStableID: m.FromStableID,
				ToStableID:   m.ToStableID,
				MessageID:    m.MessageID,
				Signature:    m.Signature,
				SigningKeyID: m.SigningKeyID,
			}
			m.VerificationStatus, _ = VerifyMessage(env)
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
	}

	resp, err := c.sseClient.Do(req)
	if err != nil {
		return nil, err
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
	Body          string `json:"body"`
	ExtendWait    bool   `json:"hang_on,omitempty"`
	ReplyTo       string `json:"reply_to,omitempty"`
	FromDID       string `json:"from_did,omitempty"`
	Signature     string `json:"signature,omitempty"`
	Timestamp     string `json:"timestamp,omitempty"`
	MessageID     string `json:"message_id,omitempty"`
	SignedPayload string `json:"signed_payload,omitempty"`
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

	// In-session messages: include deterministic To for signature verification.
	// (aweb returns to_address for reconstruction; we sign the same value.)
	to := ""
	from := c.address
	if c.signingKey != nil {
		if toAddr, err := c.toAddressForSession(ctx, sessionID); err == nil {
			to = toAddr
		}
		from = c.alias()
	}
	sf, err := c.signEnvelope(ctx, &MessageEnvelope{
		From: from,
		To:   to,
		Type: "chat",
		Body: payload.Body,
	})
	if err != nil {
		return nil, err
	}
	payload.FromDID = sf.FromDID
	payload.Signature = sf.Signature
	payload.Timestamp = sf.Timestamp
	payload.MessageID = sf.MessageID
	payload.SignedPayload = sf.SignedPayload

	var out ChatSendMessageResponse
	if err := c.Post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", &payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatListSessions lists chat sessions the authenticated agent participates in.
type ChatSessionItem struct {
	SessionID            string   `json:"session_id"`
	Participants         []string `json:"participants"`
	ParticipantAddresses []string `json:"participant_addresses,omitempty"`
	CreatedAt            string   `json:"created_at"`
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
