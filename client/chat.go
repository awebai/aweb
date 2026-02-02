package aweb

import (
	"context"
	"io"
	"net/http"
	"time"
)

type ChatCreateSessionRequest struct {
	ToAliases []string `json:"to_aliases"`
	Message   string   `json:"message"`
	Leaving   bool     `json:"leaving,omitempty"`
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
	var out ChatCreateSessionResponse
	if err := c.post(ctx, "/v1/chat/sessions", req, &out); err != nil {
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
	LastMessage          string   `json:"last_message"`
	LastFrom             string   `json:"last_from"`
	UnreadCount          int      `json:"unread_count"`
	LastActivity         string   `json:"last_activity"`
	SenderWaiting        bool     `json:"sender_waiting"`
	TimeRemainingSeconds *int     `json:"time_remaining_seconds"`
}

func (c *Client) ChatPending(ctx context.Context) (*ChatPendingResponse, error) {
	var out ChatPendingResponse
	if err := c.get(ctx, "/v1/chat/pending", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ChatHistoryResponse struct {
	Messages []ChatMessage `json:"messages"`
}

type ChatMessage struct {
	MessageID     string `json:"message_id"`
	FromAgent     string `json:"from_agent"`
	Body          string `json:"body"`
	Timestamp     string `json:"timestamp"`
	SenderLeaving bool   `json:"sender_leaving"`
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
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ChatMarkReadRequest struct {
	UpToMessageID string `json:"up_to_message_id"`
}

type ChatMarkReadResponse struct {
	Success            bool `json:"success"`
	MessagesMarked     int  `json:"messages_marked"`
	WaitExtendedSeconds int `json:"wait_extended_seconds"`
}

func (c *Client) ChatMarkRead(ctx context.Context, sessionID string, req *ChatMarkReadRequest) (*ChatMarkReadResponse, error) {
	var out ChatMarkReadResponse
	if err := c.post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/read", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatStream opens an SSE stream for a session.
//
// deadline is required by the aweb API and must be a future time.
// Uses a dedicated HTTP client without response timeout since SSE connections are long-lived.
func (c *Client) ChatStream(ctx context.Context, sessionID string, deadline time.Time) (*SSEStream, error) {
	path := "/v1/chat/sessions/" + urlPathEscape(sessionID) + "/stream?deadline=" + urlQueryEscape(deadline.UTC().Format(time.RFC3339Nano))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.sseClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return nil, &apiError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return NewSSEStream(resp.Body), nil
}

// ChatSendMessage sends a message in an existing chat session.
type ChatSendMessageRequest struct {
	Body   string `json:"body"`
	HangOn bool   `json:"hang_on,omitempty"`
}

type ChatSendMessageResponse struct {
	MessageID          string `json:"message_id"`
	Delivered          bool   `json:"delivered"`
	ExtendsWaitSeconds int    `json:"extends_wait_seconds"`
}

func (c *Client) ChatSendMessage(ctx context.Context, sessionID string, req *ChatSendMessageRequest) (*ChatSendMessageResponse, error) {
	var out ChatSendMessageResponse
	if err := c.post(ctx, "/v1/chat/sessions/"+urlPathEscape(sessionID)+"/messages", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ChatListSessions lists chat sessions the authenticated agent participates in.
type ChatSessionItem struct {
	SessionID    string   `json:"session_id"`
	Participants []string `json:"participants"`
	CreatedAt    string   `json:"created_at"`
}

type ChatListSessionsResponse struct {
	Sessions []ChatSessionItem `json:"sessions"`
}

func (c *Client) ChatListSessions(ctx context.Context) (*ChatListSessionsResponse, error) {
	var out ChatListSessionsResponse
	if err := c.get(ctx, "/v1/chat/sessions", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
