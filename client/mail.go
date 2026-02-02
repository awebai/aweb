package aweb

import (
	"context"
)

type MessagePriority string

const (
	PriorityLow    MessagePriority = "low"
	PriorityNormal MessagePriority = "normal"
	PriorityHigh   MessagePriority = "high"
	PriorityUrgent MessagePriority = "urgent"
)

type SendMessageRequest struct {
	ToAgentID string          `json:"to_agent_id,omitempty"`
	ToAlias   string          `json:"to_alias,omitempty"`
	Subject   string          `json:"subject,omitempty"`
	Body      string          `json:"body"`
	Priority  MessagePriority `json:"priority,omitempty"`
	ThreadID  *string         `json:"thread_id,omitempty"`
}

type SendMessageResponse struct {
	MessageID   string `json:"message_id"`
	Status      string `json:"status"`
	DeliveredAt string `json:"delivered_at"`
}

func (c *Client) SendMessage(ctx context.Context, req *SendMessageRequest) (*SendMessageResponse, error) {
	var out SendMessageResponse
	if err := c.post(ctx, "/v1/messages", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type InboxMessage struct {
	MessageID   string          `json:"message_id"`
	FromAgentID string          `json:"from_agent_id"`
	FromAlias   string          `json:"from_alias"`
	Subject     string          `json:"subject"`
	Body        string          `json:"body"`
	Priority    MessagePriority `json:"priority"`
	ThreadID    *string         `json:"thread_id"`
	ReadAt      *string         `json:"read_at"`
	CreatedAt   string          `json:"created_at"`
}

type InboxResponse struct {
	Messages []InboxMessage `json:"messages"`
}

type InboxParams struct {
	UnreadOnly bool
	Limit      int
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
	var out InboxResponse
	if err := c.get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type AckResponse struct {
	MessageID      string `json:"message_id"`
	AcknowledgedAt string `json:"acknowledged_at"`
}

func (c *Client) AckMessage(ctx context.Context, messageID string) (*AckResponse, error) {
	var out AckResponse
	if err := c.post(ctx, "/v1/messages/"+urlPathEscape(messageID)+"/ack", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
