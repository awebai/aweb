package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AgentEventType identifies a typed event emitted by GET /v1/events/stream.
type AgentEventType string

const (
	AgentEventConnected        AgentEventType = "connected"
	AgentEventActionableMail   AgentEventType = "actionable_mail"
	AgentEventActionableChat   AgentEventType = "actionable_chat"
	AgentEventWorkAvailable    AgentEventType = "work_available"
	AgentEventClaimUpdate      AgentEventType = "claim_update"
	AgentEventClaimRemoved     AgentEventType = "claim_removed"
	AgentEventControlPause     AgentEventType = "control_pause"
	AgentEventControlResume    AgentEventType = "control_resume"
	AgentEventControlInterrupt AgentEventType = "control_interrupt"
	AgentEventError            AgentEventType = "error"
)

// AgentEvent is a typed event emitted by GET /v1/events/stream.
type AgentEvent struct {
	Type          AgentEventType  `json:"type"`
	Raw           json.RawMessage `json:"raw,omitempty"`
	AgentID       string          `json:"agent_id,omitempty"`
	TeamID        string          `json:"team_id,omitempty"`
	WakeMode      string          `json:"wake_mode,omitempty"`
	Channel       string          `json:"channel,omitempty"`
	MessageID     string          `json:"message_id,omitempty"`
	FromAlias     string          `json:"from_alias,omitempty"`
	FromDID       string          `json:"from_did,omitempty"`
	FromAddress   string          `json:"from_address,omitempty"`
	SessionID     string          `json:"session_id,omitempty"`
	Subject       string          `json:"subject,omitempty"`
	UnreadCount   int             `json:"unread_count,omitempty"`
	SenderWaiting bool            `json:"sender_waiting,omitempty"`
	TaskID        string          `json:"task_id,omitempty"`
	Title         string          `json:"title,omitempty"`
	Status        string          `json:"status,omitempty"`
	SignalID      string          `json:"signal_id,omitempty"`
	Text          string          `json:"text,omitempty"`
}

func (e AgentEvent) IsActionableCoordination() bool {
	switch e.Type {
	case AgentEventActionableMail, AgentEventActionableChat:
		return true
	default:
		return false
	}
}

func (e AgentEvent) IsInterruptWake() bool {
	return e.IsActionableCoordination() && strings.EqualFold(strings.TrimSpace(e.WakeMode), "interrupt")
}

// AgentEventStream decodes typed events from GET /v1/events/stream.
// It is intentionally low-level: EOF and reconnect/backoff strategy are left to callers.
type AgentEventStream struct {
	sse *SSEStream
}

func newAgentEventStream(body io.ReadCloser) *AgentEventStream {
	return &AgentEventStream{sse: NewSSEStream(body)}
}

func (s *AgentEventStream) Close() error {
	if s == nil || s.sse == nil {
		return nil
	}
	return s.sse.Close()
}

// Next reads the next typed agent event, skipping unknown event names.
// The ctx parameter is accepted for EventSource interface conformance;
// cancellation is handled by the underlying HTTP response body context.
func (s *AgentEventStream) Next(_ context.Context) (*AgentEvent, error) {
	if s == nil || s.sse == nil {
		return nil, fmt.Errorf("aweb: agent event stream is nil")
	}
	for {
		ev, err := s.sse.Next()
		if err != nil {
			return nil, err
		}
		out, ok, err := parseAgentEvent(ev.Event, ev.Data)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		return &out, nil
	}
}

// EventStream opens GET /v1/events/stream using the active client auth.
// deadline is sent as an ISO8601/RFC3339 timestamp because the server expects an absolute time.
func (c *Client) EventStream(ctx context.Context, deadline time.Time) (*AgentEventStream, error) {
	path := "/v1/events/stream?deadline=" + urlQueryEscape(deadline.UTC().Format(time.RFC3339))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	if c.teamCertHeader != "" && c.signingKey != nil {
		timestamp := time.Now().UTC().Format(time.RFC3339)
		sigPayload := certAuthSignPayload(c.teamID, timestamp, nil)
		sig := ed25519.Sign(c.signingKey, sigPayload)
		req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(sig)))
		req.Header.Set("X-AWEB-Timestamp", timestamp)
		req.Header.Set("X-AWID-Team-Certificate", c.teamCertHeader)
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
	return newAgentEventStream(resp.Body), nil
}

func parseAgentEvent(eventName, data string) (AgentEvent, bool, error) {
	eventName = strings.TrimSpace(eventName)
	data = strings.TrimSpace(data)
	if eventName == "" {
		return AgentEvent{}, false, nil
	}

	raw := json.RawMessage(data)

	switch AgentEventType(eventName) {
	case AgentEventConnected:
		var payload struct {
			AgentID string `json:"agent_id"`
			TeamID  string `json:"team_id"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse connected event: %w", err)
		}
		return AgentEvent{
			Type:    AgentEventConnected,
			Raw:     raw,
			AgentID: payload.AgentID,
			TeamID:  payload.TeamID,
		}, true, nil

	case AgentEventActionableMail:
		var payload struct {
			MessageID   string `json:"message_id"`
			FromAlias   string `json:"from_alias"`
			FromDID     string `json:"from_did"`
			FromAddress string `json:"from_address"`
			Subject     string `json:"subject"`
			WakeMode    string `json:"wake_mode"`
			Channel     string `json:"channel"`
			UnreadCount int    `json:"unread_count"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse actionable_mail event: %w", err)
		}
		return AgentEvent{
			Type:        AgentEventActionableMail,
			Raw:         raw,
			WakeMode:    payload.WakeMode,
			Channel:     coalesceChannel(payload.Channel, AgentEventActionableMail),
			MessageID:   payload.MessageID,
			FromAlias:   payload.FromAlias,
			FromDID:     payload.FromDID,
			FromAddress: payload.FromAddress,
			Subject:     payload.Subject,
			UnreadCount: payload.UnreadCount,
		}, true, nil

	case AgentEventActionableChat:
		var payload struct {
			MessageID     string `json:"message_id"`
			FromAlias     string `json:"from_alias"`
			FromDID       string `json:"from_did"`
			FromAddress   string `json:"from_address"`
			SessionID     string `json:"session_id"`
			WakeMode      string `json:"wake_mode"`
			Channel       string `json:"channel"`
			UnreadCount   int    `json:"unread_count"`
			SenderWaiting bool   `json:"sender_waiting"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse actionable_chat event: %w", err)
		}
		return AgentEvent{
			Type:          AgentEventActionableChat,
			Raw:           raw,
			WakeMode:      payload.WakeMode,
			Channel:       coalesceChannel(payload.Channel, AgentEventActionableChat),
			MessageID:     payload.MessageID,
			FromAlias:     payload.FromAlias,
			FromDID:       payload.FromDID,
			FromAddress:   payload.FromAddress,
			SessionID:     payload.SessionID,
			UnreadCount:   payload.UnreadCount,
			SenderWaiting: payload.SenderWaiting,
		}, true, nil

	case AgentEventWorkAvailable:
		var payload struct {
			TaskID string `json:"task_id"`
			Title  string `json:"title"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse work_available event: %w", err)
		}
		return AgentEvent{
			Type:   AgentEventWorkAvailable,
			Raw:    raw,
			TaskID: payload.TaskID,
			Title:  payload.Title,
		}, true, nil

	case AgentEventClaimUpdate:
		var payload struct {
			TaskID string `json:"task_id"`
			Title  string `json:"title"`
			Status string `json:"status"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse claim_update event: %w", err)
		}
		return AgentEvent{
			Type:   AgentEventClaimUpdate,
			Raw:    raw,
			TaskID: payload.TaskID,
			Title:  payload.Title,
			Status: payload.Status,
		}, true, nil

	case AgentEventClaimRemoved:
		var payload struct {
			TaskID string `json:"task_id"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse claim_removed event: %w", err)
		}
		return AgentEvent{
			Type:   AgentEventClaimRemoved,
			Raw:    raw,
			TaskID: payload.TaskID,
		}, true, nil

	case AgentEventControlPause, AgentEventControlResume, AgentEventControlInterrupt:
		var payload struct {
			SignalID string `json:"signal_id"`
		}
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse %s event: %w", eventName, err)
		}
		return AgentEvent{
			Type:     AgentEventType(eventName),
			Raw:      raw,
			SignalID: payload.SignalID,
		}, true, nil

	case AgentEventError:
		var payload map[string]any
		if err := json.Unmarshal(raw, &payload); err != nil {
			return AgentEvent{}, false, fmt.Errorf("parse error event: %w", err)
		}
		return AgentEvent{
			Type: AgentEventError,
			Raw:  raw,
			Text: strings.TrimSpace(string(mustCompactJSON(payload))),
		}, true, nil

	default:
		return AgentEvent{}, false, nil
	}
}

func coalesceChannel(value string, eventType AgentEventType) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	switch eventType {
	case AgentEventActionableMail:
		return "mail"
	case AgentEventActionableChat:
		return "chat"
	default:
		return ""
	}
}

func mustCompactJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return bytes.TrimSpace(data)
}
