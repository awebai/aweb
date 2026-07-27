package aweb

import (
	"context"
	"fmt"
	"net/http"

	"github.com/awebai/aw/awid"
)

type SessionLeaseRequest struct {
	SessionID  string `json:"session_id"`
	SessionKey string `json:"session_key"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type SessionLeaseTakeoverRequest struct {
	SessionID  string `json:"session_id"`
	SessionKey string `json:"session_key"`
	TTLSeconds int    `json:"ttl_seconds"`
	Reason     string `json:"reason"`
}

type SessionLeaseReleaseRequest struct {
	SessionID  string `json:"session_id"`
	SessionKey string `json:"session_key"`
}

type SessionLeaseView struct {
	Status           string `json:"status"`
	TeamID           string `json:"team_id"`
	PrincipalAgentID string `json:"principal_agent_id"`
	SessionID        string `json:"session_id"`
	Generation       int64  `json:"generation"`
	AcquiredAt       string `json:"acquired_at"`
	ExpiresAt        string `json:"expires_at"`
}

func (c *Client) SessionLeaseGet(ctx context.Context) (*SessionLeaseView, error) {
	var out SessionLeaseView
	if err := c.Get(ctx, "/v1/session-leases", &out); err != nil {
		return nil, sessionLeaseCompatibilityError(err)
	}
	return &out, nil
}

func (c *Client) SessionLeaseAcquire(ctx context.Context, req *SessionLeaseRequest) (*SessionLeaseView, error) {
	var out SessionLeaseView
	if err := c.Post(ctx, "/v1/session-leases", req, &out); err != nil {
		return nil, sessionLeaseCompatibilityError(err)
	}
	return &out, nil
}

func (c *Client) SessionLeaseRenew(ctx context.Context, req *SessionLeaseRequest) (*SessionLeaseView, error) {
	var out SessionLeaseView
	if err := c.Post(ctx, "/v1/session-leases/renew", req, &out); err != nil {
		return nil, sessionLeaseCompatibilityError(err)
	}
	return &out, nil
}

func (c *Client) SessionLeaseRelease(ctx context.Context, req *SessionLeaseReleaseRequest) error {
	return sessionLeaseCompatibilityError(c.Post(ctx, "/v1/session-leases/release", req, nil))
}

func (c *Client) SessionLeaseTakeover(ctx context.Context, req *SessionLeaseTakeoverRequest) (*SessionLeaseView, error) {
	var out SessionLeaseView
	if err := c.Post(ctx, "/v1/session-leases/takeover", req, &out); err != nil {
		return nil, sessionLeaseCompatibilityError(err)
	}
	return &out, nil
}

func sessionLeaseCompatibilityError(err error) error {
	if err == nil {
		return nil
	}
	if status, ok := awid.HTTPStatusCode(err); ok && status == http.StatusNotFound {
		return fmt.Errorf("session leases require aweb server 1.26.28 or later: %w", err)
	}
	return err
}
