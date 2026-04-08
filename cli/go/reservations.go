package aweb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/awebai/aw/awid"
)

type ReservationAcquireRequest struct {
	ResourceKey string         `json:"resource_key"`
	TTLSeconds  int            `json:"ttl_seconds,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

type ReservationAcquireResponse struct {
	Status        string `json:"status"`
	ResourceKey   string `json:"resource_key"`
	HolderAgentID string `json:"holder_agent_id,omitempty"`
	HolderAlias   string `json:"holder_alias,omitempty"`
	AcquiredAt    string `json:"acquired_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

// ReservationHeldError is returned when a reservation is already held by another agent.
type ReservationHeldError struct {
	Detail        string `json:"detail"`
	HolderAgentID string `json:"holder_agent_id"`
	HolderAlias   string `json:"holder_alias"`
	ExpiresAt     string `json:"expires_at"`
}

func (e *ReservationHeldError) Error() string {
	if e.HolderAlias != "" {
		return "aweb: reservation held by " + e.HolderAlias
	}
	if e.Detail != "" {
		return "aweb: " + e.Detail
	}
	return "aweb: reservation is already held"
}

func (c *Client) ReservationAcquire(ctx context.Context, req *ReservationAcquireRequest) (*ReservationAcquireResponse, error) {
	resp, err := c.DoRaw(ctx, http.MethodPost, "/v1/reservations", "application/json", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, awid.MaxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusConflict {
		var held ReservationHeldError
		if err := json.Unmarshal(data, &held); err == nil {
			return nil, &held
		}
		return nil, &awid.APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &awid.APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	var out ReservationAcquireResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ReservationRenewRequest struct {
	ResourceKey string `json:"resource_key"`
	TTLSeconds  int    `json:"ttl_seconds,omitempty"`
}

type ReservationRenewResponse struct {
	Status      string `json:"status"`
	ResourceKey string `json:"resource_key"`
	ExpiresAt   string `json:"expires_at"`
}

func (c *Client) ReservationRenew(ctx context.Context, req *ReservationRenewRequest) (*ReservationRenewResponse, error) {
	var out ReservationRenewResponse
	if err := c.Post(ctx, "/v1/reservations/renew", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ReservationReleaseRequest struct {
	ResourceKey string `json:"resource_key"`
}

type ReservationReleaseResponse struct {
	Status      string `json:"status"`
	ResourceKey string `json:"resource_key"`
}

func (c *Client) ReservationRelease(ctx context.Context, req *ReservationReleaseRequest) (*ReservationReleaseResponse, error) {
	var out ReservationReleaseResponse
	if err := c.Post(ctx, "/v1/reservations/release", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ReservationView struct {
	ResourceKey   string         `json:"resource_key"`
	HolderAgentID string         `json:"holder_agent_id"`
	HolderAlias   string         `json:"holder_alias"`
	AcquiredAt    string         `json:"acquired_at"`
	ExpiresAt     string         `json:"expires_at"`
	Metadata      map[string]any `json:"metadata"`
}

type ReservationListResponse struct {
	Reservations []ReservationView `json:"reservations"`
}

type ReservationRevokeRequest struct {
	Prefix string `json:"prefix,omitempty"`
}

type ReservationRevokeResponse struct {
	RevokedCount int      `json:"revoked_count"`
	RevokedKeys  []string `json:"revoked_keys"`
}

// ReservationRevoke force-releases reservations, optionally filtered by prefix.
func (c *Client) ReservationRevoke(ctx context.Context, req *ReservationRevokeRequest) (*ReservationRevokeResponse, error) {
	var out ReservationRevokeResponse
	if err := c.Post(ctx, "/v1/reservations/revoke", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ReservationList(ctx context.Context, prefix string) (*ReservationListResponse, error) {
	path := "/v1/reservations"
	if prefix != "" {
		path += "?prefix=" + urlQueryEscape(prefix)
	}
	var out ReservationListResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
