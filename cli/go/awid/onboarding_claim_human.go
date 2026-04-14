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

const onboardingClaimHumanPath = "/api/v1/claim-human"

// ClaimHumanRequest is sent to POST /api/v1/claim-human.
type ClaimHumanRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	DIDKey   string `json:"did_key"`
}

// ClaimHumanResponse is returned by POST /api/v1/claim-human.
type ClaimHumanResponse struct {
	Status string `json:"status"`
	Email  string `json:"email,omitempty"`
}

// ClaimHuman calls the cloud onboarding endpoint to attach a human account to
// an existing CLI-created agent identity. It is not an awid registry route.
func (c *Client) ClaimHuman(ctx context.Context, req *ClaimHumanRequest) (*ClaimHumanResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("aweb: claim-human request is required")
	}
	if strings.TrimSpace(req.Username) == "" {
		return nil, fmt.Errorf("aweb: username is required for claim-human")
	}
	if strings.TrimSpace(req.Email) == "" {
		return nil, fmt.Errorf("aweb: email is required for claim-human")
	}
	if strings.TrimSpace(req.DIDKey) == "" {
		return nil, fmt.Errorf("aweb: did_key is required for claim-human")
	}
	if c.signingKey == nil {
		return nil, fmt.Errorf("aweb: claim-human requires a signing key")
	}
	if c.did == "" {
		return nil, fmt.Errorf("aweb: claim-human requires a did:key identity")
	}
	if strings.TrimSpace(req.DIDKey) != c.did {
		return nil, fmt.Errorf("aweb: did_key %q does not match client did:key %q", req.DIDKey, c.did)
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	requestPath := onboardingClaimHumanPath
	if strings.HasSuffix(c.baseURL, "/api") {
		requestPath = strings.TrimPrefix(requestPath, "/api")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+requestPath, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Content-Type", "application/json")

	timestamp := time.Now().UTC().Format(time.RFC3339)
	signPayload := onboardingDIDKeySignPayload(httpReq.Method, httpReq.URL.Path, timestamp, bodyBytes)
	signature := ed25519.Sign(c.signingKey, signPayload)
	httpReq.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", c.did, base64.RawStdEncoding.EncodeToString(signature)))
	httpReq.Header.Set("X-AWEB-Timestamp", timestamp)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if v := resp.Header.Get("X-Latest-Client-Version"); v != "" {
		c.latestClientVersion.Store(v)
	}

	limited := io.LimitReader(resp.Body, MaxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	var out ClaimHumanResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
