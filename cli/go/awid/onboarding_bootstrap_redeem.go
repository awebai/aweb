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

const onboardingBootstrapRedeemPath = "/api/v1/onboarding/bootstrap-redeem"

// BootstrapRedeemRequest is sent to POST /api/v1/onboarding/bootstrap-redeem.
type BootstrapRedeemRequest struct {
	Token  string `json:"token"`
	DIDKey string `json:"did_key"`
	DIDAW  string `json:"did_aw,omitempty"`
}

// BootstrapRedeemResponse is returned by POST /api/v1/onboarding/bootstrap-redeem.
type BootstrapRedeemResponse struct {
	Certificate   string `json:"certificate"`
	TeamAddress   string `json:"team_address"`
	Lifetime      string `json:"lifetime"`
	Alias         string `json:"alias"`
	DIDAW         string `json:"did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
}

// BootstrapRedeem redeems a one-time bootstrap token into a team certificate.
func (c *Client) BootstrapRedeem(ctx context.Context, req *BootstrapRedeemRequest) (*BootstrapRedeemResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("aweb: bootstrap-redeem request is required")
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, fmt.Errorf("aweb: token is required for bootstrap-redeem")
	}
	if strings.TrimSpace(req.DIDKey) == "" {
		return nil, fmt.Errorf("aweb: did_key is required for bootstrap-redeem")
	}
	if c.signingKey == nil {
		return nil, fmt.Errorf("aweb: bootstrap-redeem requires a signing key")
	}
	if c.did == "" {
		return nil, fmt.Errorf("aweb: bootstrap-redeem requires a did:key identity")
	}
	if strings.TrimSpace(req.DIDKey) != c.did {
		return nil, fmt.Errorf("aweb: did_key %q does not match client did:key %q", req.DIDKey, c.did)
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	requestPath := onboardingBootstrapRedeemPath
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

	var out BootstrapRedeemResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
