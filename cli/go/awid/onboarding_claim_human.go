package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const onboardingClaimHumanPath = "/api/v1/onboarding/claim-human"

// ClaimHumanRequest is sent to POST /api/v1/onboarding/claim-human.
type ClaimHumanRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	AgentDIDKey string `json:"agent_did_key"`
}

// ClaimHumanResponse is returned by POST /api/v1/onboarding/claim-human.
type ClaimHumanResponse struct {
	Status string `json:"status"`
	Email  string `json:"email,omitempty"`
}

// ClaimHuman attaches an email address to an existing CLI-created account.
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
	if strings.TrimSpace(req.AgentDIDKey) == "" {
		return nil, fmt.Errorf("aweb: agent_did_key is required for claim-human")
	}
	if c.signingKey == nil {
		return nil, fmt.Errorf("aweb: claim-human requires a signing key")
	}
	if c.did == "" {
		return nil, fmt.Errorf("aweb: claim-human requires a did:key identity")
	}
	if strings.TrimSpace(req.AgentDIDKey) != c.did {
		return nil, fmt.Errorf("aweb: agent_did_key %q does not match client did:key %q", req.AgentDIDKey, c.did)
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
	signPayload := cloudDIDAuthSignPayload(httpReq.Method, httpReq.URL.Path, timestamp, bodyBytes)
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

// cloudDIDAuthSignPayload builds the canonical onboarding verifier envelope.
// Keys are serialized in lexicographic order with no whitespace:
// {"body_sha256":"...","method":"POST","path":"/api/v1/...","timestamp":"..."}
func cloudDIDAuthSignPayload(method, path, timestamp string, body []byte) []byte {
	h := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(h[:])

	var b strings.Builder
	b.WriteString(`{"body_sha256":`)
	hashJSON, _ := json.Marshal(bodyHash)
	b.Write(hashJSON)
	b.WriteString(`,"method":`)
	methodJSON, _ := json.Marshal(strings.ToUpper(strings.TrimSpace(method)))
	b.Write(methodJSON)
	b.WriteString(`,"path":`)
	pathJSON, _ := json.Marshal(strings.TrimSpace(path))
	b.Write(pathJSON)
	b.WriteString(`,"timestamp":`)
	tsJSON, _ := json.Marshal(timestamp)
	b.Write(tsJSON)
	b.WriteByte('}')
	return []byte(b.String())
}
