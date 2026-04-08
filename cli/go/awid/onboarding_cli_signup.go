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

// Onboarding HTTP helpers for the hosted onboarding endpoints.
//
// These helpers live in the awid package alongside the other HTTP client
// code, but they speak to the hosted onboarding service, not to the awid
// registry. The split-authority rule: the CLI signs its own awid operations
// (DID registration) and its own onboarding requests; the hosted service
// signs its own controller operations (namespace / team / cert registration
// at awid). Neither side signs for the other.

// CheckUsernameRequest is the body for POST /api/v1/onboarding/check-username.
type CheckUsernameRequest struct {
	Username string `json:"username"`
}

// CheckUsernameResponse is the reply from POST /api/v1/onboarding/check-username.
// Reason is empty when Available is true; otherwise one of "taken",
// "invalid_format", "reserved".
type CheckUsernameResponse struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// CliSignupRequest is the body for POST /api/v1/onboarding/cli-signup.
// DIDKey must be the did:key the CLI just registered at awid via POST /v1/did.
// DIDAW is the stable id (did:aw:...) for that same keypair.
type CliSignupRequest struct {
	Username string `json:"username"`
	DIDKey   string `json:"did_key"`
	DIDAW    string `json:"did_aw"`
	Alias    string `json:"alias"`
}

// CliSignupResponse carries the hosted onboarding reply: the signed team certificate
// plus the identity metadata the CLI needs to write .aw/identity.yaml.
// Certificate is a base64-encoded team certificate JSON document.
type CliSignupResponse struct {
	UserID          string `json:"user_id"`
	Username        string `json:"username"`
	OrgID           string `json:"org_id"`
	NamespaceDomain string `json:"namespace_domain"`
	TeamAddress     string `json:"team_address"`
	Certificate     string `json:"certificate"`
	DIDAW           string `json:"did_aw"`
	MemberAddress   string `json:"member_address"`
	Alias           string `json:"alias"`
}

// CheckUsername validates a username against the hosted onboarding service. No auth required.
func CheckUsername(ctx context.Context, onboardingURL, username string) (*CheckUsernameResponse, error) {
	body := &CheckUsernameRequest{Username: username}
	var out CheckUsernameResponse
	if err := postJSONNoAuth(ctx, onboardingURL, "/api/v1/onboarding/check-username", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CliSignup creates a hosted aweb.ai account + personal namespace + default
// team + signed team certificate, tying it to a did:aw the CLI already
// registered at awid. The request is DIDKey-signed by signingKey (which must
// match req.DIDKey).
//
// Critical implementation detail: the JSON body is marshaled exactly once,
// those bytes are hashed for body_sha256 in the signature envelope, and those
// same bytes are sent as the HTTP request body. Re-marshalling after hashing
// would desync the hash from the wire bytes and the server would reject the
// signature.
func CliSignup(
	ctx context.Context,
	onboardingURL string,
	req *CliSignupRequest,
	signingKey ed25519.PrivateKey,
) (*CliSignupResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("cli-signup: request is required")
	}
	if signingKey == nil {
		return nil, fmt.Errorf("cli-signup: signing key is required")
	}
	expectedDID := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if req.DIDKey != expectedDID {
		return nil, fmt.Errorf(
			"cli-signup: body did_key %s does not match signing key did:key %s",
			req.DIDKey, expectedDID,
		)
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cli-signup: marshal request: %w", err)
	}

	const path = "/api/v1/onboarding/cli-signup"
	headers := onboardingDIDKeyHeaders(http.MethodPost, path, bodyBytes, signingKey)

	var out CliSignupResponse
	if err := postJSONWithHeaders(ctx, onboardingURL, path, bodyBytes, headers, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// onboardingDIDKeyHeaders builds the DIDKey auth headers for an onboarding endpoint call.
// The caller provides the exact body bytes that will be transmitted; this
// function does not re-marshal anything.
//
// The signed envelope is built by the shared onboardingDIDKeySignPayload helper,
// which is also used by claim-human
// and bootstrap-redeem so all three onboarding endpoints produce
// byte-identical canonical payloads.
func onboardingDIDKeyHeaders(
	method, path string,
	body []byte,
	signingKey ed25519.PrivateKey,
) map[string]string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	payload := onboardingDIDKeySignPayload(method, path, timestamp, body)
	sig := ed25519.Sign(signingKey, payload)
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	return map[string]string{
		"Authorization":    fmt.Sprintf("DIDKey %s %s", did, base64.RawStdEncoding.EncodeToString(sig)),
		"X-AWEB-Timestamp": timestamp,
	}
}

// postJSONNoAuth sends a JSON POST with no authentication. Marshals once,
// expects a JSON response body.
func postJSONNoAuth(ctx context.Context, baseURL, path string, in, out any) error {
	bodyBytes, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	return postJSONWithHeaders(ctx, baseURL, path, bodyBytes, nil, out)
}

// postJSONWithHeaders sends a POST with a pre-marshaled body and a set of
// headers (e.g. a DIDKey auth envelope). It guarantees the body bytes
// transmitted on the wire are exactly the bytes the caller provided —
// critical for body_sha256-based authentication.
func postJSONWithHeaders(
	ctx context.Context,
	baseURL, path string,
	bodyBytes []byte,
	headers map[string]string,
	out any,
) error {
	requestPath := path
	if strings.HasSuffix(strings.TrimRight(baseURL, "/"), "/api") && strings.HasPrefix(requestPath, "/api/") {
		requestPath = strings.TrimPrefix(requestPath, "/api")
	}
	u := strings.TrimRight(baseURL, "/") + requestPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &RegistryError{StatusCode: resp.StatusCode, Detail: strings.TrimSpace(string(detail))}
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
