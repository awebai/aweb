package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
)

// CliSignupSubmission freezes the original signup request bytes independently
// of the transport attempt. The signer remains the same key; each request gets
// the existing onboarding authentication envelope with a fresh timestamp.
type CliSignupSubmission struct {
	OnboardingURL string
	RequestJSON   []byte
	SigningKey    ed25519.PrivateKey
}

// SubmitCliSignup signs and sends the retained request bytes without decoding
// and re-encoding them. This preserves the exact request for server replay and
// uses CliSignup's released onboarding proof, without a new wire field.
func SubmitCliSignup(ctx context.Context, input CliSignupSubmission) (*CliSignupResponse, error) {
	if len(input.SigningKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cli-signup: signing key is required and must be valid")
	}
	body := bytes.Clone(input.RequestJSON)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, fmt.Errorf("cli-signup: retained request is malformed")
	}
	var didKey string
	if err := json.Unmarshal(fields["did_key"], &didKey); err != nil {
		return nil, fmt.Errorf("cli-signup: body did_key is required")
	}
	expectedDID := ComputeDIDKey(ed25519.PublicKey(input.SigningKey[ed25519.SeedSize:]))
	if didKey != expectedDID {
		return nil, fmt.Errorf("cli-signup: body did_key %s does not match signing key did:key %s", didKey, expectedDID)
	}
	const path = "/api/v1/onboarding/cli-signup"
	headers := onboardingDIDKeyHeaders(http.MethodPost, path, body, input.SigningKey)
	var response CliSignupResponse
	if err := postJSONWithHeaders(ctx, input.OnboardingURL, path, body, headers, &response); err != nil {
		return nil, err
	}
	return &response, nil
}
