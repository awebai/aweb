package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const hostedJoinTokenPrefix = "aw_inv_v1_"

type hostedJoinTokenEnvelope struct {
	Version int    `json:"v"`
	Token   string `json:"t"`
	AwebURL string `json:"a"`
}

// encodeHostedJoinToken preserves the server-issued bearer token while adding
// the service URL needed to redeem it. The aw_inv_ prefix keeps the token
// recognizable (and covered by existing secret-redaction rules), while the
// versioned payload lets newer clients distinguish it from legacy opaque
// hosted tokens.
func encodeHostedJoinToken(token, awebURL string) (string, error) {
	token = strings.TrimSpace(token)
	if !awid.IsHostedSpawnInviteToken(token) {
		return "", fmt.Errorf("hosted invite token is required")
	}
	awebURL, err := canonicalReconnectAwebURL(awebURL)
	if err != nil {
		return "", fmt.Errorf("invalid invite service URL: %w", err)
	}
	payload, err := json.Marshal(hostedJoinTokenEnvelope{Version: 1, Token: token, AwebURL: awebURL})
	if err != nil {
		return "", err
	}
	return hostedJoinTokenPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

// decodeJoinToken returns the raw token and any service URL carried by either
// the hosted envelope above or the existing local-controller token's `a`
// field. Legacy opaque hosted tokens remain valid and simply have no embedded
// URL.
func decodeJoinToken(token string) (rawToken, awebURL string, err error) {
	token = strings.TrimSpace(token)
	if strings.HasPrefix(token, hostedJoinTokenPrefix) {
		encoded := strings.TrimPrefix(token, hostedJoinTokenPrefix)
		payload, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
		if decodeErr != nil {
			return "", "", fmt.Errorf("invalid hosted invite envelope: %w", decodeErr)
		}
		var envelope hostedJoinTokenEnvelope
		if decodeErr := json.Unmarshal(payload, &envelope); decodeErr != nil {
			return "", "", fmt.Errorf("invalid hosted invite envelope: %w", decodeErr)
		}
		if envelope.Version != 1 || !awid.IsHostedSpawnInviteToken(envelope.Token) || strings.TrimSpace(envelope.AwebURL) == "" {
			return "", "", fmt.Errorf("invalid hosted invite envelope")
		}
		normalized, normalizeErr := canonicalReconnectAwebURL(envelope.AwebURL)
		if normalizeErr != nil {
			return "", "", fmt.Errorf("invalid hosted invite service URL: %w", normalizeErr)
		}
		return strings.TrimSpace(envelope.Token), normalized, nil
	}
	if awid.IsHostedSpawnInviteToken(token) {
		return token, "", nil
	}
	decoded, decodeErr := awconfig.DecodeInviteToken(token)
	if decodeErr != nil {
		return token, "", nil
	}
	if strings.TrimSpace(decoded.AwebURL) == "" {
		return token, "", nil
	}
	normalized, normalizeErr := canonicalReconnectAwebURL(decoded.AwebURL)
	if normalizeErr != nil {
		return "", "", fmt.Errorf("invalid invite service URL: %w", normalizeErr)
	}
	return token, normalized, nil
}
