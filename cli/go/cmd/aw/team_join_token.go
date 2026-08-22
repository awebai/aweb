package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const hostedJoinTokenPrefix = "aw_inv_v1_"

var legacyHostedJoinTokenPattern = regexp.MustCompile(`^aw_inv_[A-Za-z0-9_-]{43}$`)

type hostedJoinTokenEnvelope struct {
	Version    int    `json:"v"`
	InnerToken string `json:"t"`
	AwebURL    string `json:"a"`
}

// decodeJoinToken returns the exact token that must be redeemed and any service
// URL it carries. A hosted envelope is opaque to older clients, so newer clients
// decode only `a` and still submit the full original token unchanged. Legacy
// hosted tokens remain valid and simply have no embedded URL.
func decodeJoinToken(token string) (rawToken, awebURL string, err error) {
	token = strings.TrimSpace(token)
	// Legacy hosted tokens have an exact fixed-length shape. Check it before
	// the versioned prefix because a valid random legacy suffix can begin `v1_`.
	if legacyHostedJoinTokenPattern.MatchString(token) {
		return token, "", nil
	}
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
		if envelope.Version != 1 || !awid.IsHostedSpawnInviteToken(envelope.InnerToken) || strings.TrimSpace(envelope.AwebURL) == "" {
			return "", "", fmt.Errorf("invalid hosted invite envelope")
		}
		normalized, normalizeErr := validateInviteAwebURL(envelope.AwebURL)
		if normalizeErr != nil {
			return "", "", fmt.Errorf("invalid hosted invite service URL: %w", normalizeErr)
		}
		return token, normalized, nil
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
	normalized, normalizeErr := validateInviteAwebURL(decoded.AwebURL)
	if normalizeErr != nil {
		return "", "", fmt.Errorf("invalid invite service URL: %w", normalizeErr)
	}
	return token, normalized, nil
}
