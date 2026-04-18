package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type didRegisterRequest struct {
	AuthorizedBy   string  `json:"authorized_by"`
	DIDAW          string  `json:"did_aw"`
	NewDIDKey      string  `json:"new_did_key"`
	Operation      string  `json:"operation"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	PreviousDIDKey *string `json:"previous_did_key"`
	Seq            int     `json:"seq"`
	StateHash      string  `json:"state_hash"`
	Timestamp      string  `json:"timestamp"`
	Proof          string  `json:"proof"`
}

type didKeyResponse struct {
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
}

func RegisterIdentity(
	ctx context.Context,
	registryBaseURL string,
	did string,
	stableID string,
	signingKey ed25519.PrivateKey,
) error {
	registryBaseURL, err := canonicalServerOrigin(registryBaseURL)
	if err != nil {
		return fmt.Errorf("invalid registry URL: %w", err)
	}
	client := NewAWIDRegistryClient(nil, nil)
	client.DefaultRegistryURL = registryBaseURL
	_, err = client.RegisterIdentity(ctx, registryBaseURL, did, stableID, signingKey)
	var already *AlreadyRegisteredError
	if errors.As(err, &already) && strings.TrimSpace(already.ExistingDIDKey) == strings.TrimSpace(did) {
		return nil
	}
	return err
}

func canonicalRegistryServerOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if strings.TrimRight(parsed.Path, "/") == "/api" {
		parsed.Path = ""
		parsed.RawPath = ""
	}
	return canonicalServerOrigin(parsed.String())
}

func stableIdentityStateHash(stableID string, did string) string {
	payload := canonicalStateJSON(stableID, did)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func canonicalStateJSON(stableID string, did string) string {
	var b strings.Builder
	b.WriteByte('{')
	writeJSONField(&b, "current_did_key", did)
	b.WriteByte(',')
	writeJSONField(&b, "did_aw", stableID)
	b.WriteByte('}')
	return b.String()
}
