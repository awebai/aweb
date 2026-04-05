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
	DIDAW         string  `json:"did_aw"`
	DIDKey        string  `json:"did_key"`
	Server        string  `json:"server"`
	Address       string  `json:"address"`
	Handle        *string `json:"handle"`
	Seq           int     `json:"seq"`
	PrevEntryHash *string `json:"prev_entry_hash"`
	StateHash     string  `json:"state_hash"`
	AuthorizedBy  string  `json:"authorized_by"`
	Timestamp     string  `json:"timestamp"`
	Proof         string  `json:"proof"`
}

type didKeyResponse struct {
	DIDAW         string `json:"did_aw"`
	CurrentDIDKey string `json:"current_did_key"`
}

func RegisterSelfCustodialDID(
	ctx context.Context,
	registryBaseURL string,
	serverURL string,
	address string,
	handle string,
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
	_, err = client.RegisterDID(ctx, registryBaseURL, serverURL, address, handle, did, stableID, signingKey)
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

func stableIdentityStateHash(
	stableID string,
	did string,
	serverURL string,
	address string,
	handle string,
) string {
	payload := canonicalStateJSON(stableID, did, serverURL, address, handle)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

func canonicalStateJSON(
	stableID string,
	did string,
	serverURL string,
	address string,
	handle string,
) string {
	var b strings.Builder
	b.WriteByte('{')
	writeJSONField(&b, "address", strings.TrimSpace(address))
	b.WriteByte(',')
	writeJSONField(&b, "current_did_key", did)
	b.WriteByte(',')
	writeJSONField(&b, "did_aw", stableID)
	b.WriteByte(',')
	if strings.TrimSpace(handle) == "" {
		b.WriteString(`"handle":null`)
	} else {
		writeJSONField(&b, "handle", strings.TrimSpace(handle))
	}
	b.WriteByte(',')
	writeJSONField(&b, "server", serverURL)
	b.WriteByte('}')
	return b.String()
}
