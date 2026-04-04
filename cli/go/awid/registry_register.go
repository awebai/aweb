package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
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
	serverURL, err = canonicalRegistryServerOrigin(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	if strings.TrimSpace(did) == "" || strings.TrimSpace(stableID) == "" {
		return fmt.Errorf("did and stableID are required")
	}
	if signingKey == nil {
		return fmt.Errorf("signing key is required")
	}
	if got := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); got != did {
		return fmt.Errorf("did does not match signing key")
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	stateHash := stableIdentityStateHash(stableID, did, serverURL, address, strings.TrimSpace(handle))
	proofPayload := CanonicalDidLogPayload(stableID, &DidKeyEvidence{
		Seq:          1,
		Operation:    "create",
		NewDIDKey:    did,
		StateHash:    stateHash,
		AuthorizedBy: did,
		Timestamp:    timestamp,
	})
	proof := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(proofPayload)))

	client, err := New(registryBaseURL)
	if err != nil {
		return err
	}
	req := &didRegisterRequest{
		DIDAW:         stableID,
		DIDKey:        did,
		Server:        serverURL,
		Address:       strings.TrimSpace(address),
		Seq:           1,
		StateHash:     stateHash,
		AuthorizedBy:  did,
		Timestamp:     timestamp,
		Proof:         proof,
	}
	if trimmed := strings.TrimSpace(handle); trimmed != "" {
		req.Handle = &trimmed
	}
	if err := client.Post(ctx, "/v1/did", req, nil); err != nil {
		code, ok := HTTPStatusCode(err)
		if !ok || code != 409 {
			return err
		}
		var existing didKeyResponse
		if getErr := client.Get(ctx, "/v1/did/"+urlPathEscape(stableID)+"/key", &existing); getErr != nil {
			return err
		}
		if strings.TrimSpace(existing.DIDAW) != stableID {
			return fmt.Errorf("registry returned mismatched did:aw %q", existing.DIDAW)
		}
		if strings.TrimSpace(existing.CurrentDIDKey) != did {
			return fmt.Errorf("did:aw already registered to %s", existing.CurrentDIDKey)
		}
	}
	return nil
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
