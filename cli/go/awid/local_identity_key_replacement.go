package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// LocalIdentityKeyReplacementInput binds a controller-authorized transition to one service.
type LocalIdentityKeyReplacementInput struct {
	ServiceURL       string
	Alias            string
	Request          LocalIdentityKeyReplacementRequest
	TeamKey          ed25519.PrivateKey
	MaxResponseBytes int64
}

// LocalIdentityKeyReplacementPayloadInput names the exact controller-signed operation.
type LocalIdentityKeyReplacementPayloadInput struct {
	Alias     string
	Request   LocalIdentityKeyReplacementRequest
	Timestamp string
}

// LocalIdentityKeyReplacementUnknownError requires exact replay before assuming an outcome.
type LocalIdentityKeyReplacementUnknownError struct{ Cause error }

// Error describes why the roster outcome could not be established.
func (e *LocalIdentityKeyReplacementUnknownError) Error() string { return e.Cause.Error() }

// Unwrap retains the transport, decoding or receipt-validation failure.
func (e *LocalIdentityKeyReplacementUnknownError) Unwrap() error { return e.Cause }

// LocalIdentityKeyReplacementRequest identifies both keys and certificates.
type LocalIdentityKeyReplacementRequest struct {
	TeamID           string `json:"team_id"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	OldCertificateID string `json:"old_certificate_id"`
	NewCertificateID string `json:"new_certificate_id"`
}

// LocalIdentityKeyReplacementState is the roster transition receipt state.
type LocalIdentityKeyReplacementState string

// LocalIdentityKeyReplaced records the exact completed roster transition.
const LocalIdentityKeyReplaced LocalIdentityKeyReplacementState = "replaced"

// LocalIdentityKeyReplacementResponse is the controller-attributed transition receipt.
type LocalIdentityKeyReplacementResponse struct {
	Status           LocalIdentityKeyReplacementState `json:"status"`
	AuditID          string                           `json:"audit_id"`
	AgentID          string                           `json:"agent_id"`
	TeamID           string                           `json:"team_id"`
	Alias            string                           `json:"alias"`
	OldDIDKey        string                           `json:"old_did_key"`
	NewDIDKey        string                           `json:"new_did_key"`
	OldCertificateID string                           `json:"old_certificate_id"`
	NewCertificateID string                           `json:"new_certificate_id"`
	AuthorizedBy     string                           `json:"authorized_by"`
	AuthorizedAt     string                           `json:"authorized_at"`
}

// LocalIdentityKeyReplacementPayload canonicalizes the signed controller operation.
func LocalIdentityKeyReplacementPayload(input LocalIdentityKeyReplacementPayloadInput) ([]byte, error) {
	alias, payload, timestamp := input.Alias, input.Request, input.Timestamp
	// The server verifies over Python canonical_json_bytes of these fields.
	canonical, err := CanonicalJSONValue(map[string]any{
		"agent_alias":        alias,
		"new_certificate_id": payload.NewCertificateID,
		"new_did_key":        payload.NewDIDKey,
		"old_certificate_id": payload.OldCertificateID,
		"old_did_key":        payload.OldDIDKey,
		"operation":          "replace_local_identity_key",
		"team_id":            payload.TeamID,
		"timestamp":          timestamp,
	})
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

// ReplaceLocalIdentityKey submits one signed transition and validates its exact receipt.
// docs/identity-messaging-contract.md:96-100 keeps local conversation authority at the literal key.
func ReplaceLocalIdentityKey(ctx context.Context, input LocalIdentityKeyReplacementInput) (*LocalIdentityKeyReplacementResponse, error) {
	serviceURL, alias, payload, teamKey := input.ServiceURL, input.Alias, input.Request, input.TeamKey
	if len(teamKey) != ed25519.PrivateKeySize {
		return nil, errors.New("a valid team signing key is required")
	}
	if input.MaxResponseBytes < 0 {
		return nil, errors.New("replacement response limit must not be negative")
	}
	if input.MaxResponseBytes == 0 {
		input.MaxResponseBytes = MaxResponseSize
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := "/v1/agents/" + url.PathEscape(alias) + "/replace-key"
	timestamp := time.Now().UTC().Format(time.RFC3339)
	canonical, err := LocalIdentityKeyReplacementPayload(LocalIdentityKeyReplacementPayloadInput{Alias: alias, Request: payload, Timestamp: timestamp})
	if err != nil {
		return nil, err
	}
	controllerDID, signatureBytes, err := KeySigner(teamKey)(canonical)
	if err != nil {
		return nil, err
	}
	signature := base64.RawStdEncoding.EncodeToString(signatureBytes)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(serviceURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "DIDKey "+controllerDID+" "+signature)
	req.Header.Set("X-AWEB-Timestamp", timestamp)
	resp, err := DoServerRequest(&http.Client{Timeout: APITimeout()}, req, serviceURL)
	if err != nil {
		return nil, &LocalIdentityKeyReplacementUnknownError{Cause: err}
	}
	defer resp.Body.Close()
	responseBody, err := ReadAllBounded(resp.Body, input.MaxResponseBytes)
	if err != nil {
		return nil, &LocalIdentityKeyReplacementUnknownError{Cause: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("aweb replace-key returned %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
			return nil, &LocalIdentityKeyReplacementUnknownError{Cause: err}
		}
		return nil, err
	}
	var out LocalIdentityKeyReplacementResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, &LocalIdentityKeyReplacementUnknownError{Cause: fmt.Errorf("decode aweb replace-key response: %w", err)}
	}
	if out.Status != LocalIdentityKeyReplaced || out.AuditID == "" || out.AgentID == "" || out.AuthorizedAt == "" || out.AuthorizedBy != controllerDID || out.TeamID != payload.TeamID || out.Alias != alias || out.OldDIDKey != payload.OldDIDKey || out.NewDIDKey != payload.NewDIDKey || out.OldCertificateID != payload.OldCertificateID || out.NewCertificateID != payload.NewCertificateID {
		return nil, &LocalIdentityKeyReplacementUnknownError{Cause: errors.New("aweb replace-key response does not match the authorized transition")}
	}
	return &out, nil
}
