package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/awebai/aw/canonicaljson"
	"github.com/awebai/aw/signaturewire"
)

// RotateKeyRequest is the input to Client.RotateKey.
type RotateKeyRequest struct {
	NewDID       string            // did:key of the new key
	NewPublicKey ed25519.PublicKey // raw new public key
	Custody      string            // "self" or "custodial"
}

// rotateKeyWireRequest is the wire format sent to PUT /v1/agents/me/rotate.
// For self-custody: includes new_did, new_public_key, rotation_signature.
// For custodial: key material fields are omitted (omitempty).
type rotateKeyWireRequest struct {
	Custody           string `json:"custody"`
	Timestamp         string `json:"timestamp"`
	NewDID            string `json:"new_did,omitempty"`
	NewPublicKey      string `json:"new_public_key,omitempty"`
	RotationSignature string `json:"rotation_signature,omitempty"`
}

// RotateKeyResponse is returned by PUT /v1/agents/me/rotate.
type RotateKeyResponse struct {
	Status       string `json:"status"`
	OldDID       string `json:"old_did"`
	NewDID       string `json:"new_did"`
	NewPublicKey string `json:"new_public_key,omitempty"`
	Custody      string `json:"custody"`
}

// RotateKey sends a key rotation request to the server.
// The client must have been created with NewWithIdentity (has a signing key).
// The rotation_signature is computed by signing the canonical rotation payload
// with the current (old) key.
func (c *Client) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	if c.signingKey == nil {
		return nil, fmt.Errorf("RotateKey: client has no signing key")
	}

	ts := time.Now().UTC().Format(time.RFC3339)

	// Sign the rotation payload with the old (current) key.
	payload := CanonicalRotationJSON(c.did, req.NewDID, ts)
	sig := signaturewire.SignBytes(c.signingKey, []byte(payload))

	wire := &rotateKeyWireRequest{
		Custody:           req.Custody,
		Timestamp:         ts,
		NewDID:            req.NewDID,
		NewPublicKey:      base64.RawURLEncoding.EncodeToString(req.NewPublicKey),
		RotationSignature: base64.RawStdEncoding.EncodeToString(sig),
	}

	var resp RotateKeyResponse
	if err := c.Put(ctx, "/v1/agents/me/rotate", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CanonicalRotationJSON builds the canonical JSON for rotation signing.
// Fields: new_did, old_did, timestamp — sorted lexicographically.
func CanonicalRotationJSON(oldDID, newDID, timestamp string) string {
	return canonicaljson.Object(map[string]any{"new_did": newDID, "old_did": oldDID, "timestamp": timestamp})
}

// RotateKeyCustodialRequest is the input to Client.RotateKeyCustodial.
// For custodial→self graduation: set Custody="self" and provide NewDID/NewPublicKey.
// For custodial→custodial rotation: set Custody="custodial" and leave NewDID/NewPublicKey empty.
type RotateKeyCustodialRequest struct {
	NewDID       string            // did:key of the new key (empty for custodial→custodial)
	NewPublicKey ed25519.PublicKey // raw new public key (nil for custodial→custodial)
	Custody      string            // "self" or "custodial"
}

// RotateKeyCustodial sends a rotation request where the server holds the old key.
// For custodial→self: server signs the rotation on behalf, client provides new key material.
// For custodial→custodial: server generates new keypair; key material fields are omitted.
func (c *Client) RotateKeyCustodial(ctx context.Context, req *RotateKeyCustodialRequest) (*RotateKeyResponse, error) {
	ts := time.Now().UTC().Format(time.RFC3339)
	wire := &rotateKeyWireRequest{
		Custody:   req.Custody,
		Timestamp: ts,
	}
	if len(req.NewPublicKey) > 0 {
		wire.NewDID = req.NewDID
		wire.NewPublicKey = base64.RawURLEncoding.EncodeToString(req.NewPublicKey)
	}
	var resp RotateKeyResponse
	if err := c.Put(ctx, "/v1/agents/me/rotate", wire, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SignRotation signs a rotation announcement with the old key.
// Returns the signature as base64 (RFC 4648, no padding).
func SignRotation(oldKey ed25519.PrivateKey, oldDID, newDID, timestamp string) (string, error) {
	payload := CanonicalRotationJSON(oldDID, newDID, timestamp)
	sig := signaturewire.SignBytes(oldKey, []byte(payload))
	return base64.RawStdEncoding.EncodeToString(sig), nil
}

// VerifyRotationSignature verifies a rotation_signature using the old public key.
func VerifyRotationSignature(oldPub ed25519.PublicKey, oldDID, newDID, timestamp, signature string) (bool, error) {
	sig, err := signaturewire.DecodeStd(signature)
	if err != nil {
		return false, fmt.Errorf("decode rotation signature: %w", err)
	}
	payload := CanonicalRotationJSON(oldDID, newDID, timestamp)
	return signaturewire.Verify(signaturewire.Proof{PublicKey: oldPub, Payload: []byte(payload), Signature: sig}), nil
}
