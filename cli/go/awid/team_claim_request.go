package awid

import (
	"crypto/ed25519"
	"fmt"
	"github.com/awebai/aw/signaturewire"
	"strings"
	"unicode/utf8"
)

const unownedTeamClaimOperation = "claim_unowned_team"

// UnownedTeamClaimRequest binds the host-normalized prospective account before
// ownership effects (docs/unowned-team-claim.md). Account policy stays with
// the host; email and username are signed verbatim.
type UnownedTeamClaimRequest struct {
	AWIDTeamID string `json:"awid_team_id"`
	Email      string `json:"email"`
	Username   string `json:"username"`
	Timestamp  string `json:"timestamp"`
}

func (request UnownedTeamClaimRequest) payload() map[string]any {
	return map[string]any{"operation": unownedTeamClaimOperation, "awid_team_id": strings.TrimSpace(request.AWIDTeamID), "email": request.Email, "username": request.Username, "timestamp": strings.TrimSpace(request.Timestamp)}
}
func (request UnownedTeamClaimRequest) SigningBytes() ([]byte, error) {
	for _, value := range []string{request.AWIDTeamID, request.Email, request.Username, request.Timestamp} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("claim fields are required; correct the request and retry")
		}
	}
	return teamControlPayload(request.payload())
}
func (request UnownedTeamClaimRequest) Sign(key ed25519.PrivateKey) (SignedUnownedTeamClaim, error) {
	payload, err := request.SigningBytes()
	if err != nil {
		return SignedUnownedTeamClaim{}, err
	}
	signature, err := signTeamControlPayload(key, payload)
	if err != nil {
		return SignedUnownedTeamClaim{}, err
	}
	return SignedUnownedTeamClaim{Request: request, SignerDIDKey: ComputeDIDKey(ed25519.PublicKey(key[ed25519.SeedSize:])), Signature: signature}, nil
}
func (request UnownedTeamClaimRequest) verifySignature(proof teamClaimSignature) error {
	payload, err := request.SigningBytes()
	if err != nil {
		return err
	}
	return verifyTeamControlPayload(proof, payload)
}

type teamClaimSignature struct {
	signerDIDKey string
	signature    string
}

func teamControlPayload(fields map[string]any) ([]byte, error) {
	for _, value := range fields {
		if text, ok := value.(string); ok && !utf8.ValidString(text) {
			return nil, fmt.Errorf("team-control fields must be valid Unicode; correct the request and retry")
		}
	}
	payload, err := CanonicalJSONValue(fields)
	if err != nil {
		return nil, fmt.Errorf("encode team-control request: %w; correct the request and retry", err)
	}
	return []byte(payload), nil
}
func signTeamControlPayload(key ed25519.PrivateKey, payload []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("use an Ed25519 private key and retry")
	}
	return signaturewire.SignStd(key, payload), nil
}
func verifyTeamControlPayload(proof teamClaimSignature, payload []byte) error {
	key, err := ExtractPublicKey(proof.signerDIDKey)
	if err != nil {
		return fmt.Errorf("invalid team-control signer: %w; regenerate the request and retry", err)
	}
	signature, err := signaturewire.DecodeStd(proof.signature)
	if err != nil {
		return fmt.Errorf("invalid team-control signature encoding: %w; regenerate the request and retry", err)
	}
	if !signaturewire.Verify(signaturewire.Proof{PublicKey: key, Payload: payload, Signature: signature}) {
		return fmt.Errorf("invalid team-control signature; regenerate it with the controller key and retry")
	}
	return nil
}
