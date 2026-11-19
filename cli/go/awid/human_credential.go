package awid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// HumanCredential is the public credential a human-role act binds: the
// authenticator's credential id and COSE public key, each in unpadded
// base64url, and the relying party id it was made for
// (docs/owner-act-delivery.md, "The credential").
type HumanCredential struct {
	CredentialID string `json:"credential_id"`
	PublicKey    string `json:"public_key"`
	RPID         string `json:"rp_id"`
}

const humanCredentialDomain = "aweb.human-credential/1\n"

// SHA256 is the credential's credential_sha256: the lowercase hex SHA-256 of
// "aweb.human-credential/1\n" followed by its canonical JSON.
func (c HumanCredential) SHA256() (string, error) {
	for _, field := range []string{c.CredentialID, c.PublicKey} {
		if field == "" {
			return "", errors.New("credential_id and public_key are required")
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(field); err != nil {
			return "", errors.New("credential_id and public_key must be unpadded base64url")
		}
	}
	if strings.TrimSpace(c.RPID) == "" || c.RPID != strings.TrimSpace(c.RPID) {
		return "", errors.New("rp_id is required")
	}
	canonical, err := CanonicalJSONValue(map[string]any{
		"credential_id": c.CredentialID, "public_key": c.PublicKey, "rp_id": c.RPID,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(humanCredentialDomain + canonical))
	return hex.EncodeToString(digest[:]), nil
}

// CredentialFingerprint is the first 16 hex characters of a
// credential_sha256, in four groups of four separated by spaces.
func CredentialFingerprint(credentialSHA256 string) string {
	if len(credentialSHA256) < 16 {
		return ""
	}
	prefix := credentialSHA256[:16]
	return prefix[0:4] + " " + prefix[4:8] + " " + prefix[8:12] + " " + prefix[12:16]
}
