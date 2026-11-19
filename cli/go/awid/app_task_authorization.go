package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// AppTaskAuthorizationPrefix domain-separates a member's task authorization
// (docs/app-task-requests.md §1) from every other signed artifact. It ends in
// one literal newline byte.
const AppTaskAuthorizationPrefix = "aweb.app-task-authorization/1\n"

// TaskBodySHA256 is the bare hex SHA-256 of the canonical JSON of a task body
// (StrictCanonicalJSON): the value a member's task authorization binds as
// task_body_sha256. Decode the task with UseNumber.
func TaskBodySHA256(task map[string]any) (string, error) {
	canonical, err := StrictCanonicalJSON(task)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// AppTaskAuthorizationSigningBytes is the domain prefix followed by the
// canonical JSON (StrictCanonicalJSON) of the authorization payload.
func AppTaskAuthorizationSigningBytes(payload map[string]any) ([]byte, error) {
	canonical, err := StrictCanonicalJSON(payload)
	if err != nil {
		return nil, err
	}
	return append([]byte(AppTaskAuthorizationPrefix), canonical...), nil
}

// SignAppTaskAuthorization signs a task authorization payload with the
// member's key. The signature is base64url without padding, the one accepted
// encoding.
func SignAppTaskAuthorization(key ed25519.PrivateKey, payload map[string]any) (string, error) {
	signing, err := AppTaskAuthorizationSigningBytes(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signing)), nil
}
