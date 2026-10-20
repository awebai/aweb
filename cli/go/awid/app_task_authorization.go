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

// TaskBodySHA256 is the bare hex SHA-256 of the canonical JSON of a task body:
// the value a member's task authorization binds as task_body_sha256. The task
// must be a JSON object decoded as map[string]any (with json.Number for
// numbers), so that its keys are sorted like Python's canonical_json_bytes.
func TaskBodySHA256(task map[string]any) (string, error) {
	canonical, err := CanonicalJSONValue(task)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:]), nil
}

// AppTaskAuthorizationSigningBytes is the domain prefix followed by the
// canonical JSON of the authorization payload.
func AppTaskAuthorizationSigningBytes(payload map[string]any) ([]byte, error) {
	canonical, err := CanonicalJSONValue(payload)
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

// PageProposalPrefix domain-separates a page proposal digest
// (docs/page-actions.md §4). It ends in one literal newline byte.
const PageProposalPrefix = "aweb.page-proposal/1\n"

// ProposalSHA256 is the digest a decision binds for one proposal record:
// "sha256:" and the hex SHA-256 of the prefix and the canonical JSON of
// {collection, record_id, value}. Numbers in value must be json.Number, as
// decoded with UseNumber, so they keep their exact integer form.
func ProposalSHA256(collection, recordID string, value any) (string, error) {
	canonical, err := CanonicalJSONValue(map[string]any{
		"collection": collection,
		"record_id":  recordID,
		"value":      value,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(PageProposalPrefix), canonical...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
