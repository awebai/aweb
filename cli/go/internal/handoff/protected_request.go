package handoff

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"

	"github.com/awebai/aw/awid"
)

// RequestKeySigner signs a protected request's envelope with the requester's
// current key, answering that key's did:key and the signature.
type RequestKeySigner func(payload []byte) (didKey string, signature []byte, err error)

// ProtectedRequest is one prepare or receipt request to a protected service,
// made by a restricted requester for one configured scope.
type ProtectedRequest struct {
	Profile *Profile
	// Scope is the operation's complete protected scope; a receipt read uses
	// the scope the operation was prepared under.
	Scope       map[string]any
	RequesterID string
	Method      string
	// Path is the external raw path the request is sent to.
	Path      string
	Body      []byte
	Timestamp string
	Sign      RequestKeySigner
}

var receiptPath = regexp.MustCompile(`^/protected-operations/[^/?#]+$`)

// protectedOperationLabel is the covering-v2 operation of the two protected
// routes, and nothing else.
func protectedOperationLabel(method, path string) (string, error) {
	switch {
	case method == http.MethodPost && path == "/protected-operations":
		return "protected_operation_prepare", nil
	case method == http.MethodGet && receiptPath.MatchString(path):
		return "protected_operation_receipt", nil
	}
	return "", fmt.Errorf("%s %s is not a protected-operation route", method, path)
}

// ProtectedRequestHeaders is the requester proof for r
// (docs/protected-service-profile.md): the existing covering-v2 envelope over
// the profile's request origin, the scope's authority domain, the route's
// operation, the exact body, the service and the scope's SHA-256, signed with
// the requester's key. The requester's stable ID only selects it; the service
// checks its current key and scope grant. A scope the profile does not
// configure, or a signer answer that is not a valid signature over the exact
// envelope, sends nothing.
func ProtectedRequestHeaders(r ProtectedRequest) (http.Header, error) {
	operation, err := protectedOperationLabel(r.Method, r.Path)
	if err != nil {
		return nil, err
	}
	if _, err := r.Profile.BindingFor(r.Scope); err != nil {
		return nil, err
	}
	authority, _ := r.Scope["authority"].(map[string]any)
	domain, _ := authority["domain"].(string)
	scope, err := awid.StrictCanonicalJSON(r.Scope)
	if err != nil {
		return nil, err
	}
	scopeSum := sha256.Sum256(scope)
	payload, err := awid.ControllerRequestPayload(r.Profile.RequestOrigin, r.Method, r.Path, r.Body, r.Timestamp, domain, operation,
		map[string]any{"service_id": r.Profile.ServiceID, "scope_sha256": hex.EncodeToString(scopeSum[:])})
	if err != nil {
		return nil, err
	}
	didKey, signature, err := r.Sign(payload)
	if err != nil {
		return nil, err
	}
	if err := awid.VerifyControllerRequestSignature(didKey, signature, payload); err != nil {
		return nil, fmt.Errorf("the requester's signature does not verify over the exact request: %w", err)
	}
	headers := http.Header{}
	headers.Set("Authorization", "DIDKey "+didKey+" "+base64.RawStdEncoding.EncodeToString(signature))
	headers.Set("X-AWEB-DID-AW", r.RequesterID)
	headers.Set("X-AWEB-Timestamp", r.Timestamp)
	headers.Set("X-AWEB-Signed-Payload", base64.RawURLEncoding.EncodeToString(payload))
	return headers, nil
}
