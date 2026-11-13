package handoff

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

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

var (
	receiptPath = regexp.MustCompile(`^/protected-operations/[^/?#]+$`)
	executePath = regexp.MustCompile(`^/protected-operations/[^/?#]+/execute$`)
)

// admissionPolicyPath is the policy read's route; its query names the team.
const admissionPolicyPath = "/protected-admission-policies"

const admissionPolicyReadLabel = "protected_admission_policy_read"

// protectedOperationLabel is the covering-v2 operation of the protected
// routes, and nothing else.
func protectedOperationLabel(method, path string) (string, error) {
	switch {
	case method == http.MethodPost && path == "/protected-operations":
		return "protected_operation_prepare", nil
	case method == http.MethodGet && receiptPath.MatchString(path):
		return "protected_operation_receipt", nil
	case method == http.MethodPost && executePath.MatchString(path):
		return "protected_operation_execute", nil
	case method == http.MethodGet && strings.HasPrefix(path, admissionPolicyPath+"?"):
		return admissionPolicyReadLabel, nil
	}
	return "", fmt.Errorf("%s %s is not a protected-operation route", method, path)
}

// AdmissionPolicyPath is the policy read's exact path and query for team.
func AdmissionPolicyPath(team string) string {
	return admissionPolicyPath + "?" + url.Values{"team_id": {team}}.Encode()
}

// requestDomain is the authority domain r's envelope binds. An operation's
// scope must be one the profile configures; a policy read's scope is exactly
// this service and one team the profile binds a controller for, read from
// its own path and nothing else.
func requestDomain(r ProtectedRequest, operation string) (string, error) {
	if operation != admissionPolicyReadLabel {
		if _, err := r.Profile.BindingFor(r.Scope); err != nil {
			return "", err
		}
		authority, _ := r.Scope["authority"].(map[string]any)
		domain, _ := authority["domain"].(string)
		return domain, nil
	}
	team, _ := r.Scope["team_id"].(string)
	if !exactMembers(r.Scope, []string{"service_id", "team_id"}) || r.Scope["service_id"] != r.Profile.ServiceID || r.Path != AdmissionPolicyPath(team) || len(r.Body) != 0 {
		return "", coded("profile_scope_refused", errors.New("the policy read is not exactly this service and one team's path"))
	}
	domain, ok := r.Profile.teamDomain(team)
	if !ok {
		return "", coded("profile_scope_refused", fmt.Errorf("the profile configures no controller for team %s", team))
	}
	return domain, nil
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
	domain, err := requestDomain(r, operation)
	if err != nil {
		return nil, err
	}
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
