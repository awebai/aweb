package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	A2APublicationOperation = "publish_a2a_route"
	A2ADelegationOperation  = "delegate_a2a_bridge"

	A2ACardDigestAlgSHA256 = "sha256"

	A2AStatusActive  = "active"
	A2AStatusRevoked = "revoked"

	A2ACustodyDelegatedBridge       = "self_to_delegated_bridge"
	A2ACustodyHostedDelegatedBridge = "hosted_to_delegated_bridge"

	A2AAuthoritySelfIdentityKey  = "self_identity_key"
	A2AAuthoritySelfDelegation   = "self_identity_delegation"
	A2AAuthorityHostedSession    = "hosted_session"
	A2AAuthorityHostedDelegation = "hosted_delegation"

	A2APublicationCodePublicationExistsDifferentDigest  = "a2a_publication_exists_different_digest"
	A2APublicationCodePublicationExistsDifferentGateway = "a2a_publication_exists_different_gateway"
	A2APublicationCodeDelegationMissing                 = "a2a_delegation_missing"
	A2APublicationCodeDelegationDigestMismatch          = "a2a_delegation_digest_mismatch"
	A2APublicationCodeDelegationExpired                 = "a2a_delegation_expired"
	A2APublicationCodeDelegationRevoked                 = "a2a_delegation_revoked"
	A2APublicationCodeCardDigestMismatch                = "a2a_card_digest_mismatch"
	A2APublicationCodeCardURLInvalid                    = "a2a_card_url_invalid"
	A2APublicationCodeRPCURLInvalid                     = "a2a_rpc_url_invalid"
	A2APublicationCodeRouteIDInvalid                    = "a2a_route_id_invalid"
	A2APublicationCodeIdentitySignatureInvalid          = "a2a_identity_signature_invalid"
	A2APublicationCodeDelegationSignatureInvalid        = "a2a_delegation_signature_invalid"
	A2APublicationCodeTimestampStale                    = "a2a_timestamp_stale"
	A2APublicationCodeNamespaceNotRegistered            = "a2a_namespace_not_registered"
	A2APublicationCodeAddressNotRegistered              = "a2a_address_not_registered"
	A2APublicationCodeCustodyCombinationUnsupported     = "a2a_custody_combination_unsupported"
	A2APublicationCodeAuthoritySourceInvalid            = "a2a_authority_source_invalid"
	A2APublicationCodePayloadCanonicalization           = "a2a_payload_canonicalization_mismatch"
	A2APublicationCodePrimitiveDisabled                 = "a2a_primitive_disabled"
	A2APublicationCodePrimitiveNotSupported             = "a2a_primitive_not_supported"
)

var (
	a2aRouteIDRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	a2aAssertionIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	a2aDigestHexRE   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	a2aDigestB64RE   = regexp.MustCompile(`^sha256:[A-Za-z0-9+/]+$`)
)

var A2APublicationConflictCodes = []string{
	A2APublicationCodePublicationExistsDifferentDigest,
	A2APublicationCodePublicationExistsDifferentGateway,
	A2APublicationCodeDelegationMissing,
	A2APublicationCodeDelegationDigestMismatch,
	A2APublicationCodeDelegationExpired,
	A2APublicationCodeDelegationRevoked,
	A2APublicationCodeCardDigestMismatch,
	A2APublicationCodeCardURLInvalid,
	A2APublicationCodeRPCURLInvalid,
	A2APublicationCodeRouteIDInvalid,
	A2APublicationCodeIdentitySignatureInvalid,
	A2APublicationCodeDelegationSignatureInvalid,
	A2APublicationCodeTimestampStale,
	A2APublicationCodeNamespaceNotRegistered,
	A2APublicationCodeAddressNotRegistered,
	A2APublicationCodeCustodyCombinationUnsupported,
	A2APublicationCodeAuthoritySourceInvalid,
	A2APublicationCodePayloadCanonicalization,
	A2APublicationCodePrimitiveDisabled,
	A2APublicationCodePrimitiveNotSupported,
}

var A2AAllowedOperations = []string{"send_task", "receive_reply", "cancel_task", "serve_card"}

type A2APublicationConflictError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *A2APublicationConflictError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return fmt.Sprintf("a2a publication failed: %s", e.Code)
	}
	return fmt.Sprintf("a2a publication failed: %s: %s", e.Code, e.Message)
}

type A2APublicationFields struct {
	Operation        string
	AssertionID      string
	Address          string
	DIDAW            string
	CurrentDIDKey    string
	SignerDID        string
	SignerKID        string
	CardURL          string
	RPCURL           string
	RouteID          string
	Tenant           string
	GatewayIdentity  string
	DelegationID     string
	DelegationDigest string
	CardDigestAlg    string
	CardDigest       string
	CardRevision     string
	DefaultForHost   bool
	Status           string
	PublishedAt      string
	ExpiresAt        string
	RegistryURL      string
	IdentityCustody  string
	AuthoritySource  string
}

type A2ADelegationFields struct {
	Operation                string
	DelegationID             string
	DelegatorDIDAW           string
	DelegatorCurrentDIDKey   string
	DelegatedGatewayIdentity string
	Address                  string
	RouteID                  string
	CardURL                  string
	RPCURL                   string
	AllowedOperations        []string
	CardDigestAlg            string
	CardDigest               string
	CustodyMode              string
	AuthoritySource          string
	SignerDID                string
	SignerKID                string
	IssuedAt                 string
	ExpiresAt                string
	Status                   string
	RevokedAt                string
	RevocationReason         string
	RegistryURL              string
}

type A2AWriteResponse struct {
	Status          string `json:"status"`
	AssertionID     string `json:"assertion_id,omitempty"`
	DelegationID    string `json:"delegation_id,omitempty"`
	AssertionDigest string `json:"assertion_digest"`
	Address         string `json:"address"`
	RouteID         string `json:"route_id"`
}

type A2APublicationParams struct {
	A2APublicationFields
	SigningKey ed25519.PrivateKey
}

type A2ADelegationParams struct {
	A2ADelegationFields
	SigningKey ed25519.PrivateKey
}

func A2APublicationCanonical(fields A2APublicationFields) (string, error) {
	normalized, err := normalizeA2APublicationFields(fields)
	if err != nil {
		return "", err
	}
	return CanonicalJSONValue(omitEmpty(map[string]any{
		"operation":         normalized.Operation,
		"assertion_id":      normalized.AssertionID,
		"address":           normalized.Address,
		"did_aw":            normalized.DIDAW,
		"current_did_key":   normalized.CurrentDIDKey,
		"signer_did":        normalized.SignerDID,
		"signer_kid":        normalized.SignerKID,
		"card_url":          normalized.CardURL,
		"rpc_url":           normalized.RPCURL,
		"route_id":          normalized.RouteID,
		"tenant":            normalized.Tenant,
		"gateway_identity":  normalized.GatewayIdentity,
		"delegation_id":     normalized.DelegationID,
		"delegation_digest": normalized.DelegationDigest,
		"card_digest_alg":   normalized.CardDigestAlg,
		"card_digest":       normalized.CardDigest,
		"card_revision":     normalized.CardRevision,
		"default_for_host":  normalized.DefaultForHost,
		"status":            normalized.Status,
		"published_at":      normalized.PublishedAt,
		"expires_at":        normalized.ExpiresAt,
		"registry_url":      normalized.RegistryURL,
		"identity_custody":  normalized.IdentityCustody,
		"authority_source":  normalized.AuthoritySource,
	}))
}

func A2ADelegationCanonical(fields A2ADelegationFields) (string, error) {
	normalized, err := normalizeA2ADelegationFields(fields)
	if err != nil {
		return "", err
	}
	return CanonicalJSONValue(omitEmpty(map[string]any{
		"operation":                  normalized.Operation,
		"delegation_id":              normalized.DelegationID,
		"delegator_did_aw":           normalized.DelegatorDIDAW,
		"delegator_current_did_key":  normalized.DelegatorCurrentDIDKey,
		"delegated_gateway_identity": normalized.DelegatedGatewayIdentity,
		"address":                    normalized.Address,
		"route_id":                   normalized.RouteID,
		"card_url":                   normalized.CardURL,
		"rpc_url":                    normalized.RPCURL,
		"allowed_operations":         normalized.AllowedOperations,
		"card_digest_alg":            normalized.CardDigestAlg,
		"card_digest":                normalized.CardDigest,
		"custody_mode":               normalized.CustodyMode,
		"authority_source":           normalized.AuthoritySource,
		"signer_did":                 normalized.SignerDID,
		"signer_kid":                 normalized.SignerKID,
		"issued_at":                  normalized.IssuedAt,
		"expires_at":                 normalized.ExpiresAt,
		"status":                     normalized.Status,
		"revoked_at":                 normalized.RevokedAt,
		"revocation_reason":          normalized.RevocationReason,
		"registry_url":               normalized.RegistryURL,
	}))
}

func A2ASignedAssertionDigest(canonical, signature string) (string, error) {
	canonical = strings.TrimSpace(canonical)
	if canonical == "" {
		return "", fmt.Errorf("canonical payload is required")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}
	sum := sha256.Sum256(append([]byte(canonical), sig...))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func normalizeA2APublicationFields(fields A2APublicationFields) (A2APublicationFields, error) {
	out := fields
	out.Operation = strings.TrimSpace(firstNonEmpty(out.Operation, A2APublicationOperation))
	if out.Operation != A2APublicationOperation {
		return A2APublicationFields{}, fmt.Errorf("operation must be %q", A2APublicationOperation)
	}
	address, err := normalizeA2AAddress(out.Address)
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.Address = address
	out.AssertionID, err = validateA2AAssertionID(out.AssertionID, "assertion_id")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.DIDAW, err = validateA2ADIDAW(out.DIDAW, "did_aw")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.CurrentDIDKey, err = validateA2ADIDKey(out.CurrentDIDKey, "current_did_key")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.SignerDID, err = validateA2ADIDKey(out.SignerDID, "signer_did")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.SignerKID = strings.TrimSpace(out.SignerKID)
	if out.SignerKID != out.SignerDID+"#ed25519" {
		return A2APublicationFields{}, fmt.Errorf("signer_kid must be signer_did#ed25519")
	}
	out.CardURL, err = normalizeA2AHTTPSURL(out.CardURL, "card_url")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.RPCURL, err = normalizeA2AHTTPSURL(out.RPCURL, "rpc_url")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.RouteID, err = validateA2ARouteID(out.RouteID)
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.Tenant = strings.TrimSpace(out.Tenant)
	out.GatewayIdentity, err = validateA2ADIDAW(out.GatewayIdentity, "gateway_identity")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.DelegationID = strings.TrimSpace(out.DelegationID)
	out.DelegationDigest = strings.TrimSpace(out.DelegationDigest)
	if (out.DelegationID == "") != (out.DelegationDigest == "") {
		return A2APublicationFields{}, fmt.Errorf("delegation_id and delegation_digest must be supplied together")
	}
	if out.DelegationID != "" {
		out.DelegationID, err = validateA2AAssertionID(out.DelegationID, "delegation_id")
		if err != nil {
			return A2APublicationFields{}, err
		}
		if err := validateA2AB64Digest(out.DelegationDigest, "delegation_digest"); err != nil {
			return A2APublicationFields{}, err
		}
	}
	out.CardDigestAlg = strings.ToLower(strings.TrimSpace(firstNonEmpty(out.CardDigestAlg, A2ACardDigestAlgSHA256)))
	if out.CardDigestAlg != A2ACardDigestAlgSHA256 {
		return A2APublicationFields{}, fmt.Errorf("card_digest_alg must be sha256")
	}
	out.CardDigest = strings.TrimSpace(out.CardDigest)
	if !a2aDigestHexRE.MatchString(out.CardDigest) {
		return A2APublicationFields{}, fmt.Errorf("card_digest must be sha256:<64 lowercase hex chars>")
	}
	out.CardRevision = strings.TrimSpace(out.CardRevision)
	if out.CardRevision == "" {
		return A2APublicationFields{}, fmt.Errorf("card_revision is required")
	}
	out.Status = strings.TrimSpace(firstNonEmpty(out.Status, A2AStatusActive))
	if out.Status != A2AStatusActive && out.Status != A2AStatusRevoked {
		return A2APublicationFields{}, fmt.Errorf("status must be active or revoked")
	}
	out.PublishedAt, err = normalizeA2ATime(out.PublishedAt, "published_at")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.ExpiresAt, err = normalizeA2ATime(out.ExpiresAt, "expires_at")
	if err != nil {
		return A2APublicationFields{}, err
	}
	out.RegistryURL, err = canonicalRegistryServerOrigin(out.RegistryURL)
	if err != nil {
		return A2APublicationFields{}, fmt.Errorf("registry_url: %w", err)
	}
	out.IdentityCustody = normalizeAddressClaimCustody(out.IdentityCustody)
	out.AuthoritySource = strings.TrimSpace(out.AuthoritySource)
	return out, nil
}

func normalizeA2ADelegationFields(fields A2ADelegationFields) (A2ADelegationFields, error) {
	out := fields
	out.Operation = strings.TrimSpace(firstNonEmpty(out.Operation, A2ADelegationOperation))
	if out.Operation != A2ADelegationOperation {
		return A2ADelegationFields{}, fmt.Errorf("operation must be %q", A2ADelegationOperation)
	}
	var err error
	out.DelegationID, err = validateA2AAssertionID(out.DelegationID, "delegation_id")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.DelegatorDIDAW, err = validateA2ADIDAW(out.DelegatorDIDAW, "delegator_did_aw")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.DelegatorCurrentDIDKey, err = validateA2ADIDKey(out.DelegatorCurrentDIDKey, "delegator_current_did_key")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.DelegatedGatewayIdentity, err = validateA2ADIDAW(out.DelegatedGatewayIdentity, "delegated_gateway_identity")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.Address, err = normalizeA2AAddress(out.Address)
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.RouteID, err = validateA2ARouteID(out.RouteID)
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.CardURL, err = normalizeA2AHTTPSURL(out.CardURL, "card_url")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.RPCURL, err = normalizeA2AHTTPSURL(out.RPCURL, "rpc_url")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	if len(out.AllowedOperations) == 0 {
		out.AllowedOperations = append([]string(nil), A2AAllowedOperations...)
	}
	if strings.Join(out.AllowedOperations, "\x00") != strings.Join(A2AAllowedOperations, "\x00") {
		return A2ADelegationFields{}, fmt.Errorf("allowed_operations must equal the v1 product operation order")
	}
	out.CardDigestAlg = strings.ToLower(strings.TrimSpace(firstNonEmpty(out.CardDigestAlg, A2ACardDigestAlgSHA256)))
	if out.CardDigestAlg != A2ACardDigestAlgSHA256 {
		return A2ADelegationFields{}, fmt.Errorf("card_digest_alg must be sha256")
	}
	out.CardDigest = strings.TrimSpace(out.CardDigest)
	if !a2aDigestHexRE.MatchString(out.CardDigest) {
		return A2ADelegationFields{}, fmt.Errorf("card_digest must be sha256:<64 lowercase hex chars>")
	}
	out.CustodyMode = strings.TrimSpace(firstNonEmpty(out.CustodyMode, A2ACustodyDelegatedBridge))
	if out.CustodyMode != A2ACustodyDelegatedBridge && out.CustodyMode != A2ACustodyHostedDelegatedBridge {
		return A2ADelegationFields{}, fmt.Errorf("unsupported custody_mode")
	}
	out.AuthoritySource = strings.TrimSpace(out.AuthoritySource)
	out.SignerDID, err = validateA2ADIDKey(out.SignerDID, "signer_did")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.SignerKID = strings.TrimSpace(out.SignerKID)
	if out.SignerKID != out.SignerDID+"#ed25519" {
		return A2ADelegationFields{}, fmt.Errorf("signer_kid must be signer_did#ed25519")
	}
	out.IssuedAt, err = normalizeA2ATime(out.IssuedAt, "issued_at")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.ExpiresAt, err = normalizeA2ATime(out.ExpiresAt, "expires_at")
	if err != nil {
		return A2ADelegationFields{}, err
	}
	out.Status = strings.TrimSpace(firstNonEmpty(out.Status, A2AStatusActive))
	if out.Status != A2AStatusActive && out.Status != A2AStatusRevoked {
		return A2ADelegationFields{}, fmt.Errorf("status must be active or revoked")
	}
	out.RevokedAt = strings.TrimSpace(out.RevokedAt)
	if out.Status == A2AStatusRevoked && out.RevokedAt == "" {
		return A2ADelegationFields{}, fmt.Errorf("revoked_at is required when status is revoked")
	}
	if out.RevokedAt != "" {
		out.RevokedAt, err = normalizeA2ATime(out.RevokedAt, "revoked_at")
		if err != nil {
			return A2ADelegationFields{}, err
		}
	}
	out.RevocationReason = strings.TrimSpace(out.RevocationReason)
	out.RegistryURL, err = canonicalRegistryServerOrigin(out.RegistryURL)
	if err != nil {
		return A2ADelegationFields{}, fmt.Errorf("registry_url: %w", err)
	}
	return out, nil
}

func a2aPublicationConflictFromError(err error) error {
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) {
		return err
	}
	var envelope struct {
		Detail struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"detail"`
	}
	if json.Unmarshal([]byte(registryErr.Detail), &envelope) != nil {
		return err
	}
	code := strings.TrimSpace(envelope.Detail.Code)
	if !knownA2APublicationConflictCode(code) {
		return err
	}
	return &A2APublicationConflictError{
		StatusCode: registryErr.StatusCode,
		Code:       code,
		Message:    strings.TrimSpace(envelope.Detail.Message),
	}
}

func knownA2APublicationConflictCode(code string) bool {
	code = strings.TrimSpace(code)
	for _, known := range A2APublicationConflictCodes {
		if code == known {
			return true
		}
	}
	return false
}

func signedA2APublicationBody(fields A2APublicationFields, signingKey ed25519.PrivateKey) (map[string]any, string, error) {
	if signingKey == nil {
		return nil, "", fmt.Errorf("signing key is required")
	}
	normalized, err := normalizeA2APublicationFields(fields)
	if err != nil {
		return nil, "", err
	}
	if did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != normalized.SignerDID {
		return nil, "", fmt.Errorf("signing key does not match signer_did")
	}
	canonical, err := A2APublicationCanonical(normalized)
	if err != nil {
		return nil, "", err
	}
	body, err := canonicalObject(canonical)
	if err != nil {
		return nil, "", err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(canonical)))
	body["signature"] = signature
	return body, signature, nil
}

func signedA2ADelegationBody(fields A2ADelegationFields, signingKey ed25519.PrivateKey) (map[string]any, string, error) {
	if signingKey == nil {
		return nil, "", fmt.Errorf("signing key is required")
	}
	normalized, err := normalizeA2ADelegationFields(fields)
	if err != nil {
		return nil, "", err
	}
	if did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != normalized.SignerDID {
		return nil, "", fmt.Errorf("signing key does not match signer_did")
	}
	canonical, err := A2ADelegationCanonical(normalized)
	if err != nil {
		return nil, "", err
	}
	body, err := canonicalObject(canonical)
	if err != nil {
		return nil, "", err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, []byte(canonical)))
	body["signature"] = signature
	return body, signature, nil
}

func canonicalObject(canonical string) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal([]byte(canonical), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeA2AAddress(value string) (string, error) {
	raw := strings.ToLower(strings.TrimSpace(value))
	if strings.Count(raw, "/") != 1 {
		return "", fmt.Errorf("address must be domain/name")
	}
	domain, name, _ := strings.Cut(raw, "/")
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || strings.Contains(domain, "..") || strings.ContainsAny(domain, `/\`) {
		return "", fmt.Errorf("invalid address domain")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\.`) {
		return "", fmt.Errorf("invalid address name")
	}
	return domain + "/" + name, nil
}

func validateA2ARouteID(routeID string) (string, error) {
	routeID = strings.TrimSpace(routeID)
	if routeID == "." || routeID == ".." || strings.Contains(routeID, "..") || !a2aRouteIDRE.MatchString(routeID) {
		return "", fmt.Errorf("route_id must be a non-empty path-safe segment")
	}
	return routeID, nil
}

func validateA2AAssertionID(value, fieldName string) (string, error) {
	value = strings.TrimSpace(value)
	if !a2aAssertionIDRE.MatchString(value) {
		return "", fmt.Errorf("%s is invalid", fieldName)
	}
	return value, nil
}

func validateA2ADIDKey(value, fieldName string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "did:key:z") {
		return "", fmt.Errorf("%s must be did:key", fieldName)
	}
	return value, nil
}

func validateA2ADIDAW(value, fieldName string) (string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "did:aw:") {
		return "", fmt.Errorf("%s must be did:aw", fieldName)
	}
	return value, nil
}

func validateA2AB64Digest(value, fieldName string) error {
	if !a2aDigestB64RE.MatchString(strings.TrimSpace(value)) {
		return fmt.Errorf("%s must be sha256:<base64>", fieldName)
	}
	return nil
}

func normalizeA2AHTTPSURL(value, fieldName string) (string, error) {
	raw := strings.TrimSpace(value)
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", fieldName, err)
	}
	if strings.ToLower(parsed.Scheme) != "https" {
		return "", fmt.Errorf("%s must be an absolute https URL", fieldName)
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("%s host is required", fieldName)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("%s must not include userinfo", fieldName)
	}
	if parsed.Fragment != "" {
		return "", fmt.Errorf("%s must not include a fragment", fieldName)
	}
	host := strings.ToLower(parsed.Hostname())
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port := parsed.Port(); port != "" && port != "443" {
		host += ":" + port
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := ""
	if parsed.RawQuery != "" {
		query = "?" + parsed.RawQuery
	}
	return "https://" + host + path + query, nil
}

func normalizeA2ATime(value, fieldName string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", fieldName)
	}
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return "", fmt.Errorf("%s must be RFC3339 UTC seconds with Z", fieldName)
	}
	return ts.UTC().Truncate(time.Second).Format(time.RFC3339), nil
}

func omitEmpty(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) == "" {
				continue
			}
		case nil:
			continue
		}
		out[key] = value
	}
	return out
}
