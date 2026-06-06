package awid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const AtomicAddressClaimOperation = "claim_identity_address"

type AddressClaimCustody string

const (
	AddressClaimCustodySelf            AddressClaimCustody = "self"
	AddressClaimCustodyHostedCustodial AddressClaimCustody = "hosted_custodial"
	addressClaimCustodyHostedHyphen    AddressClaimCustody = "hosted-custodial"
)

const (
	AtomicAddressClaimCodeAddressTakenDifferentOwner    = "address_taken_different_owner"
	AtomicAddressClaimCodeDIDTakenDifferentKey          = "did_taken_different_key"
	AtomicAddressClaimCodeNamespaceAuthorityInvalid     = "namespace_authority_invalid"
	AtomicAddressClaimCodeIdentitySignatureInvalid      = "identity_signature_invalid"
	AtomicAddressClaimCodeTimestampStale                = "timestamp_stale"
	AtomicAddressClaimCodeNamespaceNotRegistered        = "namespace_not_registered"
	AtomicAddressClaimCodePayloadCanonicalization       = "payload_canonicalization_mismatch"
	AtomicAddressClaimCodeCustodyCombinationUnsupported = "custody_combination_unsupported"
	AtomicAddressClaimCodePrimitiveDisabled             = "primitive_disabled"
	AtomicAddressClaimCodePrimitiveNotSupported         = "primitive_not_supported"
	AtomicAddressClaimCodeDIDLogProofRequired           = "did_log_proof_required"
	AtomicAddressClaimCodeDIDLogProofInvalid            = "did_log_proof_invalid"
)

var AtomicAddressClaimConflictCodes = []string{
	AtomicAddressClaimCodeAddressTakenDifferentOwner,
	AtomicAddressClaimCodeDIDTakenDifferentKey,
	AtomicAddressClaimCodeNamespaceAuthorityInvalid,
	AtomicAddressClaimCodeIdentitySignatureInvalid,
	AtomicAddressClaimCodeTimestampStale,
	AtomicAddressClaimCodeNamespaceNotRegistered,
	AtomicAddressClaimCodePayloadCanonicalization,
	AtomicAddressClaimCodeCustodyCombinationUnsupported,
	AtomicAddressClaimCodePrimitiveDisabled,
	AtomicAddressClaimCodePrimitiveNotSupported,
	AtomicAddressClaimCodeDIDLogProofRequired,
	AtomicAddressClaimCodeDIDLogProofInvalid,
}

type AtomicAddressClaimConflictError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *AtomicAddressClaimConflictError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return fmt.Sprintf("atomic address claim failed: %s", e.Code)
	}
	return fmt.Sprintf("atomic address claim failed: %s: %s", e.Code, e.Message)
}

func atomicAddressClaimConflictFromError(err error) error {
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
	if !knownAtomicAddressClaimConflictCode(code) {
		return err
	}
	return &AtomicAddressClaimConflictError{
		StatusCode: registryErr.StatusCode,
		Code:       code,
		Message:    strings.TrimSpace(envelope.Detail.Message),
	}
}

func knownAtomicAddressClaimConflictCode(code string) bool {
	code = strings.TrimSpace(code)
	for _, known := range AtomicAddressClaimConflictCodes {
		if code == known {
			return true
		}
	}
	return false
}

type AtomicAddressClaimFields struct {
	Operation        string
	Domain           string
	AddressName      string
	DIDAW            string
	CurrentDIDKey    string
	RegistryURL      string
	Timestamp        string
	DryRun           bool
	IdentityCustody  string
	NamespaceCustody string
}

func AtomicAddressClaimIdentityCanonical(fields AtomicAddressClaimFields) (string, error) {
	normalized, err := normalizeAtomicAddressClaimFields(fields)
	if err != nil {
		return "", err
	}
	return CanonicalJSONValue(map[string]any{
		"operation":        normalized.Operation,
		"domain":           normalized.Domain,
		"address_name":     normalized.AddressName,
		"did_aw":           normalized.DIDAW,
		"current_did_key":  normalized.CurrentDIDKey,
		"registry_url":     normalized.RegistryURL,
		"timestamp":        normalized.Timestamp,
		"dry_run":          normalized.DryRun,
		"identity_custody": normalized.IdentityCustody,
	})
}

func AtomicAddressClaimIdentityProofHash(identityCanonical, identitySignature string) (string, error) {
	identityCanonical = strings.TrimSpace(identityCanonical)
	if identityCanonical == "" {
		return "", fmt.Errorf("identity canonical payload is required")
	}
	sig, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(identitySignature))
	if err != nil {
		return "", fmt.Errorf("decode identity signature: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte(identityCanonical))
	_, _ = h.Write(sig)
	return "sha256:" + base64.RawStdEncoding.EncodeToString(h.Sum(nil)), nil
}

func AtomicAddressClaimNamespaceCanonical(fields AtomicAddressClaimFields, identityProofHash string) (string, error) {
	normalized, err := normalizeAtomicAddressClaimFields(fields)
	if err != nil {
		return "", err
	}
	identityProofHash = strings.TrimSpace(identityProofHash)
	if identityProofHash == "" {
		return "", fmt.Errorf("identity proof hash is required")
	}
	return CanonicalJSONValue(map[string]any{
		"operation":           normalized.Operation,
		"domain":              normalized.Domain,
		"address_name":        normalized.AddressName,
		"did_aw":              normalized.DIDAW,
		"current_did_key":     normalized.CurrentDIDKey,
		"registry_url":        normalized.RegistryURL,
		"timestamp":           normalized.Timestamp,
		"dry_run":             normalized.DryRun,
		"identity_proof_hash": identityProofHash,
		"namespace_custody":   normalized.NamespaceCustody,
	})
}

func normalizeAtomicAddressClaimFields(fields AtomicAddressClaimFields) (AtomicAddressClaimFields, error) {
	out := fields
	out.Operation = strings.TrimSpace(out.Operation)
	if out.Operation == "" {
		out.Operation = AtomicAddressClaimOperation
	}
	if out.Operation != AtomicAddressClaimOperation {
		return AtomicAddressClaimFields{}, fmt.Errorf("operation must be %q", AtomicAddressClaimOperation)
	}
	out.Domain = canonicalizeDomain(out.Domain)
	if out.Domain == "" {
		return AtomicAddressClaimFields{}, fmt.Errorf("domain is required")
	}
	out.AddressName = strings.ToLower(strings.TrimSpace(out.AddressName))
	if out.AddressName == "" {
		return AtomicAddressClaimFields{}, fmt.Errorf("address name is required")
	}
	if strings.ContainsAny(out.AddressName, `/\.`) || out.AddressName == "." || out.AddressName == ".." {
		return AtomicAddressClaimFields{}, fmt.Errorf("invalid address name %q", out.AddressName)
	}
	out.DIDAW = strings.TrimSpace(out.DIDAW)
	if !strings.HasPrefix(out.DIDAW, "did:aw:") {
		return AtomicAddressClaimFields{}, fmt.Errorf("did_aw must start with did:aw:")
	}
	out.CurrentDIDKey = strings.TrimSpace(out.CurrentDIDKey)
	if !strings.HasPrefix(out.CurrentDIDKey, "did:key:") {
		return AtomicAddressClaimFields{}, fmt.Errorf("current_did_key must start with did:key:")
	}
	registryURL, err := canonicalRegistryServerOrigin(out.RegistryURL)
	if err != nil {
		return AtomicAddressClaimFields{}, fmt.Errorf("registry_url: %w", err)
	}
	out.RegistryURL = registryURL
	out.Timestamp = strings.TrimSpace(out.Timestamp)
	if out.Timestamp == "" {
		return AtomicAddressClaimFields{}, fmt.Errorf("timestamp is required")
	}
	out.IdentityCustody = normalizeAddressClaimCustody(out.IdentityCustody)
	if out.IdentityCustody == "" {
		return AtomicAddressClaimFields{}, fmt.Errorf("identity_custody is required")
	}
	out.NamespaceCustody = normalizeAddressClaimCustody(out.NamespaceCustody)
	if out.NamespaceCustody == "" {
		return AtomicAddressClaimFields{}, fmt.Errorf("namespace_custody is required")
	}
	if out.IdentityCustody == string(AddressClaimCustodyHostedCustodial) && out.NamespaceCustody == string(AddressClaimCustodySelf) {
		return AtomicAddressClaimFields{}, fmt.Errorf("hosted-custodial DID with self-custodial namespace is unsupported")
	}
	return out, nil
}

func normalizeAddressClaimCustody(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(AddressClaimCustodySelf):
		return string(AddressClaimCustodySelf)
	case string(AddressClaimCustodyHostedCustodial), string(addressClaimCustodyHostedHyphen):
		return string(AddressClaimCustodyHostedCustodial)
	default:
		return ""
	}
}
