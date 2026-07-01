package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
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
	DIDLogProof      *DidKeyEvidence
}

type AtomicAddressClaimDIDLogProof struct {
	DIDAW          string  `json:"did_aw"`
	Seq            int     `json:"seq"`
	Operation      string  `json:"operation"`
	PreviousDIDKey *string `json:"previous_did_key"`
	NewDIDKey      string  `json:"new_did_key"`
	PrevEntryHash  *string `json:"prev_entry_hash"`
	StateHash      string  `json:"state_hash"`
	AuthorizedBy   string  `json:"authorized_by"`
	Timestamp      string  `json:"timestamp"`
	Signature      string  `json:"signature"`
}

type AtomicAddressClaimIdentityProof struct {
	Operation         string                        `json:"operation"`
	Domain            string                        `json:"domain"`
	AddressName       string                        `json:"address_name"`
	DIDAW             string                        `json:"did_aw"`
	CurrentDIDKey     string                        `json:"current_did_key"`
	RegistryURL       string                        `json:"registry_url"`
	Timestamp         string                        `json:"timestamp"`
	DryRun            bool                          `json:"dry_run"`
	IdentityCustody   string                        `json:"identity_custody"`
	NamespaceCustody  string                        `json:"namespace_custody"`
	IdentitySignature string                        `json:"identity_signature"`
	DIDLogProof       AtomicAddressClaimDIDLogProof `json:"did_log_proof"`
}

func BuildAtomicAddressClaimIdentityProof(fields AtomicAddressClaimFields, identitySigningKey ed25519.PrivateKey) (*AtomicAddressClaimIdentityProof, error) {
	if identitySigningKey == nil {
		return nil, fmt.Errorf("identity signing key is required")
	}
	pub, ok := identitySigningKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("identity signing key has invalid public key type")
	}
	if strings.TrimSpace(fields.Operation) == "" {
		fields.Operation = AtomicAddressClaimOperation
	}
	if strings.TrimSpace(fields.Timestamp) == "" {
		fields.Timestamp = registryNow().UTC().Format(time.RFC3339)
	}
	if strings.TrimSpace(fields.IdentityCustody) == "" {
		fields.IdentityCustody = string(AddressClaimCustodySelf)
	}
	if strings.TrimSpace(fields.NamespaceCustody) == "" {
		fields.NamespaceCustody = string(AddressClaimCustodySelf)
	}
	fields.CurrentDIDKey = strings.TrimSpace(fields.CurrentDIDKey)
	if fields.CurrentDIDKey == "" {
		fields.CurrentDIDKey = ComputeDIDKey(pub)
	}
	fields.DIDAW = strings.TrimSpace(fields.DIDAW)
	if fields.DIDAW == "" {
		fields.DIDAW = ComputeStableID(pub)
	}
	if did := ComputeDIDKey(pub); did != strings.TrimSpace(fields.CurrentDIDKey) {
		return nil, fmt.Errorf("identity signing key does not match current_did_key")
	}
	logProof := fields.DIDLogProof
	if stableID := ComputeStableID(pub); stableID != strings.TrimSpace(fields.DIDAW) {
		if logProof == nil {
			return nil, fmt.Errorf("identity signing key does not match did_aw and no did log proof was provided")
		}
		if strings.TrimSpace(logProof.NewDIDKey) != strings.TrimSpace(fields.CurrentDIDKey) {
			return nil, fmt.Errorf("did log proof current did:key %q does not match %q", logProof.NewDIDKey, fields.CurrentDIDKey)
		}
	}
	normalized, err := normalizeAtomicAddressClaimFields(fields)
	if err != nil {
		return nil, err
	}
	identityCanonical, err := AtomicAddressClaimIdentityCanonical(normalized)
	if err != nil {
		return nil, err
	}
	identitySignature := base64.RawStdEncoding.EncodeToString(
		ed25519.Sign(identitySigningKey, []byte(identityCanonical)),
	)
	if logProof == nil {
		stateHash := stableIdentityStateHash(normalized.DIDAW, normalized.CurrentDIDKey)
		didLogPayload := CanonicalDidLogPayload(normalized.DIDAW, &DidKeyEvidence{
			Seq:            1,
			Operation:      "register_did",
			PreviousDIDKey: nil,
			NewDIDKey:      normalized.CurrentDIDKey,
			PrevEntryHash:  nil,
			StateHash:      stateHash,
			AuthorizedBy:   normalized.CurrentDIDKey,
			Timestamp:      normalized.Timestamp,
		})
		logProof = &DidKeyEvidence{
			Seq:            1,
			Operation:      "register_did",
			PreviousDIDKey: nil,
			NewDIDKey:      normalized.CurrentDIDKey,
			PrevEntryHash:  nil,
			StateHash:      stateHash,
			AuthorizedBy:   normalized.CurrentDIDKey,
			Timestamp:      normalized.Timestamp,
			Signature: base64.RawStdEncoding.EncodeToString(
				ed25519.Sign(identitySigningKey, []byte(didLogPayload)),
			),
		}
	}
	return &AtomicAddressClaimIdentityProof{
		Operation:         normalized.Operation,
		Domain:            normalized.Domain,
		AddressName:       normalized.AddressName,
		DIDAW:             normalized.DIDAW,
		CurrentDIDKey:     normalized.CurrentDIDKey,
		RegistryURL:       normalized.RegistryURL,
		Timestamp:         normalized.Timestamp,
		DryRun:            normalized.DryRun,
		IdentityCustody:   normalized.IdentityCustody,
		NamespaceCustody:  normalized.NamespaceCustody,
		IdentitySignature: identitySignature,
		DIDLogProof: AtomicAddressClaimDIDLogProof{
			DIDAW:          normalized.DIDAW,
			Seq:            logProof.Seq,
			Operation:      strings.TrimSpace(logProof.Operation),
			PreviousDIDKey: logProof.PreviousDIDKey,
			NewDIDKey:      strings.TrimSpace(logProof.NewDIDKey),
			PrevEntryHash:  logProof.PrevEntryHash,
			StateHash:      strings.TrimSpace(logProof.StateHash),
			AuthorizedBy:   strings.TrimSpace(logProof.AuthorizedBy),
			Timestamp:      strings.TrimSpace(logProof.Timestamp),
			Signature:      strings.TrimSpace(logProof.Signature),
		},
	}, nil
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
