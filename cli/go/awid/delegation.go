package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const NamespaceDelegationVersion = "awid.namespace-delegation.v1"

type ControllerRolloverRecoveryMode string

const (
	ControllerRolloverRecoveryNone      ControllerRolloverRecoveryMode = "none"
	ControllerRolloverRecoveryExactDNS  ControllerRolloverRecoveryMode = "exact_dns"
	ControllerRolloverRecoveryDelegated ControllerRolloverRecoveryMode = "delegated"
)

type NamespaceDelegationPayload struct {
	Version                string  `json:"version"`
	Operation              string  `json:"operation"`
	ParentDomain           string  `json:"parent_domain"`
	ChildDomain            string  `json:"child_domain"`
	ChildControllerDID     string  `json:"child_controller_did"`
	Sequence               int64   `json:"sequence"`
	PreviousDelegationHash *string `json:"previous_delegation_hash"`
}

func ValidateNamespaceDelegationPayload(value NamespaceDelegationPayload) error {
	if value.Version != NamespaceDelegationVersion {
		return fmt.Errorf("invalid delegation version")
	}
	if value.Operation != "delegate" && value.Operation != "rotate" && value.Operation != "revoke" {
		return fmt.Errorf("invalid delegation operation")
	}
	parent, err := canonicalFederationDomain(value.ParentDomain)
	if err != nil || parent != value.ParentDomain {
		return fmt.Errorf("delegation parent domain is invalid or noncanonical")
	}
	child, err := canonicalFederationDomain(value.ChildDomain)
	if err != nil || child != value.ChildDomain {
		return fmt.Errorf("delegation child domain is invalid or noncanonical")
	}
	if !strings.HasSuffix(value.ChildDomain, "."+value.ParentDomain) {
		return fmt.Errorf("delegation child must be a strict parent descendant")
	}
	if boundary, err := publicsuffix.EffectiveTLDPlusOne(value.ChildDomain); err == nil {
		if value.ParentDomain != boundary && !strings.HasSuffix(value.ParentDomain, "."+boundary) {
			return fmt.Errorf("delegation parent is outside registrable boundary")
		}
	}
	if _, err := ExtractPublicKey(value.ChildControllerDID); err != nil {
		return fmt.Errorf("invalid child controller: %w", err)
	}
	if value.Sequence < 1 || (value.Sequence == 1) != (value.PreviousDelegationHash == nil) {
		return fmt.Errorf("invalid delegation predecessor/sequence shape")
	}
	if value.PreviousDelegationHash != nil && !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(*value.PreviousDelegationHash) {
		return fmt.Errorf("invalid previous delegation hash")
	}
	return nil
}

func (payload *NamespaceDelegationPayload) UnmarshalJSON(data []byte) error {
	type plain NamespaceDelegationPayload
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	parsed := NamespaceDelegationPayload(value)
	if err := ValidateNamespaceDelegationPayload(parsed); err != nil {
		return err
	}
	*payload = parsed
	return nil
}

type NamespaceDelegationSignature struct {
	ControllerDID string `json:"controller_did"`
	Signature     string `json:"signature"`
}

func ValidateNamespaceDelegationSignature(value NamespaceDelegationSignature) error {
	if _, err := ExtractPublicKey(value.ControllerDID); err != nil {
		return err
	}
	if strings.Contains(value.Signature, "=") {
		return fmt.Errorf("delegation signature must be unpadded")
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(value.Signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("invalid delegation signature encoding")
	}
	return nil
}

func (signature *NamespaceDelegationSignature) UnmarshalJSON(data []byte) error {
	type plain NamespaceDelegationSignature
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	parsed := NamespaceDelegationSignature(value)
	if err := ValidateNamespaceDelegationSignature(parsed); err != nil {
		return err
	}
	*signature = parsed
	return nil
}

type NamespaceDelegationAssertion struct {
	Payload    NamespaceDelegationPayload     `json:"payload"`
	EntryHash  string                         `json:"entry_hash"`
	Signatures []NamespaceDelegationSignature `json:"signatures"`
}

func (assertion *NamespaceDelegationAssertion) UnmarshalJSON(data []byte) error {
	type plain NamespaceDelegationAssertion
	var value plain
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	parsed := NamespaceDelegationAssertion(value)
	if err := ValidateNamespaceDelegationAssertion(parsed); err != nil {
		return err
	}
	*assertion = parsed
	return nil
}

type NamespaceDelegationLogPage struct {
	Entries      []NamespaceDelegationAssertion `json:"entries"`
	HasMore      bool                           `json:"has_more"`
	NextSequence int64                          `json:"next_sequence"`
	NextCursor   string                         `json:"next_cursor,omitempty"`
	HeadSequence int64                          `json:"head_sequence"`
	HeadHash     string                         `json:"head_hash"`
}

type NamespaceControllerRollover struct {
	RolloverID        string                         `json:"rollover_id"`
	ParentDomain      string                         `json:"parent_domain"`
	OldControllerDID  string                         `json:"old_controller_did"`
	NewControllerDID  string                         `json:"new_controller_did"`
	RecoveryMode      ControllerRolloverRecoveryMode `json:"recovery_mode"`
	RecoveryAssertion *NamespaceDelegationAssertion  `json:"recovery_assertion,omitempty"`
	State             string                         `json:"state"`
	TotalChildren     int                            `json:"total_children"`
	SignedChildren    int                            `json:"signed_children"`
	StartedAt         string                         `json:"started_at"`
	CutoverAt         string                         `json:"cutover_at,omitempty"`
	CompleteAfter     string                         `json:"complete_after,omitempty"`
}

type NamespaceControllerRolloverChild struct {
	ChildDomain string                     `json:"child_domain"`
	HeadHash    string                     `json:"head_hash"`
	Payload     NamespaceDelegationPayload `json:"payload"`
}

type NamespaceControllerRolloverChildren struct {
	Children   []NamespaceControllerRolloverChild `json:"children"`
	HasMore    bool                               `json:"has_more"`
	NextCursor string                             `json:"next_cursor,omitempty"`
}

type NamespaceControllerRolloverSignature struct {
	ChildDomain string `json:"child_domain"`
	HeadHash    string `json:"head_hash"`
	Signature   string `json:"signature"`
}

func CanonicalNamespaceDelegationPayload(payload NamespaceDelegationPayload) ([]byte, error) {
	canonical, err := CanonicalJSONValue(map[string]any{
		"version":                  payload.Version,
		"operation":                payload.Operation,
		"parent_domain":            payload.ParentDomain,
		"child_domain":             payload.ChildDomain,
		"child_controller_did":     payload.ChildControllerDID,
		"sequence":                 payload.Sequence,
		"previous_delegation_hash": payload.PreviousDelegationHash,
	})
	return []byte(canonical), err
}

func NamespaceDelegationEntryHash(canonical []byte) string {
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ValidateNamespaceDelegationAssertion(assertion NamespaceDelegationAssertion) error {
	if err := ValidateNamespaceDelegationPayload(assertion.Payload); err != nil {
		return err
	}
	canonical, err := CanonicalNamespaceDelegationPayload(assertion.Payload)
	if err != nil {
		return err
	}
	if NamespaceDelegationEntryHash(canonical) != assertion.EntryHash {
		return fmt.Errorf("delegation entry hash mismatch")
	}
	if len(assertion.Signatures) == 0 {
		return fmt.Errorf("delegation assertion has no signatures")
	}
	seen := map[string]bool{}
	for _, signature := range assertion.Signatures {
		if err := ValidateNamespaceDelegationSignature(signature); err != nil {
			return err
		}
		if seen[signature.ControllerDID] {
			return fmt.Errorf("duplicate delegation signature controller")
		}
		seen[signature.ControllerDID] = true
		if err := VerifyNamespaceDelegationSignature(signature.ControllerDID, signature.Signature, canonical); err != nil {
			return err
		}
	}
	return nil
}

func VerifyNamespaceDelegationSignature(controllerDID, signature string, canonical []byte) error {
	if len(signature) == 0 || signature[len(signature)-1] == '=' {
		return fmt.Errorf("delegation signature must be unpadded standard base64")
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(signature)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("delegation signature must be canonical Ed25519 base64")
	}
	publicKey, err := ExtractPublicKey(controllerDID)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, raw) {
		return fmt.Errorf("invalid delegation signature")
	}
	return nil
}
