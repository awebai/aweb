package awid

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var messageViaPattern = regexp.MustCompile(`\A[a-z][a-z0-9_]{0,31}\z`)

func validateMessageVia(via string) error {
	if !messageViaPattern.MatchString(via) {
		return fmt.Errorf("via must be an ASCII channel kind")
	}
	return nil
}

// Supplied null/empty/malformed values are different from an omitted field.
func signedMessageVia(data []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", err
	}
	raw, ok := fields["via"]
	if !ok {
		return "", nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("invalid via: %w", err)
	}
	if err := validateMessageVia(value); err != nil {
		return "", err
	}
	return value, nil
}

// SignedPayloadVia extracts a channel kind without reconstructing signed bytes.
// Callers must verify the original signature before using it as provenance.
func SignedPayloadVia(payload string) (string, error) {
	return signedMessageVia([]byte(payload))
}

func hasVerifiedProvenance(status VerificationStatus) bool {
	return status == Verified || status == VerifiedLegacy || status == VerifiedCustodial
}

func verifiedPayloadVia(payload string, status VerificationStatus) (string, VerificationStatus) {
	if payload == "" || !hasVerifiedProvenance(status) {
		return "", status
	}
	via, err := SignedPayloadVia(payload)
	if err != nil {
		return "", Failed
	}
	return via, status
}

func (env *MessageEnvelope) UnmarshalJSON(data []byte) error {
	type wire MessageEnvelope
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if _, err := signedMessageVia(data); err != nil {
		return err
	}
	*env = MessageEnvelope(value)
	return nil
}

func (inner *E2EEInnerPayload) UnmarshalJSON(data []byte) error {
	type wire E2EEInnerPayload
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if _, err := signedMessageVia(data); err != nil {
		return err
	}
	*inner = E2EEInnerPayload(value)
	return nil
}
