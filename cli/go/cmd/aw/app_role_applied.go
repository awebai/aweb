package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

// appliedActFor verifies history from a confirmed service-owned receipt. Unlike
// signedActFor, it grants no current delivery authority and never calls a POST.
func appliedActFor(operationID string, intent map[string]any, authority string, result []byte, now time.Time) (*signedAct, error) {
	invalid := func() (*signedAct, error) {
		return nil, withErrorCode("signed_act_invalid", fmt.Errorf("invalid service-owned applied receipt"))
	}
	fields, ok := handoff.DecodeObject(result)
	if !ok || len(fields) != 4 || fields["v"] != json.Number("2") || fields["type"] != "aweb.protected-delivery" {
		return invalid()
	}
	artifact, ok := fields["artifact"].(map[string]any)
	if !ok || len(artifact) != 2 {
		return invalid()
	}
	delivery, ok := fields["delivery"].(map[string]any)
	if !ok || len(delivery) != 3 || delivery["mode"] != "service_owned" || delivery["state"] != "applied" {
		return invalid()
	}
	reference, ok := delivery["reference"].(map[string]any)
	if !ok || len(reference) != 2 || reference["operation_id"] != operationID {
		return invalid()
	}
	encoded, _ := artifact["signing"].(string)
	signing, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || !bytes.HasPrefix(signing, []byte(awid.OwnerActPrefix)) {
		return invalid()
	}
	act, ok := handoff.DecodeObject(signing[len(awid.OwnerActPrefix):])
	if !ok {
		return invalid()
	}
	issued, _ := act["issued_at"].(string)
	originalTime, err := time.Parse("2006-01-02T15:04:05Z", issued)
	if err != nil || originalTime.After(now.Add(time.Minute)) {
		return invalid()
	}
	legacyResult, err := json.Marshal(artifact)
	if err != nil {
		return invalid()
	}
	// The unchanged verifier still enforces exact bytes, intent, signature and
	// original structural/lifetime bounds, evaluated at issuance for history.
	checked, err := signedActFor(intent, authority, legacyResult, originalTime)
	if err != nil {
		return nil, err
	}
	digest, err := awid.ProtectedArtifactDigest(checked.Signing, checked.Signature)
	if err != nil || reference["artifact_sha256"] != digest {
		return invalid()
	}
	return checked, nil
}
