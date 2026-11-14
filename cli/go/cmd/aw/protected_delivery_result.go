package main

import (
	"encoding/base64"
	"encoding/json"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

// retainedSignedResult verifies the confirmed delivery reference. Admission
// and removal consume history and never deliver the artifact locally.
func retainedSignedResult(result []byte, prepared *handoff.Prepared) ([]byte, []byte, string) {
	f, ok := handoff.DecodeObject(result)
	if ok && len(f) == 2 && f["signing"] != nil && f["signature"] != nil {
		return signedResult(result)
	}
	invalid := func() ([]byte, []byte, string) { return nil, nil, "invalid service-owned applied receipt" }
	if !ok || prepared == nil || prepared.OperationID == "" || len(f) != 4 || f["v"] != json.Number("2") || f["type"] != "aweb.protected-delivery" {
		return invalid()
	}
	a, ok := f["artifact"].(map[string]any)
	if !ok {
		return invalid()
	}
	d, ok := f["delivery"].(map[string]any)
	if !ok || len(d) != 3 || d["mode"] != "service_owned" || d["state"] != "applied" {
		return invalid()
	}
	ref, ok := d["reference"].(map[string]any)
	if !ok || len(ref) != 2 || ref["operation_id"] != prepared.OperationID {
		return invalid()
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return invalid()
	}
	signing, signature, reason := signedResult(raw)
	if reason != "" {
		return invalid()
	}
	digest, err := awid.ProtectedArtifactDigest(signing, base64.RawStdEncoding.EncodeToString(signature))
	if err != nil || ref["artifact_sha256"] != digest {
		return invalid()
	}
	return signing, signature, ""
}
