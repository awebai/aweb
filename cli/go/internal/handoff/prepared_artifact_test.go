package handoff

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func logKeyPreparation(t *testing.T) (map[string]any, map[string]any) {
	sent, payload := serverRecordPreparation(t)
	public := make([]byte, 32)
	for i := range public {
		public[i] = byte(i)
	}
	keyID, err := awid.ComputeEncryptionKeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	sent["operation"] = "team.log-key.sign"
	sent["subject"] = map[string]any{"team_id": "h:example.com", "key_id": keyID,
		"public_key": base64.RawStdEncoding.EncodeToString(public), "created_at": "2026-11-12T00:00:00Z"}
	request := payload["request"].(map[string]any)
	key := request["artifact"].(map[string]any)["team_did_key"]
	artifact := map[string]any{"v": 1, "team_key_did": key}
	for name, value := range sent["subject"].(map[string]any) {
		artifact[name] = value
	}
	request["artifact"] = artifact
	for name, value := range sent {
		request[name] = value
	}
	return sent, payload
}

func TestALogKeyPreparationUsesTheSameDigestAndExactPublicRecord(t *testing.T) {
	sent, payload := logKeyPreparation(t)
	if err := verifyPrepared(sent, coveredDigestOf(payload), payload); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"key_id", "public_key", "created_at", "team_id", "signature", "private_key"} {
		sent, payload := logKeyPreparation(t)
		artifact := payload["request"].(map[string]any)["artifact"].(map[string]any)
		artifact[name] = "changed"
		if ErrorCode(verifyPrepared(sent, coveredDigestOf(payload), payload)) != "operation_mismatch" {
			t.Fatalf("accepted changed %s", name)
		}
	}
	// Even a consistent substitution with a recomputed digest must have the
	// correct derived key id, never an arbitrary caller-selected id.
	sent, payload = logKeyPreparation(t)
	sent["subject"].(map[string]any)["key_id"] = "sha256:wrong"
	payload["request"].(map[string]any)["artifact"].(map[string]any)["key_id"] = "sha256:wrong"
	if ErrorCode(verifyPrepared(sent, coveredDigestOf(payload), payload)) != "operation_mismatch" {
		t.Fatal("accepted an unrelated key id")
	}
}

func serverRecordPreparation(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	public, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sent := revokeIntent()
	sent["operation"] = "team.server-record.publish"
	sent["audience"] = "https://registry.example.org"
	sent["subject"] = map[string]any{"server_url": "https://coord.example.org/prefix"}
	request := map[string]any{}
	for k, v := range sent {
		request[k] = v
	}
	request["requester"] = "requester"
	request["policy_ref"] = "aweb.human-assurance/1"
	request["policy_version"] = 1
	request["artifact"] = awid.NewTeamServerRecord(
		"h:example.com", awid.ComputeDIDKey(public), "https://coord.example.org/prefix",
		time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC),
	)
	payload := map[string]any{
		"policy":  map[string]any{"ref": request["policy_ref"], "version": request["policy_version"]},
		"request": request,
	}
	// Use the duplicate-free JSON decoder and numeric forms of an actual reply.
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := decodeObject(raw)
	if !ok {
		t.Fatal("could not decode prepared payload")
	}
	return sent, payload
}

func TestAServerRecordUsesTheSamePreparedDigestAndExactTypedDestination(t *testing.T) {
	sent, payload := serverRecordPreparation(t)
	digest := coveredDigestOf(payload)
	if err := verifyPrepared(sent, digest, payload); err != nil {
		t.Fatal(err)
	}
	request := payload["request"].(map[string]any)
	artifact := request["artifact"].(map[string]any)
	// A consistent subject/artifact substitution still must match the retained
	// bytes and original B2 digest, before a browser link can be shown.
	request["subject"] = map[string]any{"server_url": "https://other.example.org"}
	artifact["server_url"] = "https://other.example.org"
	if ErrorCode(verifyPrepared(sent, digest, payload)) != "operation_mismatch" {
		t.Fatal("a substituted record kept the original digest")
	}
	if ErrorCode(verifyPrepared(sent, coveredDigestOf(payload), payload)) != "operation_mismatch" {
		t.Fatal("a recomputed digest replaced the retained request")
	}
}

func TestAServerRecordRefusesNonConsumerShapesEvenWithAConsistentDigest(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any, map[string]any){
		"team":              func(_ map[string]any, a map[string]any) { a["team_id"] = "other:example.com" },
		"destination":       func(_ map[string]any, a map[string]any) { a["server_url"] = "https://other.example.org" },
		"type":              func(_ map[string]any, a map[string]any) { a["type"] = "aweb.owner-act" },
		"version":           func(_ map[string]any, a map[string]any) { a["v"] = true },
		"expiry":            func(_ map[string]any, a map[string]any) { a["expires_at"] = "2026-11-12T00:10:00Z" },
		"key":               func(_ map[string]any, a map[string]any) { a["team_did_key"] = "did:key:invalid" },
		"timestamp":         func(_ map[string]any, a map[string]any) { a["issued_at"] = "2026-11-12T00:00:00.000Z" },
		"missing timestamp": func(_ map[string]any, a map[string]any) { delete(a, "issued_at") },
		"variant":           func(s map[string]any, _ map[string]any) { s["variant"] = "unknown" },
		"authority": func(s map[string]any, _ map[string]any) {
			s["scope"].(map[string]any)["authority"].(map[string]any)["kind"] = "namespace_controller"
		},
		"extra subject": func(s map[string]any, _ map[string]any) { s["subject"].(map[string]any)["bytes"] = "arbitrary" },
		"noncanonical URL": func(s map[string]any, a map[string]any) {
			s["subject"].(map[string]any)["server_url"] = "https://coord.example.org/"
			a["server_url"] = "https://coord.example.org/"
		},
	} {
		t.Run(name, func(t *testing.T) {
			sent, payload := serverRecordPreparation(t)
			request := payload["request"].(map[string]any)
			mutate(sent, request["artifact"].(map[string]any))
			// Keep the request consistent so this tests the artifact contract,
			// independently of the already-checked request/digest commitment.
			for k, v := range sent {
				request[k] = v
			}
			if err := verifyPrepared(sent, coveredDigestOf(payload), payload); ErrorCode(err) != "operation_mismatch" {
				t.Fatalf("got %v", err)
			}
		})
	}
}
