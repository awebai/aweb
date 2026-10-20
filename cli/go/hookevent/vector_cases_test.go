package hookevent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/strictjson"
)

// The definitions below are the source of the two hook vectors. Each key is
// derived from a fixed seed; every negative case has exactly one fault.

var (
	coreSeed   = seedFrom(0x00)
	appSeed    = seedFrom(0x20)
	clientSeed = seedFrom(0x40)
	memberSeed = seedFrom(0x60)
)

func seedFrom(start byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = start + byte(i)
	}
	return seed
}

func keyFrom(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

const (
	teamID      = "demo:example.com"
	eventID     = "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11"
	traceID     = "4bf92f3577b34da6a3ce929d0e0e4736"
	bindingID   = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
	otherUUID   = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
	logsTarget  = "https://logs.example.com/hooks/ingest"
	logsOrigin  = "https://logs.example.com"
	signedAt    = "2026-10-20T12:00:01Z"
	receivedAt  = "2026-10-20T12:00:31Z"
	sampleHMAC  = "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
	sampleSHA   = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	certificate = "c_41"
)

func coreEnvelope() map[string]any {
	return map[string]any{
		"v":             int64(1),
		"type":          "aweb.hook-event",
		"catalog":       map[string]any{"id": CatalogID, "version": int64(CatalogVersion)},
		"hook":          "post-mutation-hook",
		"event_id":      eventID,
		"trace":         map[string]any{"id": traceID, "origin": "signed_request"},
		"team_id":       teamID,
		"producer":      map[string]any{"kind": "core", "origin": "https://aweb.example.com", "kid": "hook-2026-10", "did_key": didKeyOf(keyFrom(coreSeed)), "seq": int64(812)},
		"actor":         map[string]any{"did_key": didKeyOf(keyFrom(memberSeed)), "certificate_id": certificate, "alias": "bond", "authority_mode": "team_cert", "attestations": []any{}},
		"occurred_at":   "2026-10-20T12:00:00.412Z",
		"fired_at":      "2026-10-20T12:00:00.415Z",
		"result_status": "success",
		"payload": map[string]any{
			"mutation_type": "task.updated", "target_ref": "task:" + eventID, "task_ref": "demo-aa1",
			"changes": []any{"status"}, "old_status": "open", "new_status": "in_progress",
		},
	}
}

func appEnvelope() map[string]any {
	env := coreEnvelope()
	env["hook"] = "post-secret-use-hook"
	env["event_id"] = "0192f0c4-7a20-7b51-8e0e-2a64f3c19d02"
	env["trace"] = map[string]any{"id": "0af7651916cd43dd8448eb211c80319c", "origin": "producer"}
	env["producer"] = map[string]any{
		"kind": "app", "origin": "https://secrets.example.com", "app_id": "secrets",
		"installation_id": otherUUID, "generation": int64(2), "kid": "hook-2026-10",
		"did_key": didKeyOf(keyFrom(appSeed)), "seq": int64(41),
	}
	env["actor"] = map[string]any{
		"did_key": didKeyOf(keyFrom(memberSeed)), "certificate_id": certificate, "alias": "bond",
		"authority_mode": "identity_grant", "grant_id": bindingID, "attestations": []any{},
	}
	env["payload"] = map[string]any{
		"action": "completed", "op_kind": "broker", "disposition": "withheld",
		"undeclared_credential": true, "upstream_response_hmac": sampleHMAC,
	}
	return env
}

func clientEnvelope() map[string]any {
	env := coreEnvelope()
	env["hook"] = "post-command-hook"
	env["event_id"] = "0192f0c4-8b31-7c62-9f1f-3b75a4d2ae13"
	env["producer"] = map[string]any{"kind": "client", "did_key": didKeyOf(keyFrom(clientSeed)), "certificate_id": "c_77"}
	env["actor"] = map[string]any{
		"did_key": didKeyOf(keyFrom(clientSeed)), "certificate_id": "c_77", "alias": "bond",
		"authority_mode": "team_cert", "attestations": []any{},
	}
	env["result_status"] = "success"
	env["payload"] = map[string]any{
		"command": "aw id rotate-key", "command_class": "identity_key", "flags": []any{"--json"},
		"local_effects": []any{"identity_key_rotated"}, "exit_status": int64(0),
	}
	return env
}

func systemEnvelope() map[string]any {
	env := coreEnvelope()
	env["event_id"] = "0192f0c4-9c42-7d73-8a2a-4c86b5e3bf24"
	env["actor"] = map[string]any{"authority_mode": "system", "attestations": []any{}}
	env["payload"] = map[string]any{
		"mutation_type": "membership.certificate_revoked", "target_ref": "certificate:c_77",
		"certificate_id": "c_77", "certificate_sha256": sampleSHA, "member_did_key": didKeyOf(keyFrom(clientSeed)),
		"member_alias": "bond", "registry_origin": "https://api.awid.ai",
		"registry_recorded_at": "2026-10-20T11:59:58Z", "observed": true,
	}
	return env
}

func with(env map[string]any, path string, value any) map[string]any {
	parts := strings.Split(path, ".")
	target := env
	for _, part := range parts[:len(parts)-1] {
		target = target[part].(map[string]any)
	}
	if value == nil {
		delete(target, parts[len(parts)-1])
	} else {
		target[parts[len(parts)-1]] = value
	}
	return env
}

func mustCanonical(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := strictjson.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sign(key ed25519.PrivateKey, message []byte) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
}

func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func buildEnvelopeVector(t *testing.T) map[string]any {
	type positive struct {
		name string
		seed []byte
		env  map[string]any
	}
	positives := []positive{
		{"core_task_updated", coreSeed, coreEnvelope()},
		{"core_registry_observed_by_system_actor", coreSeed, systemEnvelope()},
		{"app_secret_use_with_identity_grant_actor", appSeed, appEnvelope()},
		{"client_command_signed_by_its_actor", clientSeed, clientEnvelope()},
	}
	var positiveCases []map[string]any
	for _, p := range positives {
		signing, signature, err := Sign(keyFrom(p.seed), p.env)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		positiveCases = append(positiveCases, map[string]any{
			"name": p.name, "seed_hex": hex.EncodeToString(p.seed), "envelope": p.env,
			"signing_bytes_b64url": b64url(signing), "signature_b64": signature,
		})
	}

	prefixed := func(body []byte) []byte { return append([]byte(EnvelopePrefix), body...) }
	core := keyFrom(coreSeed)
	coreBody := mustCanonical(t, coreEnvelope())
	replace := func(old, new string) []byte {
		if !bytes.Contains(coreBody, []byte(old)) {
			t.Fatalf("core envelope lacks %s", old)
		}
		return prefixed(bytes.Replace(coreBody, []byte(old), []byte(new), 1))
	}

	type negative struct {
		name, layer, err, field, team string
		key                           ed25519.PrivateKey
		signing                       []byte
	}
	env := func(e map[string]any) []byte { return prefixed(mustCanonical(t, e)) }
	negatives := []negative{
		{name: "wrong_prefix", err: "wrong_prefix", key: core, signing: append([]byte("aweb.hook-event/2\n"), coreBody...)},
		{name: "non_canonical_whitespace", err: "not_canonical", key: core, signing: replace(`{"actor"`, `{ "actor"`)},
		{name: "non_canonical_key_order", err: "not_canonical", key: core, signing: replace(`"result_status":"success","team_id"`, `"team_id_":"x","result_status":"success","team_id"`)},
		{name: "float_value", err: "float_value", key: core, signing: replace(`"seq":812`, `"seq":812.0`)},
		{name: "duplicate_key", err: "duplicate_key", key: core, signing: replace(`{"actor"`, `{"v":1,"actor"`)},
		{name: "non_ascii_string", err: "string_not_ascii", key: core, signing: replace(`"alias":"bond"`, `"alias":"b`+"ö"+`nd"`)},
		{name: "null_value", err: "null_value", key: core, signing: replace(`"alias":"bond"`, `"alias":null`)},
		{name: "unknown_envelope_field", err: "unknown_field", key: core, signing: env(with(coreEnvelope(), "note", "x"))},
		{name: "missing_envelope_field", err: "missing_field", key: core, signing: env(with(coreEnvelope(), "fired_at", nil))},
		{name: "unknown_catalog_version", err: "unknown_catalog", key: core, signing: env(with(coreEnvelope(), "catalog.version", int64(2)))},
		{name: "unknown_catalog_id", err: "unknown_catalog", key: core, signing: env(with(coreEnvelope(), "catalog.id", "acme.hooks"))},
		{name: "unknown_hook", err: "unknown_hook", key: core, signing: env(with(coreEnvelope(), "hook", "pre-secret-use-hook"))},
		{name: "trace_id_all_zero", err: "invalid_value", key: core, signing: env(with(coreEnvelope(), "trace.id", "00000000000000000000000000000000"))},
		{name: "fired_before_occurred", err: "invalid_value", key: core, signing: env(with(coreEnvelope(), "fired_at", "2026-10-20T12:00:00.411Z"))},
		{name: "system_actor_with_identity", err: "invalid_value", key: core, signing: env(with(systemEnvelope(), "actor.alias", "bond"))},
		{name: "grant_without_identity_grant_authority", err: "invalid_value", key: core, signing: env(with(coreEnvelope(), "actor.grant_id", otherUUID))},
		{name: "nested_payload_object", err: "invalid_value", key: core, signing: env(with(coreEnvelope(), "payload.task_ref", map[string]any{"id": "demo-aa1"}))},
		{name: "client_signed_server_hook", err: "producer_not_allowed", key: keyFrom(clientSeed), signing: env(with(clientEnvelope(), "hook", "post-mutation-hook"))},
		{name: "app_signed_core_hook", err: "producer_not_allowed", key: keyFrom(appSeed), signing: env(with(appEnvelope(), "hook", "post-mutation-hook"))},
		{name: "client_actor_not_its_signer", err: "actor_not_signer", key: keyFrom(clientSeed), signing: env(with(clientEnvelope(), "actor.did_key", didKeyOf(keyFrom(memberSeed))))},
		{name: "team_mismatch", err: "team_mismatch", key: core, signing: env(coreEnvelope()), team: "other:example.com"},
		{name: "signed_by_another_key", err: "bad_signature", key: keyFrom(memberSeed), signing: env(coreEnvelope())},
		{name: "catalog_unknown_payload_field", layer: "catalog", err: "unknown_field", field: "note", key: core,
			signing: env(with(coreEnvelope(), "payload.note", "x"))},
		{name: "catalog_mutation_field_of_other_type", layer: "catalog", err: "unknown_field", field: "new_status", key: core,
			signing: env(with(with(with(with(coreEnvelope(), "payload.mutation_type", "task.deleted"), "payload.changes", nil), "payload.old_status", nil), "payload.new_status", "closed"))},
	}
	var negativeCases []map[string]any
	for _, n := range negatives {
		layer := n.layer
		if layer == "" {
			layer = "envelope"
		}
		team := n.team
		if team == "" {
			team = teamID
		}
		c := map[string]any{
			"name": n.name, "signing_bytes_b64url": b64url(n.signing), "signature_b64": sign(n.key, n.signing),
			"verify_team_id": team, "layer": layer, "error": n.err,
		}
		if n.field != "" {
			c["field"] = n.field
		}
		negativeCases = append(negativeCases, c)
	}

	before := "POST /v1/charges HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"amount\":100}"
	injected := "Authorization: Bearer test-credential-not-a-secret"
	after := strings.Replace(before, "\r\n\r\n", "\r\n"+injected+"\r\n\r\n", 1)
	digest := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

	return map[string]any{
		"name":   "hook-event-envelope-v1",
		"status": "proposed (aweb-acgh.16.2); frozen once reviewed",
		"scheme": map[string]any{
			"authority":      "docs/hook-events.md, Event envelope",
			"signing_bytes":  "the ASCII prefix 'aweb.hook-event/1' and a newline, then the envelope's canonical JSON",
			"canonical":      "keys sorted, no insignificant whitespace, strings of printable ASCII (0x20-0x7E) escaping only quote and backslash, integers within +-(2^53-1), no floats and no null; a verifier re-encodes and requires identical bytes",
			"signature":      "detached Ed25519 by the producer's did:key, raw standard base64 without padding",
			"order":          "prefix; strict parse (duplicate keys, floats, null, non-ASCII); canonical bytes; envelope fields top-down; catalog; hook; trace; team_id; producer; actor; times; result_status; payload shape; producer kind allowed for the hook; a client event's actor is its signer; the expected team; the signature",
			"layers":         "envelope faults are refused by every envelope verifier; catalog faults pass the envelope layer and are refused by the catalog reader with the stated error and field",
			"producer_kinds": "core {origin, kid, did_key, seq}; app {origin, app_id, installation_id, generation, kid, did_key, seq}; client {did_key, certificate_id}, with no seq",
			"actor":          "authority_mode and attestations always; did_key unless the authority is system, which carries no identity; grant_id exactly when the authority is identity_grant; attestations are at most four unpadded base64url strings, each verified by its own contract",
		},
		"positive_cases": positiveCases,
		"negative_cases": negativeCases,
		"digest_construction": map[string]any{
			"rule":                     "request_sha256 and params_sha256 cover the request before credential injection, never after",
			"request_before_injection": before,
			"injected_header":          injected,
			"request_after_injection":  after,
			"request_sha256":           digest(before),
			"refused_request_sha256":   digest(after),
		},
	}
}

func buildDeliveryVector(t *testing.T) map[string]any {
	target, _ := url.Parse(logsTarget)
	stamp, _ := time.Parse(deliveryTimeLayout, signedAt)
	receive := map[string]any{"audience": logsOrigin, "binding_id": bindingID, "now": receivedAt}

	type positive struct {
		name string
		seed []byte
		env  map[string]any
	}
	var positiveCases []map[string]any
	deliveries := map[string]*Delivery{}
	events := map[string][2]string{}
	for _, p := range []positive{
		{"core_event_to_logs", coreSeed, coreEnvelope()},
		{"client_event_to_logs", clientSeed, clientEnvelope()},
	} {
		key := keyFrom(p.seed)
		signing, signature, err := Sign(key, p.env)
		if err != nil {
			t.Fatal(err)
		}
		d, err := SignDelivery(key, "POST", target, bindingID, signing, signature, stamp)
		if err != nil {
			t.Fatal(err)
		}
		deliveries[p.name] = d
		events[p.name] = [2]string{b64url(signing), signature}
		positiveCases = append(positiveCases, map[string]any{
			"name": p.name, "seed_hex": hex.EncodeToString(p.seed), "target": logsTarget, "binding_id": bindingID,
			"timestamp": signedAt, "event_signing_bytes_b64url": b64url(signing), "event_signature_b64": signature,
			"headers": d.Headers, "body": string(d.Body), "canonical_signed_payload": string(d.SignedPayload),
			"receive": receive,
		})
	}

	base := deliveries["core_event_to_logs"]
	core := keyFrom(coreSeed)
	signed := func(key ed25519.PrivateKey, scheme string, payload map[string]any) map[string]string {
		data := mustCanonical(t, payload)
		return map[string]string{
			"Authorization":     scheme + didKeyOf(key) + " " + sign(key, data),
			SignedPayloadHeader: b64url(data),
			"Content-Type":      "application/json",
		}
	}
	basePayload := func() map[string]any {
		parsed, err := strictjson.ParseCanonicalObject(base.SignedPayload)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	appEmit, err := awid.SignAppEmitCredential(keyFrom(appSeed), "POST", target, teamID, "secrets", "hook-2026-10", base.Body, signedAt)
	if err != nil {
		t.Fatal(err)
	}
	appEmitHeaders := map[string]string{}
	for name := range appEmit.Headers {
		appEmitHeaders[name] = appEmit.Headers.Get(name)
	}
	resolvePayload := basePayload()
	resolvePayload["auth"] = "hook-resolve"
	appEventPayload := map[string]any{
		"v": int64(1), "auth": "app-event", "aud": logsOrigin, "method": "POST", "path": "/hooks/ingest",
		"team_id": teamID, "app_id": "secrets", "kid": "hook-2026-10", "did_key": didKeyOf(keyFrom(appSeed)),
		"body_sha256": basePayload()["body_sha256"], "timestamp": signedAt,
	}
	tamperedHeaders := map[string]string{}
	for name, value := range base.Headers {
		tamperedHeaders[name] = value
	}
	tampered := basePayload()
	tampered["aud"] = "https://evil.example.com"
	tamperedHeaders[SignedPayloadHeader] = b64url(mustCanonical(t, tampered))
	otherEvent := basePayload()
	otherEvent["event_id"] = otherUUID
	otherTeam := basePayload()
	otherTeam["team_id"] = "other:example.com"
	member := keyFrom(memberSeed)
	byMember := basePayload()
	byMember["did_key"] = didKeyOf(member)

	type negative struct {
		name, method, path, body, err string
		headers                       map[string]string
		receive                       map[string]any
	}
	rx := func(key, value string) map[string]any {
		r := map[string]any{"audience": logsOrigin, "binding_id": bindingID, "now": receivedAt}
		r[key] = value
		return r
	}
	body := string(base.Body)
	negatives := []negative{
		{name: "app_event_credential_at_hook_target", headers: appEmitHeaders, err: "wrong_scheme"},
		{name: "hook_resolve_credential_at_hook_target", headers: signed(keyFrom(appSeed), "AWEB-App-Hook-Resolve DIDKey ", resolvePayload), err: "wrong_scheme"},
		{name: "app_event_payload_under_hook_scheme", headers: signed(keyFrom(appSeed), AuthScheme, appEventPayload), err: "wrong_auth"},
		{name: "hook_resolve_payload_under_hook_scheme", headers: signed(core, AuthScheme, resolvePayload), err: "wrong_auth"},
		{name: "payload_altered_after_signing", headers: tamperedHeaders, err: "bad_signature"},
		{name: "cross_audience", headers: base.Headers, receive: rx("audience", "https://logs.other.example.com"), err: "audience_mismatch"},
		{name: "cross_endpoint", headers: base.Headers, path: "/hooks/other", err: "request_mismatch"},
		{name: "tampered_body", headers: base.Headers, body: strings.Replace(body, `"signature":"`, `"signature":"A`, 1), err: "body_mismatch"},
		{name: "stale_timestamp", headers: base.Headers, receive: rx("now", "2026-10-20T12:05:02Z"), err: "timestamp_outside_window"},
		{name: "future_timestamp", headers: base.Headers, receive: rx("now", "2026-10-20T11:55:00Z"), err: "timestamp_outside_window"},
		{name: "wrong_binding", headers: base.Headers, receive: rx("binding_id", otherUUID), err: "binding_mismatch"},
		{name: "credential_names_another_event", headers: signed(core, AuthScheme, otherEvent), err: "event_mismatch"},
		{name: "credential_names_another_team", headers: signed(core, AuthScheme, otherTeam), err: "team_mismatch"},
		{name: "signer_is_not_the_producer", headers: signed(member, AuthScheme, byMember), err: "producer_mismatch"},
	}
	var negativeCases []map[string]any
	for _, n := range negatives {
		method, path, b, r := n.method, n.path, n.body, n.receive
		if method == "" {
			method = "POST"
		}
		if path == "" {
			path = base.Path
		}
		if b == "" {
			b = body
		}
		if r == nil {
			r = receive
		}
		negativeCases = append(negativeCases, map[string]any{
			"name": n.name, "method": method, "path": path, "headers": n.headers, "body": b,
			"receive": r, "error": n.err,
		})
	}

	return map[string]any{
		"name":   "hook-delivery-credential-v1",
		"status": "proposed (aweb-acgh.16.2); frozen once reviewed",
		"scheme": map[string]any{
			"authority":       "docs/hook-events.md, Delivery",
			"authorization":   "AWEB-Hook DIDKey <did:key> <signature>, the signature over the canonical signed payload, raw standard base64 without padding",
			"signed_payload":  "X-AWEB-Signed-Payload carries the canonical payload, unpadded base64url",
			"payload_fields":  "v, auth (hook-delivery), aud (the target's origin), method, path (raw path and query), body_sha256, team_id, binding_id, event_id, producer, kid, did_key, timestamp",
			"producer":        "core, app:<app_id> or client:<certificate_id>; kid is the server producer's kid, or member for a client producer",
			"body":            "canonical JSON {hook_event: unpadded base64url signing bytes, signature: the envelope signature}",
			"timestamp":       "UTC to the second; refused when more than 300 seconds from the receiver's clock",
			"order":           "scheme; signed payload strict and canonical; signature by the header did:key; auth; payload fields; did_key equals the header's; v; aud; method and path; body_sha256; timestamp; binding_id; body; the event (with the credential's team); event_id; producer, kid and did_key equal the event's producer",
			"receive_options": "what the target knows independently: its own public origin, the binding the delivery must name, and its clock",
		},
		"positive_cases": positiveCases,
		"negative_cases": negativeCases,
	}
}
