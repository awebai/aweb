package conformance_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
	"github.com/gowebpki/jcs"
)

//go:embed vectors/*.json
var vectorsFS embed.FS

// --- message-signing-v1 ---

type messageSigningVector struct {
	Name             string        `json:"name"`
	SigningSeedHex   string        `json:"signing_seed_hex"`
	SigningDIDKey    string        `json:"signing_did_key"`
	Message          messageFields `json:"message"`
	CanonicalPayload string        `json:"canonical_payload"`
	SignatureB64     string        `json:"signature_b64"`
}

type messageFields struct {
	From         string `json:"from"`
	FromDID      string `json:"from_did"`
	To           string `json:"to"`
	ToDID        string `json:"to_did"`
	Type         string `json:"type"`
	MessageID    string `json:"message_id"`
	Subject      string `json:"subject"`
	Body         string `json:"body"`
	Timestamp    string `json:"timestamp"`
	FromStableID string `json:"from_stable_id"`
	ToStableID   string `json:"to_stable_id"`
}

func TestMessageSigningVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/message-signing-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []messageSigningVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			seed, err := hex.DecodeString(v.SigningSeedHex)
			if err != nil {
				t.Fatal(err)
			}
			key := ed25519.NewKeyFromSeed(seed)

			// Verify did:key matches seed.
			got := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
			if got != v.SigningDIDKey {
				t.Fatalf("ComputeDIDKey: got %s, want %s", got, v.SigningDIDKey)
			}

			env := &awid.MessageEnvelope{
				From:         v.Message.From,
				FromDID:      v.Message.FromDID,
				To:           v.Message.To,
				ToDID:        v.Message.ToDID,
				Type:         v.Message.Type,
				MessageID:    v.Message.MessageID,
				Subject:      v.Message.Subject,
				Body:         v.Message.Body,
				Timestamp:    v.Message.Timestamp,
				FromStableID: v.Message.FromStableID,
				ToStableID:   v.Message.ToStableID,
			}

			// Test canonical payload matches expected.
			canonical := awid.CanonicalJSON(env)
			if canonical != v.CanonicalPayload {
				t.Errorf("CanonicalJSON:\n  got:  %s\n  want: %s", canonical, v.CanonicalPayload)
			}

			// Test signing produces expected signature.
			sig, err := awid.SignMessage(key, env)
			if err != nil {
				t.Fatal(err)
			}
			if sig != v.SignatureB64 {
				t.Errorf("SignMessage:\n  got:  %s\n  want: %s", sig, v.SignatureB64)
			}

			// Test verification succeeds.
			env.Signature = v.SignatureB64
			env.SigningKeyID = v.SigningDIDKey
			status, verifyErr := awid.VerifyMessage(env)
			if verifyErr != nil {
				t.Errorf("VerifyMessage error: %v", verifyErr)
			}
			if status != awid.Verified {
				t.Errorf("VerifyMessage: got %s, want %s", status, awid.Verified)
			}
		})
	}
}

// --- stable-id-v1 ---

type stableIDVector struct {
	Name         string `json:"name"`
	SeedHex      string `json:"seed_hex"`
	DIDKey       string `json:"did_key"`
	PublicKeyHex string `json:"public_key_hex"`
	StableIDAW   string `json:"stable_id_aw"`
}

func TestStableIDVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/stable-id-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []stableIDVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := awid.ExtractPublicKey(v.DIDKey)
			if err != nil {
				t.Fatal(err)
			}

			// Verify public key hex matches.
			if hex.EncodeToString(pub) != v.PublicKeyHex {
				t.Errorf("public key hex: got %s, want %s", hex.EncodeToString(pub), v.PublicKeyHex)
			}

			gotAW := awid.ComputeStableID(pub)
			if gotAW != v.StableIDAW {
				t.Errorf("ComputeStableID: got %s, want %s", gotAW, v.StableIDAW)
			}
		})
	}
}

// --- identity-log-v1 ---

type identityLogVectors struct {
	KeySeeds map[string]string `json:"key_seeds"`
	Mapping  struct {
		DIDAW         string `json:"did_aw"`
		InitialDIDKey string `json:"initial_did_key"`
		RotatedDIDKey string `json:"rotated_did_key"`
	} `json:"mapping"`
	Entries []identityLogEntryVector `json:"entries"`
}

type identityLogEntryVector struct {
	Name                  string         `json:"name"`
	Comment               string         `json:"comment"`
	StatePayload          map[string]any `json:"state_payload"`
	CanonicalStatePayload string         `json:"canonical_state_payload"`
	StateHash             string         `json:"state_hash"`
	EntryPayload          map[string]any `json:"entry_payload"`
	CanonicalEntryPayload string         `json:"canonical_entry_payload"`
	EntryHash             string         `json:"entry_hash"`
	SignatureB64          string         `json:"signature_b64"`
}

func TestIdentityLogVectors(t *testing.T) {
	data := readRootVector(t, "identity-log-v1.json")
	var vectors identityLogVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	initialSeed, err := hex.DecodeString(vectors.KeySeeds["initial_seed_hex"])
	if err != nil {
		t.Fatal(err)
	}
	rotatedSeed, err := hex.DecodeString(vectors.KeySeeds["rotated_seed_hex"])
	if err != nil {
		t.Fatal(err)
	}
	initialKey := ed25519.NewKeyFromSeed(initialSeed)
	rotatedKey := ed25519.NewKeyFromSeed(rotatedSeed)
	if got := awid.ComputeDIDKey(initialKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.InitialDIDKey {
		t.Fatalf("initial did:key: got %s, want %s", got, vectors.Mapping.InitialDIDKey)
	}
	if got := awid.ComputeDIDKey(rotatedKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.RotatedDIDKey {
		t.Fatalf("rotated did:key: got %s, want %s", got, vectors.Mapping.RotatedDIDKey)
	}
	if got := awid.ComputeStableID(initialKey.Public().(ed25519.PublicKey)); got != vectors.Mapping.DIDAW {
		t.Fatalf("did:aw: got %s, want %s", got, vectors.Mapping.DIDAW)
	}

	seedByDID := map[string][]byte{
		vectors.Mapping.InitialDIDKey: initialSeed,
		vectors.Mapping.RotatedDIDKey: rotatedSeed,
	}
	var previousEntryHash string
	for _, entry := range vectors.Entries {
		t.Run(entry.Name, func(t *testing.T) {
			statePayload, err := awid.CanonicalJSONValue(entry.StatePayload)
			if err != nil {
				t.Fatal(err)
			}
			if statePayload != entry.CanonicalStatePayload {
				t.Fatalf("state canonical:\n got:  %s\n want: %s", statePayload, entry.CanonicalStatePayload)
			}
			stateHash := sha256.Sum256([]byte(statePayload))
			if got := hex.EncodeToString(stateHash[:]); got != entry.StateHash {
				t.Fatalf("state_hash: got %s, want %s", got, entry.StateHash)
			}
			requireNoAddressFields(t, entry.StatePayload)

			entryPayload, err := awid.CanonicalJSONValue(entry.EntryPayload)
			if err != nil {
				t.Fatal(err)
			}
			requireNoAddressFields(t, entry.EntryPayload)
			if entryPayload != entry.CanonicalEntryPayload {
				t.Fatalf("entry canonical:\n got:  %s\n want: %s", entryPayload, entry.CanonicalEntryPayload)
			}
			entryHash := sha256.Sum256([]byte(entryPayload))
			if got := hex.EncodeToString(entryHash[:]); got != entry.EntryHash {
				t.Fatalf("entry_hash: got %s, want %s", got, entry.EntryHash)
			}
			if got := nullableString(entry.EntryPayload["prev_entry_hash"]); got != previousEntryHash {
				t.Fatalf("prev_entry_hash: got %q, want %q", got, previousEntryHash)
			}
			authorizedBy, ok := entry.EntryPayload["authorized_by"].(string)
			if !ok || authorizedBy == "" {
				t.Fatalf("missing authorized_by")
			}
			seed, ok := seedByDID[authorizedBy]
			if !ok {
				t.Fatalf("unknown authorized_by %s", authorizedBy)
			}
			key := ed25519.NewKeyFromSeed(seed)
			signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, []byte(entryPayload)))
			if signature != entry.SignatureB64 {
				t.Fatalf("signature:\n got:  %s\n want: %s", signature, entry.SignatureB64)
			}
			signatureBytes, err := base64.RawStdEncoding.DecodeString(entry.SignatureB64)
			if err != nil {
				t.Fatal(err)
			}
			publicKey := key.Public().(ed25519.PublicKey)
			if !ed25519.Verify(publicKey, []byte(entryPayload), signatureBytes) {
				t.Fatalf("signature did not verify against canonical entry payload")
			}
			tamperedPayloadMap := cloneMap(entry.EntryPayload)
			tamperedPayloadMap["state_hash"] = strings.Repeat("0", 64)
			tamperedPayload, err := awid.CanonicalJSONValue(tamperedPayloadMap)
			if err != nil {
				t.Fatal(err)
			}
			if ed25519.Verify(publicKey, []byte(tamperedPayload), signatureBytes) {
				t.Fatalf("tampered state_hash unexpectedly verified")
			}
		})
		previousEntryHash = entry.EntryHash
	}
}

func readRootVector(t *testing.T, name string) []byte {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, "docs", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireNoAddressFields(t *testing.T, payload map[string]any) {
	t.Helper()
	for _, field := range []string{"address", "handle", "server"} {
		if _, ok := payload[field]; ok {
			t.Fatalf("identity vector payload must not contain %q", field)
		}
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func nullableString(value any) string {
	if value == nil {
		return ""
	}
	if out, ok := value.(string); ok {
		return out
	}
	return ""
}

// --- a2a-v1 ---

type a2aVector struct {
	Source             a2aSource      `json:"source"`
	SchemaValidation   a2aSchema      `json:"schema_validation"`
	CardDigestContract a2aCardDigest  `json:"card_digest_contract"`
	AgentCards         []a2aCardCase  `json:"agent_cards"`
	JSONRPC            []a2aRPCCase   `json:"jsonrpc"`
	BridgeReplies      []a2aReplyCase `json:"bridge_replies"`
}

type a2aSource struct {
	Name      string   `json:"name"`
	Repo      string   `json:"repo"`
	Tag       string   `json:"tag"`
	Commit    string   `json:"commit"`
	ProtoPath string   `json:"proto_path"`
	SpecPath  string   `json:"spec_path"`
	Notes     []string `json:"normative_notes"`
}

type a2aCardDigest struct {
	Algorithm        string   `json:"algorithm"`
	Encoding         string   `json:"encoding"`
	Canonicalization string   `json:"canonicalization"`
	ExcludedFields   []string `json:"excluded_fields"`
}

type a2aSchema struct {
	GeneratorScript             string   `json:"generator_script"`
	GeneratorPlugin             string   `json:"generator_plugin"`
	GeneratedSchemaSHA256       string   `json:"generated_schema_sha256"`
	GoogleAPIsInclude           string   `json:"googleapis_include"`
	AgentCardProperties         []string `json:"agent_card_properties"`
	AgentInterfaceProperties    []string `json:"agent_interface_properties"`
	AgentCapabilitiesProperties []string `json:"agent_capabilities_properties"`
	AgentSkillProperties        []string `json:"agent_skill_properties"`
}

type a2aCardCase struct {
	Name                 string         `json:"name"`
	Path                 string         `json:"path"`
	CanonicalNoSignature string         `json:"canonical_no_signatures"`
	Digest               string         `json:"digest"`
	Card                 map[string]any `json:"card"`
}

type a2aRPCCase struct {
	Name    string         `json:"name"`
	Kind    string         `json:"kind"`
	Method  string         `json:"method"`
	Payload map[string]any `json:"payload"`
}

type a2aReplyCase struct {
	Name              string `json:"name"`
	CurrentTaskID     string `json:"current_task_id"`
	CurrentContextID  string `json:"current_context_id"`
	CurrentTaskState  string `json:"current_task_state"`
	Reply             string `json:"reply"`
	ExpectedAction    string `json:"expected_action"`
	ExpectedTaskState string `json:"expected_task_state"`
}

type a2aAWIDPublicationVector struct {
	Version          string   `json:"version"`
	FixtureKind      string   `json:"fixture_kind"`
	Notes            []string `json:"notes"`
	Canonicalization string   `json:"canonicalization"`
	Publication      struct {
		Payload   map[string]any `json:"payload"`
		Canonical string         `json:"canonical"`
		Signature string         `json:"signature"`
	} `json:"publication"`
	Delegation struct {
		Payload   map[string]any `json:"payload"`
		Canonical string         `json:"canonical"`
		Signature string         `json:"signature"`
	} `json:"delegation"`
	ConflictCodes []string `json:"conflict_codes"`
}

func TestA2AV1AgentCardVectors(t *testing.T) {
	vector := readA2AVector(t)

	if vector.Source.Repo != "https://github.com/a2aproject/A2A" ||
		vector.Source.Tag != "v1.0.1" ||
		vector.Source.Commit != "3303592588e388e62e0f69f701af531d2f4e3991" ||
		vector.Source.ProtoPath != "specification/a2a.proto" {
		t.Fatalf("unexpected A2A source pin: %+v", vector.Source)
	}
	requireA2ASchemaValidationPin(t, vector.SchemaValidation)
	if vector.CardDigestContract.Algorithm != "sha256" {
		t.Fatalf("digest algorithm: got %q, want sha256", vector.CardDigestContract.Algorithm)
	}
	if vector.CardDigestContract.Encoding != "sha256:<lowercase-hex>" {
		t.Fatalf("digest encoding: got %q", vector.CardDigestContract.Encoding)
	}
	if len(vector.CardDigestContract.ExcludedFields) != 1 || vector.CardDigestContract.ExcludedFields[0] != "signatures" {
		t.Fatalf("digest excluded fields: got %#v, want [signatures]", vector.CardDigestContract.ExcludedFields)
	}

	for _, tc := range vector.AgentCards {
		t.Run(tc.Name, func(t *testing.T) {
			requireA2ACardKeysMatchGeneratedSchema(t, vector.SchemaValidation, tc.Card)
			requireA2ACardHasNoLegacyFields(t, tc.Card)
			requireA2ACardVersionDistinction(t, tc.Card)
			requireA2ACardModesAreMediaTypes(t, tc.Card)
			requireA2ACardCapabilitiesAreV1(t, tc.Card)
			requireA2ACardInterfaces(t, tc)

			cardForDigest := cloneMap(tc.Card)
			delete(cardForDigest, "signatures")
			canonical, err := awid.CanonicalJSONValue(cardForDigest)
			if err != nil {
				t.Fatal(err)
			}
			if canonical != tc.CanonicalNoSignature {
				t.Fatalf("canonical_no_signatures:\n got:  %s\n want: %s", canonical, tc.CanonicalNoSignature)
			}
			jcsCanonical, err := canonicalJSONWithJCS(cardForDigest)
			if err != nil {
				t.Fatal(err)
			}
			if jcsCanonical != canonical {
				t.Fatalf("independent RFC8785/JCS canonicalization mismatch:\n jcs:  %s\n awid: %s", jcsCanonical, canonical)
			}
			sum := sha256.Sum256([]byte(canonical))
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != tc.Digest {
				t.Fatalf("digest: got %s, want %s", got, tc.Digest)
			}
		})
	}
}

func canonicalJSONWithJCS(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(data)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}

func requireA2ASchemaValidationPin(t *testing.T, schema a2aSchema) {
	t.Helper()
	if schema.GeneratorScript != "scripts/proto_to_json_schema.sh" {
		t.Fatalf("schema generator script: got %q", schema.GeneratorScript)
	}
	if schema.GeneratorPlugin != "github.com/bufbuild/protoschema-plugins/cmd/protoc-gen-jsonschema@v0.5.2" {
		t.Fatalf("schema generator plugin: got %q", schema.GeneratorPlugin)
	}
	if schema.GeneratedSchemaSHA256 != "ba4b702b5edbdcbfe972c272484eb38e1fcd72af3c0b7eaa114b50e97455d8dd" {
		t.Fatalf("generated schema sha256: got %q", schema.GeneratedSchemaSHA256)
	}
	for name, values := range map[string][]string{
		"agent_card_properties":         schema.AgentCardProperties,
		"agent_interface_properties":    schema.AgentInterfaceProperties,
		"agent_capabilities_properties": schema.AgentCapabilitiesProperties,
		"agent_skill_properties":        schema.AgentSkillProperties,
	} {
		if len(values) == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

func requireA2ACardKeysMatchGeneratedSchema(t *testing.T, schema a2aSchema, card map[string]any) {
	t.Helper()
	requireKeysInSet(t, "AgentCard", card, schema.AgentCardProperties)
	if capabilities, ok := card["capabilities"].(map[string]any); ok {
		requireKeysInSet(t, "AgentCapabilities", capabilities, schema.AgentCapabilitiesProperties)
	}
	if interfaces, ok := card["supportedInterfaces"].([]any); ok {
		for _, value := range interfaces {
			iface, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("supportedInterfaces entry is not an object: %v", value)
			}
			requireKeysInSet(t, "AgentInterface", iface, schema.AgentInterfaceProperties)
		}
	}
	if skills, ok := card["skills"].([]any); ok {
		for _, value := range skills {
			skill, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("skills entry is not an object: %v", value)
			}
			requireKeysInSet(t, "AgentSkill", skill, schema.AgentSkillProperties)
		}
	}
}

func requireKeysInSet(t *testing.T, label string, object map[string]any, allowed []string) {
	t.Helper()
	allowedSet := stringSet(allowed)
	for key := range object {
		if !allowedSet[key] {
			t.Fatalf("%s field %q is not in pinned A2A generated schema field set", label, key)
		}
	}
}

func TestA2AV1NegativeStructuralFixtures(t *testing.T) {
	vector := readA2AVector(t)
	if len(vector.AgentCards) == 0 {
		t.Fatalf("missing agent card fixtures")
	}

	t.Run("top_level_protocol_version_rejected", func(t *testing.T) {
		card := cloneMap(vector.AgentCards[0].Card)
		card["protocolVersion"] = "1.0"
		if !containsString(a2aLegacyTopLevelFields(card), "protocolVersion") {
			t.Fatalf("expected top-level protocolVersion to be detected as legacy/non-v1")
		}
	})

	t.Run("agent_card_version_confused_with_protocol_version", func(t *testing.T) {
		card := cloneMap(vector.AgentCards[0].Card)
		card["version"] = "1.0"
		if !a2aCardVersionLooksLikeProtocolVersion(card) {
			t.Fatalf("expected AgentCard.version 1.0 to be detected as protocol-version confusion")
		}
	})

	t.Run("tenant_on_direct_per_address_card_rejected", func(t *testing.T) {
		tc := a2aCardCase{
			Name: "bad_direct_tenant",
			Path: "/a2a/agents/r_bad/agent-card.json",
			Card: map[string]any{
				"supportedInterfaces": []any{
					map[string]any{
						"url":             "https://acme.com/a2a/agents/r_bad/rpc",
						"protocolBinding": "JSONRPC",
						"protocolVersion": "1.0",
						"tenant":          "r_bad",
					},
				},
			},
		}
		if !a2aDirectCardHasTenant(tc) {
			t.Fatalf("expected direct per-address tenant to be detected")
		}
	})

	t.Run("slash_method_alias_rejected", func(t *testing.T) {
		method := "message/send"
		if !strings.Contains(method, "/") {
			t.Fatalf("test setup invalid")
		}
		allowedMethods := map[string]bool{
			"SendMessage":          true,
			"SendStreamingMessage": true,
			"GetTask":              true,
			"ListTasks":            true,
			"CancelTask":           true,
			"SubscribeToTask":      true,
		}
		if allowedMethods[method] {
			t.Fatalf("legacy slash method unexpectedly allowed")
		}
	})
}

func TestA2AV1JSONRPCVectors(t *testing.T) {
	vector := readA2AVector(t)
	allowedMethods := map[string]bool{
		"SendMessage":          true,
		"SendStreamingMessage": true,
		"GetTask":              true,
		"ListTasks":            true,
		"CancelTask":           true,
		"SubscribeToTask":      true,
	}
	allowedStates := map[string]bool{
		"TASK_STATE_SUBMITTED":      true,
		"TASK_STATE_WORKING":        true,
		"TASK_STATE_INPUT_REQUIRED": true,
		"TASK_STATE_AUTH_REQUIRED":  true,
		"TASK_STATE_COMPLETED":      true,
		"TASK_STATE_FAILED":         true,
		"TASK_STATE_CANCELED":       true,
		"TASK_STATE_REJECTED":       true,
	}

	seen := map[string]a2aRPCCase{}
	for _, tc := range vector.JSONRPC {
		t.Run(tc.Name, func(t *testing.T) {
			seen[tc.Name] = tc
			if tc.Payload["jsonrpc"] != "2.0" {
				t.Fatalf("jsonrpc: got %v, want 2.0", tc.Payload["jsonrpc"])
			}
			if !allowedMethods[tc.Method] {
				t.Fatalf("fixture method %q is not an A2A v1 JSON-RPC method", tc.Method)
			}
			if strings.Contains(tc.Method, "/") {
				t.Fatalf("legacy slash method name %q", tc.Method)
			}
			switch tc.Kind {
			case "request":
				if tc.Payload["method"] != tc.Method {
					t.Fatalf("request method: got %v, want %s", tc.Payload["method"], tc.Method)
				}
			case "response":
				if _, ok := tc.Payload["method"]; ok {
					t.Fatalf("response must not contain method")
				}
			default:
				t.Fatalf("unknown JSON-RPC fixture kind %q", tc.Kind)
			}
			for _, state := range collectA2AStates(tc.Payload) {
				if !allowedStates[state] {
					t.Fatalf("state %q is not in the A2A v1 task state set", state)
				}
			}
		})
	}

	immediate, ok := seen["send_message_immediate_request"]
	if !ok {
		t.Fatalf("missing send_message_immediate_request fixture")
	}
	config, ok := nestedMap(immediate.Payload, "params", "configuration")
	if !ok {
		t.Fatalf("send_message_immediate_request missing params.configuration")
	}
	if config["returnImmediately"] != true {
		t.Fatalf("returnImmediately: got %v, want true", config["returnImmediately"])
	}

	timeout, ok := seen["send_message_wait_timeout_failed_response"]
	if !ok {
		t.Fatalf("missing send_message_wait_timeout_failed_response fixture")
	}
	states := collectA2AStates(timeout.Payload)
	if !containsString(states, "TASK_STATE_FAILED") {
		t.Fatalf("wait-timeout fixture must return TASK_STATE_FAILED, got %#v", states)
	}
	if containsString(states, "TASK_STATE_WORKING") {
		t.Fatalf("wait-timeout fixture must not leave task in TASK_STATE_WORKING")
	}

	authRequired, ok := seen["send_message_auth_required_response"]
	if !ok {
		t.Fatalf("missing send_message_auth_required_response fixture")
	}
	if !containsString(collectA2AStates(authRequired.Payload), "TASK_STATE_AUTH_REQUIRED") {
		t.Fatalf("auth-required fixture must cover gateway-generated TASK_STATE_AUTH_REQUIRED")
	}
}

func TestA2AV1BridgeReplyVectors(t *testing.T) {
	vector := readA2AVector(t)
	terminalStates := map[string]bool{
		"TASK_STATE_COMPLETED":      true,
		"TASK_STATE_INPUT_REQUIRED": true,
		"TASK_STATE_AUTH_REQUIRED":  true,
		"TASK_STATE_FAILED":         true,
		"TASK_STATE_CANCELED":       true,
		"TASK_STATE_REJECTED":       true,
	}
	allowedActions := map[string]bool{
		"terminal_update":               true,
		"reject_or_ignore":              true,
		"no_terminal_update":            true,
		"ignore_terminal_already_final": true,
	}
	stateAliases := map[string]string{
		"completed":                 "TASK_STATE_COMPLETED",
		"input_required":            "TASK_STATE_INPUT_REQUIRED",
		"failed":                    "TASK_STATE_FAILED",
		"rejected":                  "TASK_STATE_REJECTED",
		"TASK_STATE_COMPLETED":      "TASK_STATE_COMPLETED",
		"TASK_STATE_INPUT_REQUIRED": "TASK_STATE_INPUT_REQUIRED",
		"TASK_STATE_FAILED":         "TASK_STATE_FAILED",
		"TASK_STATE_REJECTED":       "TASK_STATE_REJECTED",
	}

	seen := map[string]bool{}
	for _, tc := range vector.BridgeReplies {
		t.Run(tc.Name, func(t *testing.T) {
			seen[tc.Name] = true
			if tc.CurrentTaskID == "" {
				t.Fatalf("bridge reply fixture missing current_task_id")
			}
			if !allowedActions[tc.ExpectedAction] {
				t.Fatalf("unexpected bridge reply expected_action %q", tc.ExpectedAction)
			}
			if tc.ExpectedTaskState == "TASK_STATE_UNSPECIFIED" {
				t.Fatalf("TASK_STATE_UNSPECIFIED is validator-aware only, not a product reply state")
			}
			if tc.CurrentTaskState != "" && terminalStates[tc.CurrentTaskState] && tc.ExpectedAction != "ignore_terminal_already_final" {
				t.Fatalf("terminal current state %s must not be mutated by fixture action %s", tc.CurrentTaskState, tc.ExpectedAction)
			}

			replyPayload, hasStructuredReply := extractA2AReplyPayload(t, tc.Reply)
			switch tc.ExpectedAction {
			case "terminal_update":
				if !hasStructuredReply {
					t.Fatalf("terminal update fixture must use fenced a2a-reply")
				}
				if replyPayload["task_id"] != tc.CurrentTaskID {
					t.Fatalf("reply task_id: got %v, want %s", replyPayload["task_id"], tc.CurrentTaskID)
				}
				if tc.CurrentContextID != "" && replyPayload["context_id"] != tc.CurrentContextID {
					t.Fatalf("reply context_id: got %v, want %s", replyPayload["context_id"], tc.CurrentContextID)
				}
				state, ok := replyPayload["state"].(string)
				if !ok {
					t.Fatalf("structured reply missing state")
				}
				if got := stateAliases[state]; got != tc.ExpectedTaskState {
					t.Fatalf("reply state maps to %s, want %s", got, tc.ExpectedTaskState)
				}
				if !terminalStates[tc.ExpectedTaskState] {
					t.Fatalf("terminal update expected_task_state %s is not terminal", tc.ExpectedTaskState)
				}
			case "reject_or_ignore":
				if !hasStructuredReply {
					t.Fatalf("reject_or_ignore fixture should exercise a malformed structured reply")
				}
				if replyPayload["task_id"] == tc.CurrentTaskID && replyPayload["context_id"] == tc.CurrentContextID {
					t.Fatalf("reject_or_ignore fixture must mismatch task_id or context_id")
				}
				if tc.ExpectedTaskState != tc.CurrentTaskState {
					t.Fatalf("rejected/ignored reply must leave state unchanged: got %s, want %s", tc.ExpectedTaskState, tc.CurrentTaskState)
				}
			case "no_terminal_update":
				if hasStructuredReply {
					t.Fatalf("no_terminal_update fixture must be unfenced or non-structured prose")
				}
				if tc.ExpectedTaskState != tc.CurrentTaskState {
					t.Fatalf("unfenced prose must leave state unchanged: got %s, want %s", tc.ExpectedTaskState, tc.CurrentTaskState)
				}
			case "ignore_terminal_already_final":
				if !terminalStates[tc.CurrentTaskState] {
					t.Fatalf("late-reply fixture current state must be terminal")
				}
				if tc.ExpectedTaskState != tc.CurrentTaskState {
					t.Fatalf("late reply must not mutate terminal state: got %s, want %s", tc.ExpectedTaskState, tc.CurrentTaskState)
				}
			}
		})
	}
	for _, required := range []string{
		"completed_reply",
		"mismatched_task_id_reply",
		"stray_unfenced_prose",
		"late_reply_after_timeout_failed",
	} {
		if !seen[required] {
			t.Fatalf("missing bridge reply fixture %s", required)
		}
	}
}

func TestA2AAWIDPublicationVectors(t *testing.T) {
	data := readRootVector(t, "a2a-awid-publication-v1.json")
	var vector a2aAWIDPublicationVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Version != "a2a-awid-publication-v1" {
		t.Fatalf("version: got %q", vector.Version)
	}
	if vector.FixtureKind != "canonical_digest_only_non_verifying_signatures" {
		t.Fatalf("fixture_kind: got %q", vector.FixtureKind)
	}
	if vector.Canonicalization != "awid.CanonicalJSONValue" {
		t.Fatalf("canonicalization: got %q", vector.Canonicalization)
	}
	requireA2AAWIDCardDigestMatchesCardVector(t, vector.Publication.Payload)

	publicationCanonical, err := awid.CanonicalJSONValue(vector.Publication.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if publicationCanonical != vector.Publication.Canonical {
		t.Fatalf("publication canonical mismatch:\n got: %s\nwant: %s", publicationCanonical, vector.Publication.Canonical)
	}
	publicationJCSCanonical, err := canonicalJSONWithJCS(vector.Publication.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if publicationJCSCanonical != publicationCanonical {
		t.Fatalf("RFC8785/JCS publication canonicalization mismatch:\n jcs:  %s\n awid: %s", publicationJCSCanonical, publicationCanonical)
	}

	delegationCanonical, err := awid.CanonicalJSONValue(vector.Delegation.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if delegationCanonical != vector.Delegation.Canonical {
		t.Fatalf("delegation canonical mismatch:\n got: %s\nwant: %s", delegationCanonical, vector.Delegation.Canonical)
	}
	delegationJCSCanonical, err := canonicalJSONWithJCS(vector.Delegation.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if delegationJCSCanonical != delegationCanonical {
		t.Fatalf("RFC8785/JCS delegation canonicalization mismatch:\n jcs:  %s\n awid: %s", delegationJCSCanonical, delegationCanonical)
	}

	delegationDigest, err := signedPayloadDigest(delegationCanonical, vector.Delegation.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if got := stringValue(vector.Publication.Payload["delegation_digest"]); got != delegationDigest {
		t.Fatalf("publication delegation_digest: got %s, want %s", got, delegationDigest)
	}
	if _, ok := vector.Delegation.Payload["publication_digest"]; ok {
		t.Fatalf("delegation payload must not include publication_digest; v1 avoids mutual digest cycles")
	}
	if _, ok := vector.Delegation.Payload["publication_assertion_id"]; ok {
		t.Fatalf("delegation payload must not include publication_assertion_id; v1 avoids mutual digest cycles")
	}

	expectedCodes := []string{
		"a2a_publication_exists_different_digest",
		"a2a_publication_exists_different_gateway",
		"a2a_delegation_missing",
		"a2a_delegation_digest_mismatch",
		"a2a_delegation_expired",
		"a2a_delegation_revoked",
		"a2a_card_digest_mismatch",
		"a2a_card_url_invalid",
		"a2a_rpc_url_invalid",
		"a2a_route_id_invalid",
		"a2a_identity_signature_invalid",
		"a2a_delegation_signature_invalid",
		"a2a_timestamp_stale",
		"a2a_namespace_not_registered",
		"a2a_address_not_registered",
		"a2a_custody_combination_unsupported",
		"a2a_authority_source_invalid",
		"a2a_payload_canonicalization_mismatch",
		"a2a_primitive_disabled",
		"a2a_primitive_not_supported",
	}
	if strings.Join(vector.ConflictCodes, "\n") != strings.Join(expectedCodes, "\n") {
		t.Fatalf("conflict codes mismatch:\n got: %v\nwant: %v", vector.ConflictCodes, expectedCodes)
	}
}

func requireA2AAWIDCardDigestMatchesCardVector(t *testing.T, payload map[string]any) {
	t.Helper()
	cardURL := stringValue(payload["card_url"])
	if cardURL == "" {
		t.Fatalf("publication payload missing card_url")
	}
	parsed, err := url.Parse(cardURL)
	if err != nil {
		t.Fatal(err)
	}
	cardDigest := stringValue(payload["card_digest"])
	if cardDigest == "" {
		t.Fatalf("publication payload missing card_digest")
	}
	a2aVector := readA2AVector(t)
	for _, cardCase := range a2aVector.AgentCards {
		if cardCase.Path == parsed.Path {
			if cardCase.Digest != cardDigest {
				t.Fatalf("card_digest for %s: got %s, want %s from a2a-v1 vector", parsed.Path, cardDigest, cardCase.Digest)
			}
			return
		}
	}
	t.Fatalf("no a2a-v1 card vector found for path %s", parsed.Path)
}

func readA2AVector(t *testing.T) a2aVector {
	t.Helper()
	data := readRootVector(t, "a2a-v1.json")
	var vector a2aVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func extractA2AReplyPayload(t *testing.T, reply string) (map[string]any, bool) {
	t.Helper()
	const start = "```a2a-reply"
	startIndex := strings.Index(reply, start)
	if startIndex < 0 {
		return nil, false
	}
	bodyStart := startIndex + len(start)
	if bodyStart < len(reply) && reply[bodyStart] == '\r' {
		bodyStart++
	}
	if bodyStart < len(reply) && reply[bodyStart] == '\n' {
		bodyStart++
	}
	endIndex := strings.Index(reply[bodyStart:], "```")
	if endIndex < 0 {
		t.Fatalf("structured a2a-reply missing closing fence")
	}
	body := strings.TrimSpace(reply[bodyStart : bodyStart+endIndex])
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("structured a2a-reply is not JSON: %v", err)
	}
	return payload, true
}

func requireA2ACardHasNoLegacyFields(t *testing.T, card map[string]any) {
	t.Helper()
	for _, field := range a2aLegacyTopLevelFields(card) {
		t.Fatalf("AgentCard must not contain legacy/non-v1 top-level field %q", field)
	}
}

func requireA2ACardVersionDistinction(t *testing.T, card map[string]any) {
	t.Helper()
	version, ok := card["version"].(string)
	if !ok || version == "" {
		t.Fatalf("AgentCard missing service/card version")
	}
	if a2aCardVersionLooksLikeProtocolVersion(card) {
		t.Fatalf("AgentCard.version %q looks like the A2A protocol version; supportedInterfaces[].protocolVersion carries protocol version", version)
	}
}

func requireA2ACardModesAreMediaTypes(t *testing.T, card map[string]any) {
	t.Helper()
	for _, field := range []string{"defaultInputModes", "defaultOutputModes"} {
		values, ok := card[field].([]any)
		if !ok || len(values) == 0 {
			t.Fatalf("AgentCard %s must be a non-empty array", field)
		}
		for _, value := range values {
			mode, ok := value.(string)
			if !ok || !strings.Contains(mode, "/") {
				t.Fatalf("AgentCard %s value %v is not a media type", field, value)
			}
		}
	}
}

func requireA2ACardCapabilitiesAreV1(t *testing.T, card map[string]any) {
	t.Helper()
	capabilities, ok := card["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("AgentCard missing capabilities object")
	}
	allowed := map[string]bool{
		"streaming":         true,
		"pushNotifications": true,
		"extensions":        true,
		"extendedAgentCard": true,
	}
	for field := range capabilities {
		if !allowed[field] {
			t.Fatalf("AgentCard capabilities contains non-v1 field %q", field)
		}
	}
}

func requireA2ACardInterfaces(t *testing.T, tc a2aCardCase) {
	t.Helper()
	interfaces, ok := tc.Card["supportedInterfaces"].([]any)
	if !ok || len(interfaces) == 0 {
		t.Fatalf("AgentCard missing supportedInterfaces")
	}
	for _, value := range interfaces {
		iface, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("supportedInterfaces entry is not an object: %v", value)
		}
		if iface["protocolBinding"] != "JSONRPC" {
			t.Fatalf("protocolBinding: got %v, want JSONRPC", iface["protocolBinding"])
		}
		if iface["protocolVersion"] != "1.0" {
			t.Fatalf("protocolVersion: got %v, want 1.0", iface["protocolVersion"])
		}
		urlValue, ok := iface["url"].(string)
		if !ok || urlValue == "" {
			t.Fatalf("supported interface missing url")
		}
		if strings.HasPrefix(tc.Path, "/a2a/agents/") {
			routePrefix := strings.TrimSuffix(tc.Path, "/agent-card.json")
			if !strings.HasSuffix(urlValue, routePrefix+"/rpc") {
				t.Fatalf("per-address rpc URL %q does not match card path %q", urlValue, tc.Path)
			}
			if a2aDirectCardHasTenant(tc) {
				t.Fatalf("direct per-address card must omit supportedInterfaces[].tenant by default")
			}
		} else if tc.Path != "/.well-known/agent-card.json" {
			t.Fatalf("unexpected card path %q", tc.Path)
		}
	}
}

func a2aLegacyTopLevelFields(card map[string]any) []string {
	var out []string
	for _, field := range []string{"protocolVersion", "url", "stateTransitionHistory", "security"} {
		if _, ok := card[field]; ok {
			out = append(out, field)
		}
	}
	return out
}

func a2aCardVersionLooksLikeProtocolVersion(card map[string]any) bool {
	version, _ := card["version"].(string)
	return version == "1.0"
}

func a2aDirectCardHasTenant(tc a2aCardCase) bool {
	if !strings.HasPrefix(tc.Path, "/a2a/agents/") {
		return false
	}
	interfaces, _ := tc.Card["supportedInterfaces"].([]any)
	for _, value := range interfaces {
		iface, _ := value.(map[string]any)
		if _, ok := iface["tenant"]; ok {
			return true
		}
	}
	return false
}

func nestedMap(root map[string]any, keys ...string) (map[string]any, bool) {
	current := root
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func collectA2AStates(value any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch typed := v.(type) {
		case map[string]any:
			for key, child := range typed {
				if key == "state" {
					if state, ok := child.(string); ok && strings.HasPrefix(state, "TASK_STATE_") {
						out = append(out, state)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

// --- rotation-announcements-v1 ---

type rotationVector struct {
	Name               string         `json:"name"`
	Links              []rotationLink `json:"links"`
	PinnedDIDKey       string         `json:"pinned_did_key"`
	EnvelopeFromDIDKey string         `json:"envelope_from_did_key"`
}

type rotationLink struct {
	OldSeedHex       string `json:"old_seed_hex"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	Timestamp        string `json:"timestamp"`
	CanonicalPayload string `json:"canonical_payload"`
	SignatureB64     string `json:"signature_b64"`
}

func TestRotationAnnouncementVectors(t *testing.T) {
	data, err := vectorsFS.ReadFile("vectors/rotation-announcements-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []rotationVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			for i, link := range v.Links {
				oldPub, err := awid.ExtractPublicKey(link.OldDIDKey)
				if err != nil {
					t.Fatalf("link %d: ExtractPublicKey: %v", i, err)
				}

				// Verify canonical payload matches expected.
				gotCanonical := awid.CanonicalRotationJSON(link.OldDIDKey, link.NewDIDKey, link.Timestamp)
				if gotCanonical != link.CanonicalPayload {
					t.Errorf("link %d: CanonicalRotationJSON:\n  got:  %s\n  want: %s", i, gotCanonical, link.CanonicalPayload)
				}

				// Verify rotation signature.
				ok, err := awid.VerifyRotationSignature(oldPub, link.OldDIDKey, link.NewDIDKey, link.Timestamp, link.SignatureB64)
				if err != nil {
					t.Fatalf("link %d: VerifyRotationSignature: %v", i, err)
				}
				if !ok {
					t.Errorf("link %d: VerifyRotationSignature returned false", i)
				}

				// Verify signing with the old key produces the expected signature.
				seed, err := hex.DecodeString(link.OldSeedHex)
				if err != nil {
					t.Fatal(err)
				}
				key := ed25519.NewKeyFromSeed(seed)
				sig, err := awid.SignRotation(key, link.OldDIDKey, link.NewDIDKey, link.Timestamp)
				if err != nil {
					t.Fatalf("link %d: SignRotation: %v", i, err)
				}
				if sig != link.SignatureB64 {
					t.Errorf("link %d: SignRotation:\n  got:  %s\n  want: %s", i, sig, link.SignatureB64)
				}
			}

			// Verify chain semantics: first link's old_did matches pinned,
			// each link's new_did matches next link's old_did,
			// last link's new_did matches envelope from_did.
			if len(v.Links) > 0 {
				if v.Links[0].OldDIDKey != v.PinnedDIDKey {
					t.Errorf("chain: first link old_did %s != pinned %s", v.Links[0].OldDIDKey, v.PinnedDIDKey)
				}
				for i := 1; i < len(v.Links); i++ {
					if v.Links[i].OldDIDKey != v.Links[i-1].NewDIDKey {
						t.Errorf("chain: link %d old_did %s != link %d new_did %s", i, v.Links[i].OldDIDKey, i-1, v.Links[i-1].NewDIDKey)
					}
				}
				lastNew := v.Links[len(v.Links)-1].NewDIDKey
				if lastNew != v.EnvelopeFromDIDKey {
					t.Errorf("chain: last new_did %s != envelope from_did %s", lastNew, v.EnvelopeFromDIDKey)
				}
			}
		})
	}
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func signedPayloadDigest(canonical, signature string) (string, error) {
	signatureBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(canonical))
	_, _ = h.Write(signatureBytes)
	return "sha256:" + base64.RawStdEncoding.EncodeToString(h.Sum(nil)), nil
}

func stringValue(value any) string {
	if out, ok := value.(string); ok {
		return out
	}
	return ""
}

func intField(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}
