package conformance_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type federationPinnedCase map[string]json.RawMessage

type federationOriginIPVector struct {
	Schema         string                 `json:"schema"`
	Contract       string                 `json:"contract"`
	OriginCases    []federationPinnedCase `json:"origin_cases"`
	IPCases        []federationPinnedCase `json:"ip_cases"`
	AnswerSetCases []federationPinnedCase `json:"answer_set_cases"`
	SourceIPCases  []federationPinnedCase `json:"source_ip_cases"`
	TransportCases []federationPinnedCase `json:"transport_cases"`
}

type federationAuthorityStatementCase struct {
	Name                      string         `json:"name"`
	Payload                   map[string]any `json:"payload"`
	CanonicalPayload          string         `json:"canonical_payload"`
	AuthorityStatementVersion string         `json:"authority_statement_version"`
	AuthorityStatementDigest  string         `json:"authority_statement_digest"`
}

type federationDiscoveryVector struct {
	Schema                  string                             `json:"schema"`
	Contract                string                             `json:"contract"`
	Constants               map[string]string                  `json:"constants"`
	CanonicalAddressCases   []federationPinnedCase             `json:"canonical_address_cases"`
	DNSCases                []federationPinnedCase             `json:"dns_cases"`
	AuthorityStatementCases []federationAuthorityStatementCase `json:"authority_statement_cases"`
	AuthorityLookupCases    []federationPinnedCase             `json:"authority_lookup_cases"`
}

type federationIdentityLogReference struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Bytes    int      `json:"bytes"`
	Embedded bool     `json:"embedded"`
	Purpose  []string `json:"purpose"`
}

type federationStableError struct {
	Reason             string `json:"reason"`
	Detail             string `json:"detail"`
	HTTPStatus         int    `json:"http_status"`
	Retryable          bool   `json:"retryable"`
	RetryAfterRequired bool   `json:"retry_after_required"`
}

type federationErrorResponseContract struct {
	RequiredBodyFields        []string `json:"required_body_fields"`
	DiagnosticFieldsAllowed   []string `json:"diagnostic_fields_allowed"`
	DiagnosticFieldsForbidden []string `json:"diagnostic_fields_forbidden"`
	RetryAfterRequiredOnlyFor []string `json:"retry_after_required_only_for"`
}

type federationMutation struct {
	ID       string `json:"id"`
	MustFail bool   `json:"must_fail"`
	Proof    string `json:"proof"`
}

type federationAuthorityStateVector struct {
	Schema                string                           `json:"schema"`
	Contract              string                           `json:"contract"`
	SelectedPolicies      map[string]any                   `json:"selected_policies"`
	Bounds                map[string]any                   `json:"bounds"`
	IdentityLogReferences []federationIdentityLogReference `json:"identity_log_references"`
	CheckpointCases       []federationPinnedCase           `json:"checkpoint_cases"`
	CohortRequiredFields  []string                         `json:"cohort_required_fields"`
	CohortCases           []federationPinnedCase           `json:"cohort_cases"`
	WorkFenceCases        []federationPinnedCase           `json:"work_fence_cases"`
	EvidenceReuseCases    []federationPinnedCase           `json:"evidence_reuse_cases"`
	ErrorResponseContract federationErrorResponseContract  `json:"error_response_contract"`
	StableErrors          []federationStableError          `json:"stable_errors"`
	MandatoryMutations    []federationMutation             `json:"mandatory_mutations"`
}

type federationErrorTuple struct {
	status    int
	retryable bool
}

type federationVectorPin struct {
	bytes  int
	sha256 string
}

var federationVectorPins = map[string]federationVectorPin{
	"federation-origin-ip-v1.json": {
		bytes:  12746,
		sha256: "6d6ec789c4d994913ae84a26021a8e8fe0c7eb3aaf008ee10ce623db7a87cb18",
	},
	"federation-discovery-v1.json": {
		bytes:  18774,
		sha256: "42fc649d28f097d22073d10e01c800ca653e177ec055a9cd2f40b047eb6a22da",
	},
	"federation-authority-state-v1.json": {
		bytes:  24926,
		sha256: "dbfae045d87a947ba5e9add41b03832159eb584c1ab1d8644ec5a34f27f8d616",
	},
}

func decodeFederationVectorData(name string, data []byte, target any) error {
	pin, ok := federationVectorPins[name]
	if !ok {
		return fmt.Errorf("no immutable pin for %s", name)
	}
	digest := sha256.Sum256(data)
	if len(data) != pin.bytes || hex.EncodeToString(digest[:]) != pin.sha256 {
		return fmt.Errorf("%s does not match its immutable bytes", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON values")
	}
	return nil
}

func decodeFederationVector(t *testing.T, name string, target any) {
	t.Helper()
	if err := decodeFederationVectorData(name, readRootVector(t, name), target); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func requireUniqueFederationCaseNames(t *testing.T, group string, cases []federationPinnedCase) {
	t.Helper()
	if len(cases) == 0 {
		t.Fatalf("%s has no cases", group)
	}
	seen := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		var name string
		if err := json.Unmarshal(c["name"], &name); err != nil || name == "" {
			t.Fatalf("%s has invalid case name", group)
		}
		if _, ok := seen[name]; ok {
			t.Fatalf("%s repeats case %q", group, name)
		}
		seen[name] = struct{}{}
	}
}

func TestFederationOriginIPVectorSchema(t *testing.T) {
	var vector federationOriginIPVector
	decodeFederationVector(t, "federation-origin-ip-v1.json", &vector)
	if vector.Schema != "aweb.federation-origin-ip.v1" || vector.Contract != "aweb-aazd.2.1" {
		t.Fatalf("unexpected origin/IP schema or contract: %#v", vector)
	}
	requireUniqueFederationCaseNames(t, "origin_cases", vector.OriginCases)
	requireUniqueFederationCaseNames(t, "ip_cases", vector.IPCases)
	requireUniqueFederationCaseNames(t, "answer_set_cases", vector.AnswerSetCases)
	requireUniqueFederationCaseNames(t, "source_ip_cases", vector.SourceIPCases)
	requireUniqueFederationCaseNames(t, "transport_cases", vector.TransportCases)
}

func TestFederationDiscoveryVectorCanonicalStatements(t *testing.T) {
	var vector federationDiscoveryVector
	decodeFederationVector(t, "federation-discovery-v1.json", &vector)
	if vector.Schema != "aweb.federation-discovery.v1" || vector.Contract != "aweb-aazd.2.1" {
		t.Fatalf("unexpected discovery schema or contract: %#v", vector)
	}
	if vector.Constants["authority_statement_version"] != "aweb.federation-authority.dns.v1" ||
		vector.Constants["public_registry_origin"] != "https://api.awid.ai" {
		t.Fatalf("unexpected discovery constants: %#v", vector.Constants)
	}
	requireUniqueFederationCaseNames(t, "canonical_address_cases", vector.CanonicalAddressCases)
	requireUniqueFederationCaseNames(t, "dns_cases", vector.DNSCases)
	requireUniqueFederationCaseNames(t, "authority_lookup_cases", vector.AuthorityLookupCases)
	if len(vector.AuthorityStatementCases) == 0 {
		t.Fatal("authority_statement_cases has no cases")
	}
	seen := map[string]struct{}{}
	for _, c := range vector.AuthorityStatementCases {
		if c.Name == "" {
			t.Fatal("authority statement has blank case name")
		}
		if _, ok := seen[c.Name]; ok {
			t.Fatalf("authority statement repeats case %q", c.Name)
		}
		seen[c.Name] = struct{}{}
		canonical, err := json.Marshal(c.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != c.CanonicalPayload {
			t.Fatalf("%s canonical payload mismatch\ngot:  %s\nwant: %s", c.Name, canonical, c.CanonicalPayload)
		}
		digest := sha256.Sum256(canonical)
		wantDigest := "sha256:" + hex.EncodeToString(digest[:])
		if c.AuthorityStatementDigest != wantDigest {
			t.Fatalf("%s digest=%q want %q", c.Name, c.AuthorityStatementDigest, wantDigest)
		}
		if c.AuthorityStatementVersion != vector.Constants["authority_statement_version"] {
			t.Fatalf("%s statement version=%q", c.Name, c.AuthorityStatementVersion)
		}
	}
}

func TestFederationAuthorityStateVectorReferencesAndErrors(t *testing.T) {
	var vector federationAuthorityStateVector
	decodeFederationVector(t, "federation-authority-state-v1.json", &vector)
	if vector.Schema != "aweb.federation-authority-state.v1" || vector.Contract != "aweb-aazd.2.1" {
		t.Fatalf("unexpected authority-state schema or contract: %#v", vector)
	}
	if vector.SelectedPolicies["receiver_reuse_max_seconds"] != float64(60) ||
		vector.SelectedPolicies["receiver_reuse_is_freshness_sla"] != false ||
		vector.SelectedPolicies["contact_transfer"] != "never_automatic" {
		t.Fatalf("unexpected selected policies: %#v", vector.SelectedPolicies)
	}
	if vector.Bounds["coordination_store"] != "postgresql" ||
		vector.Bounds["mismatch_memoization"] != "none" ||
		vector.Bounds["max_log_entries"] != float64(4096) {
		t.Fatalf("unexpected authority bounds: %#v", vector.Bounds)
	}

	wantReferences := map[string]struct{}{
		"docs/vectors/identity-log-v1.json":          {},
		"docs/vectors/identity-log-negative-v1.json": {},
		"docs/vectors/identity-log-raw-wire-v1.json": {},
	}
	for _, reference := range vector.IdentityLogReferences {
		if reference.Embedded {
			t.Fatalf("identity-log reference %s embeds a body", reference.Path)
		}
		name := filepath.Base(reference.Path)
		data := readRootVector(t, name)
		if len(data) != reference.Bytes {
			t.Fatalf("%s bytes=%d want %d", reference.Path, reference.Bytes, len(data))
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != reference.SHA256 {
			t.Fatalf("%s digest mismatch", reference.Path)
		}
		delete(wantReferences, reference.Path)
	}
	if len(wantReferences) != 0 {
		t.Fatalf("missing identity-log references: %#v", wantReferences)
	}

	wantErrors := map[string]federationErrorTuple{
		"contact_identity_binding_required":               {409, false},
		"federation_authority_cas_conflict":               {503, true},
		"federation_authority_coordination_unavailable":   {503, true},
		"federation_conversation_invalid":                 {409, false},
		"federation_envelope_invalid":                     {422, false},
		"federation_message_replay_conflict":              {409, false},
		"federation_rate_limited":                         {429, true},
		"federation_resolver_busy":                        {503, true},
		"federation_route_rejected":                       {502, false},
		"federation_route_timeout":                        {504, true},
		"federation_route_unavailable":                    {503, true},
		"federation_signature_invalid":                    {422, false},
		"federation_timestamp_invalid":                    {422, false},
		"local_recipient_route_missing":                   {404, false},
		"local_sender_route_mismatch":                     {422, false},
		"recipient_address_did_mismatch":                  {422, false},
		"recipient_current_key_mismatch":                  {422, false},
		"recipient_encryption_assertion_invalid_or_stale": {422, false},
		"recipient_encryption_assertion_missing":          {424, false},
		"recipient_identity_not_found":                    {404, false},
		"recipient_policy_rejected":                       {403, false},
		"recipient_route_mismatch":                        {422, false},
		"recipient_route_missing":                         {424, false},
		"sender_address_did_mismatch":                     {422, false},
		"sender_address_required":                         {422, false},
		"sender_address_wrapper_mismatch":                 {422, false},
		"sender_current_key_mismatch":                     {422, false},
		"sender_did_log_invalid":                          {422, false},
		"sender_did_log_rollback":                         {409, false},
		"sender_did_log_split_view":                       {409, false},
		"sender_identity_evidence_too_large":              {502, false},
		"sender_identity_not_found":                       {404, false},
		"sender_identity_unverifiable":                    {503, true},
		"sender_registry_discovery_failed":                {503, true},
		"sender_registry_origin_forbidden":                {422, false},
		"sender_registry_protocol_invalid":                {502, false},
		"sender_registry_tls_invalid":                     {502, false},
		"sender_registry_unavailable":                     {503, true},
		"sender_registry_unresolvable":                    {422, false},
		"sender_route_mismatch":                           {422, false},
		"sender_route_missing":                            {424, false},
		"target_route_mismatch":                           {421, false},
	}
	errorContract := vector.ErrorResponseContract
	if len(errorContract.RequiredBodyFields) != 4 || errorContract.RequiredBodyFields[0] != "detail" ||
		len(errorContract.DiagnosticFieldsAllowed) != 2 || errorContract.DiagnosticFieldsAllowed[0] != "did_aw" ||
		len(errorContract.RetryAfterRequiredOnlyFor) != 1 || errorContract.RetryAfterRequiredOnlyFor[0] != "federation_rate_limited" {
		t.Fatalf("unexpected error response contract: %#v", errorContract)
	}
	if len(vector.StableErrors) != len(wantErrors) {
		t.Fatalf("stable errors=%d want %d", len(vector.StableErrors), len(wantErrors))
	}
	for _, item := range vector.StableErrors {
		want, ok := wantErrors[item.Reason]
		if !ok || want.status != item.HTTPStatus || want.retryable != item.Retryable || item.Detail != item.Reason {
			t.Fatalf("unexpected stable error: %#v", item)
		}
		if item.RetryAfterRequired != (item.Reason == "federation_rate_limited") {
			t.Fatalf("unexpected Retry-After requirement: %#v", item)
		}
		delete(wantErrors, item.Reason)
	}
	if len(wantErrors) != 0 {
		t.Fatalf("missing stable errors: %#v", wantErrors)
	}

	for _, group := range []struct {
		name  string
		cases []federationPinnedCase
	}{
		{"checkpoint_cases", vector.CheckpointCases},
		{"cohort_cases", vector.CohortCases},
		{"work_fence_cases", vector.WorkFenceCases},
		{"evidence_reuse_cases", vector.EvidenceReuseCases},
	} {
		requireUniqueFederationCaseNames(t, group.name, group.cases)
	}
	if len(vector.CohortRequiredFields) != 21 {
		t.Fatalf("cohort_required_fields=%d want 21", len(vector.CohortRequiredFields))
	}
	if len(vector.MandatoryMutations) != 34 {
		t.Fatalf("mandatory_mutations=%d want 34", len(vector.MandatoryMutations))
	}
	seenMutations := map[string]struct{}{}
	for _, mutation := range vector.MandatoryMutations {
		if mutation.ID == "" || !mutation.MustFail {
			t.Fatalf("invalid mandatory mutation: %#v", mutation)
		}
		if mutation.Proof != "schema" && mutation.Proof != "future_behavior" && mutation.Proof != "pre_activation_sot" {
			t.Fatalf("invalid mutation proof: %#v", mutation)
		}
		if _, ok := seenMutations[mutation.ID]; ok {
			t.Fatalf("duplicate mutation %q", mutation.ID)
		}
		seenMutations[mutation.ID] = struct{}{}
	}
}

func federationCaseMap(t *testing.T, vector map[string]any, group, name string) map[string]any {
	t.Helper()
	for _, value := range vector[group].([]any) {
		row := value.(map[string]any)
		if row["name"] == name {
			return row
		}
	}
	t.Fatalf("%s has no case %q", group, name)
	return nil
}

func removeFederationCase(t *testing.T, vector map[string]any, group, name string) {
	t.Helper()
	cases := vector[group].([]any)
	for i, value := range cases {
		if value.(map[string]any)["name"] == name {
			vector[group] = append(cases[:i], cases[i+1:]...)
			return
		}
	}
	t.Fatalf("%s has no case %q", group, name)
}

func federationVectorTarget(t *testing.T, name string) any {
	t.Helper()
	switch name {
	case "federation-origin-ip-v1.json":
		return &federationOriginIPVector{}
	case "federation-discovery-v1.json":
		return &federationDiscoveryVector{}
	case "federation-authority-state-v1.json":
		return &federationAuthorityStateVector{}
	default:
		t.Fatalf("unknown federation vector %q", name)
		return nil
	}
}

func TestFederationVectorMutationsAreRejected(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		mutate func(*testing.T, map[string]any)
	}{
		{
			name:   "mixed answer case deletion",
			vector: "federation-origin-ip-v1.json",
			mutate: func(t *testing.T, vector map[string]any) {
				removeFederationCase(t, vector, "answer_set_cases", "mixed_public_private_answers_fail_closed")
			},
		},
		{
			name:   "split-view case deletion",
			vector: "federation-authority-state-v1.json",
			mutate: func(t *testing.T, vector map[string]any) {
				removeFederationCase(t, vector, "checkpoint_cases", "same_sequence_different_hash_is_split_view")
			},
		},
		{
			name:   "production HTTP semantic reversal",
			vector: "federation-origin-ip-v1.json",
			mutate: func(t *testing.T, vector map[string]any) {
				expected := federationCaseMap(t, vector, "origin_cases", "http_is_forbidden_in_production")["expected"].(map[string]any)
				expected["ok"] = true
				expected["canonical_origin"] = "http://registry.example"
				expected["reason"] = nil
			},
		},
		{
			name:   "degraded authority semantic reversal",
			vector: "federation-discovery-v1.json",
			mutate: func(t *testing.T, vector map[string]any) {
				expected := federationCaseMap(t, vector, "authority_lookup_cases", "degraded_key_never_authorizes")["expected"].(map[string]any)
				expected["accepted"] = true
			},
		},
		{
			name:   "duplicate identity-log reference",
			vector: "federation-authority-state-v1.json",
			mutate: func(_ *testing.T, vector map[string]any) {
				references := vector["identity_log_references"].([]any)
				vector["identity_log_references"] = append(references, references[0])
			},
		},
		{
			name:   "unknown case field",
			vector: "federation-origin-ip-v1.json",
			mutate: func(t *testing.T, vector map[string]any) {
				federationCaseMap(t, vector, "ip_cases", "public_ipv4")["unknown_behavior"] = "allow_private"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var vector map[string]any
			if err := json.Unmarshal(readRootVector(t, test.vector), &vector); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, vector)
			data, err := json.Marshal(vector)
			if err != nil {
				t.Fatal(err)
			}
			err = decodeFederationVectorData(test.vector, data, federationVectorTarget(t, test.vector))
			if err == nil {
				t.Fatal("mutation unexpectedly passed federation vector validation")
			}
			if !strings.Contains(err.Error(), "immutable bytes") {
				t.Fatalf("mutation failed for the wrong reason: %v", err)
			}
		})
	}
}
