package awid

// P0 defines closed public DTOs only. Parsing never authenticates a signer,
// advertises a capability, admits a participant or writes messaging state.
import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const HumanChannelsProfile = "aweb-human-channels-v1"
const humanChannelsMaxBytes = 1024 * 1024

type HumanChannelsContractError struct{ Code, Field string }

func (e *HumanChannelsContractError) Error() string { return e.Code + ": " + e.Field }
func hcError(code, field string) error              { return &HumanChannelsContractError{code, field} }

// HumanChannelsRecord is a named, validated DTO whose exact closed field set
// is in docs/vectors/human-channels-profile-v1.json. Value remains untrusted.
type HumanChannelsRecord struct {
	Schema string
	Value  map[string]any
}
type HumanChannelsParticipant struct {
	Kind    string `json:"kind"`
	DID     string `json:"did,omitempty"`
	Bridge  string `json:"bridge,omitempty"`
	Subject string `json:"subject,omitempty"`
}
type HumanChannelsGroupContext struct {
	SessionID       string                   `json:"session_id"`
	MembershipEpoch int64                    `json:"membership_epoch"`
	MembershipHash  string                   `json:"membership_hash"`
	AuthorRef       HumanChannelsParticipant `json:"author_ref"`
	MessageID       string                   `json:"message_id"`
}
type HumanChannelsCapabilitySet struct {
	Version     string   `json:"version"`
	Implemented []string `json:"implemented"`
	Enabled     []string `json:"enabled"`
	Refused     []string `json:"refused"`
}

type hcObjectSpec struct{ Required, Optional map[string]any }
type hcProfileSpec struct {
	Schemas              map[string]hcObjectSpec
	Capabilities         []string
	DeferredCapabilities []string `json:"deferred_capabilities"`
}

var hcProfile = func() hcProfileSpec {
	var p hcProfileSpec
	if err := json.Unmarshal([]byte(humanChannelsProfileJSON), &p); err != nil {
		panic(err)
	}
	return p
}()
var hcPatterns = map[string]*regexp.Regexp{
	"platform_kind": regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`),
	"uuid":          regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
	"hash":          regexp.MustCompile(`^sha256:[0-9a-f]{64}$`),
	"commitment":    regexp.MustCompile(`^commitment:[0-9a-f]{64}$`),
	"did":           regexp.MustCompile(`^did:(aw:[A-Za-z0-9._:-]+|key:z[1-9A-HJ-NP-Za-km-z]+)$`),
	"didaw":         regexp.MustCompile(`^did:aw:[A-Za-z0-9._:-]+$`),
	"didkey":        regexp.MustCompile(`^did:key:z[1-9A-HJ-NP-Za-km-z]+$`),
	"timestamp":     regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`),
	"opaque":        regexp.MustCompile(`^[A-Za-z0-9._:-]{1,256}$`),
	"signature":     regexp.MustCompile(`^[A-Za-z0-9+/]{86}$`),
}

func DecodeHumanChannelsRecord(schema string, raw []byte) (HumanChannelsRecord, error) {
	bad := HumanChannelsRecord{}
	if len(raw) > humanChannelsMaxBytes || !utf8.Valid(raw) || !hcValidEscapes(raw) {
		return bad, hcError("invalid", "json")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := hcReadJSON(dec, 0)
	if err != nil {
		return bad, err
	}
	if _, err = dec.Token(); err != io.EOF {
		return bad, hcError("invalid", "trailing JSON")
	}
	if _, err = StrictCanonicalJSON(value); err != nil {
		return bad, hcError("invalid", "canonical JSON")
	}
	if err = hcValidate(schema, value); err != nil {
		return bad, err
	}
	return HumanChannelsRecord{schema, value.(map[string]any)}, nil
}
func (r HumanChannelsRecord) Canonical() ([]byte, error) {
	if !hcWithinDepth(r.Value, 0) {
		return nil, hcError("invalid", "depth")
	}
	if err := hcValidate(r.Schema, r.Value); err != nil {
		return nil, err
	}
	b, err := StrictCanonicalJSON(r.Value)
	if err != nil {
		return nil, hcError("invalid", "canonical JSON")
	}
	return b, nil
}

func hcReadJSON(dec *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, hcError("invalid", "depth")
	}
	t, err := dec.Token()
	if err != nil {
		return nil, hcError("invalid", "JSON")
	}
	d, delim := t.(json.Delim)
	if !delim {
		return t, nil
	}
	switch d {
	case '{':
		out := map[string]any{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return nil, hcError("invalid", "key")
			}
			key, ok := k.(string)
			if !ok {
				return nil, hcError("invalid", "key")
			}
			if _, ok := out[key]; ok {
				return nil, hcError("invalid", "duplicate key")
			}
			v, err := hcReadJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return nil, hcError("invalid", "object")
		}
		return out, nil
	case '[':
		out := []any{}
		for dec.More() {
			v, err := hcReadJSON(dec, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return nil, hcError("invalid", "array")
		}
		return out, nil
	default:
		return nil, hcError("invalid", "delimiter")
	}
}

// encoding/json replaces unpaired surrogates. New signed profiles refuse them
// instead, so Go cannot sign different bytes from a Python consumer.
func hcValidEscapes(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
func hcValidate(schema string, value any) error {
	spec, ok := hcProfile.Schemas[schema]
	if !ok {
		return hcError("unsupported", schema)
	}
	v, ok := value.(map[string]any)
	if !ok {
		return hcError("invalid", schema)
	}
	for k := range spec.Required {
		if _, ok := v[k]; !ok {
			return hcError("invalid", schema)
		}
	}
	if rule, ok := spec.Required["version"]; ok {
		if hcMatch(rule, v["version"], "version") != nil {
			return hcError("unsupported", "version")
		}
	}
	for k, item := range v {
		rule, ok := spec.Required[k]
		if !ok {
			rule, ok = spec.Optional[k]
		}
		if !ok {
			return hcError("invalid", k)
		}
		if err := hcMatch(rule, item, k); err != nil {
			return err
		}
	}
	return hcRelations(schema, v)
}
func hcMatch(rule, value any, field string) error {
	if r, ok := rule.(map[string]any); ok {
		if choices, ok := r["enum"].([]any); ok {
			for _, choice := range choices {
				if text, ok := value.(string); ok && text == choice {
					return nil
				}
			}
			return hcError("invalid", field)
		}
		if constant, ok := r["integer_const"].(float64); ok {
			n, valid := hcInt(value)
			if !valid || n != int64(constant) {
				return hcError("invalid", field)
			}
			return nil
		}
		if name, ok := r["ref"].(string); ok {
			return hcValidate(name, value)
		}
		if item, ok := r["array"]; ok {
			items, ok := value.([]any)
			if !ok || len(items) > 4096 {
				return hcError("invalid", field)
			}
			for _, v := range items {
				if err := hcMatch(item, v, field); err != nil {
					return err
				}
			}
			return nil
		}
		if choices, ok := r["one_of"].([]any); ok {
			count := 0
			for _, choice := range choices {
				if hcMatch(choice, value, field) == nil {
					count++
				}
			}
			if count != 1 {
				return hcError("invalid", field)
			}
			return nil
		}
		return hcError("invalid", "schema rule")
	}
	r := rule.(string)
	if r == "uint" || r == "positive_uint" || r == "limit" {
		n, ok := hcInt(value)
		low, high := int64(0), int64(maxSafeInteger)
		if r == "positive_uint" {
			low = 1
		}
		if r == "limit" {
			low, high = 1, 200
		}
		if !ok || n < low || n > high {
			return hcError("invalid", field)
		}
		return nil
	}
	if r == "bool" {
		if _, ok := value.(bool); !ok {
			return hcError("invalid", field)
		}
		return nil
	}
	if r == "json_object" {
		if _, ok := value.(map[string]any); !ok {
			return hcError("invalid", field)
		}
		return nil
	}
	str, ok := value.(string)
	if r == "string" {
		if !ok {
			return hcError("invalid", field)
		}
		return nil
	}
	if !ok || str == "" {
		return hcError("invalid", field)
	}
	if pattern, ok := hcPatterns[r]; ok && !pattern.MatchString(str) {
		return hcError("invalid", field)
	}
	if r == "timestamp" {
		if _, err := time.Parse("2006-01-02T15:04:05Z", str); err != nil {
			return hcError("invalid", field)
		}
	}
	if r == "signature" {
		b, err := base64.RawStdEncoding.DecodeString(str)
		if err != nil || len(b) != 64 || base64.RawStdEncoding.EncodeToString(b) != str {
			return hcError("invalid", field)
		}
	}
	return nil
}
func hcInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		x, e := n.Int64()
		return x, e == nil
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}
func hcNumber(v any) int64                  { n, _ := hcInt(v); return n }
func hcHas(v map[string]any, k string) bool { _, ok := v[k]; return ok }
func hcRelations(schema string, v map[string]any) error {
	switch schema {
	case "ResolveRequest":
		alias := hcHas(v, "team_id") && hcHas(v, "selector") && !hcHas(v, "session_id") && !hcHas(v, "participant")
		session := hcHas(v, "session_id") && hcHas(v, "participant") && !hcHas(v, "team_id") && !hcHas(v, "selector")
		if !alias && !session {
			return hcError("invalid", "alternative selector")
		}
	case "CheckpointIntent":
		fields := []string{"expected_membership_epoch", "expected_membership_hash", "expected_export_generation", "generation", "policy_digest"}
		for _, k := range fields {
			if hcHas(v, k) != (v["authorization"] == "owner") {
				return hcError("invalid", "checkpoint authority")
			}
		}
		if v["authorization"] == "owner" {
			if hcNumber(v["generation"]) != hcNumber(v["expected_export_generation"])+1 {
				return hcError("invalid", "checkpoint CAS")
			}
		} else if v["operation"] == "activate" {
			return hcError("invalid", "narrow-only checkpoint")
		}
	case "CheckpointReceipt":
		if hcNumber(v["acceptance_seq"]) != hcNumber(v["effective_after_seq"]) {
			return hcError("invalid", "checkpoint boundary")
		}
	case "MessageAcceptance":
		for _, k := range []string{"message_envelope_hash", "acceptance_seq", "membership_epoch", "membership_hash", "exports", "signer", "signing_key_id"} {
			if hcHas(v, k) != (v["capture_status"] == "recorded") {
				return hcError("invalid", "capture")
			}
		}
		if v["capture_status"] == "recorded" {
			for _, x := range v["exports"].([]any) {
				if hcNumber(x.(map[string]any)["checkpoint_seq"]) >= hcNumber(v["acceptance_seq"]) {
					return hcError("invalid", "capture boundary")
				}
			}
		}
	case "PresenceScope":
		if hcHas(v, "session_id") != (v["kind"] == "session") {
			return hcError("invalid", "presence scope")
		}
	case "PresenceIntent", "PresenceBindingIntent":
		if hcHas(v, "ownership_proof") != (v["authorization"] == "owner") {
			return hcError("invalid", "presence proof")
		}
	case "PageResult":
		if hcHas(v, "next_cursor") != v["has_more"].(bool) {
			return hcError("invalid", "cursor")
		}
	case "Interval":
		if hcNumber(v["after_seq"]) > hcNumber(v["through_seq"]) {
			return hcError("invalid", "interval")
		}
	case "Capabilities":
		implemented := map[string]bool{}
		refused := map[string]bool{}
		for _, x := range v["implemented"].([]any) {
			implemented[x.(string)] = true
		}
		for _, x := range v["refused"].([]any) {
			refused[x.(string)] = true
		}
		for _, x := range v["enabled"].([]any) {
			if !implemented[x.(string)] || refused[x.(string)] {
				return hcError("unsupported", "capability activation")
			}
		}

	case "PreparedSend":
		sum := sha256.Sum256([]byte(v["envelope"].(string)))
		if "sha256:"+hex.EncodeToString(sum[:]) != v["envelope_hash"] {
			return hcError("invalid", "envelope hash")
		}
	case "Refusal":
		allowed := map[string][]string{"invalid": {"never"}, "unsupported": {"never"}, "forbidden": {"never"}, "consent_required": {"never"}, "stale": {"refresh"}, "replay_conflict": {"never"}, "not_found": {"never"}, "authority_unavailable": {"backoff"}, "native_unavailable": {"backoff", "reconcile"}, "outcome_unknown": {"reconcile"}, "limit_exceeded": {"backoff"}}
		ok := false
		for _, r := range allowed[v["code"].(string)] {
			if r == v["retry"] {
				ok = true
			}
		}
		if !ok {
			return hcError("invalid", "retry policy")
		}
	case "NativeV2Content":
		if v["kind"] == "mail" && !hcHas(v, "subject") {
			return hcError("invalid", "mail subject")
		}
	case "PrepareRequest":
		managed := v["format"] == "managed_chat_plaintext"
		author := v["author"].(map[string]any)
		if (!managed) != hcHas(v, "target") || managed != hcHas(v, "group_context") || (managed && v["kind"] != "chat") || (v["kind"] == "mail" && author["kind"] != "native") {
			return hcError("invalid", "message profile")
		}
		if managed {
			c := v["group_context"].(map[string]any)
			a, _ := StrictCanonicalJSON(c["author_ref"])
			b, _ := StrictCanonicalJSON(author)
			if string(a) != string(b) || c["message_id"] != v["message_id"] || c["session_id"] != v["conversation_id"] {
				return hcError("invalid", "message context")
			}
		}
	case "NativeOperationRequest":
		if v["operation"] == "resolve" {
			for _, k := range []string{"decision", "owner_authorization", "evidence_hash"} {
				if !hcHas(v, k) {
					return hcError("invalid", "native resolution")
				}
			}
		} else if hcHas(v, "decision") || hcHas(v, "owner_authorization") {
			return hcError("invalid", "native decision")
		}
	case "PolicyState":
		if v["authority_mode"] == "server_readable" && v["confidentiality"] == "end_to_end" {
			return hcError("invalid", "server-readable authority")
		}

		if len(v["bridges"].([]any)) > 0 && v["confidentiality"] != "bridge_readable" {
			return hcError("invalid", "bridge-readable label")
		}
	case "ManagedPlaintext":
		ctx := v["group_context"].(map[string]any)
		if v["message_id"] != ctx["message_id"] || v["conversation_id"] != ctx["session_id"] {
			return hcError("invalid", "group context")
		}
	case "AuthorProjection":
		guest := v["author"].(map[string]any)["kind"] == "bridged"
		if guest && (v["author_assurance"] != "platform_attested" || v["trust_status"] != "external_untrusted" || v["verified"].(bool)) {
			return hcError("invalid", "guest assurance")
		}
		if !guest && (v["author_assurance"] != "native" || v["trust_status"] == "external_untrusted") {
			return hcError("invalid", "native assurance")
		}
	}
	return nil
}

// RequireCapability refuses selecting unknown or deferred features, while the DTO
// reader preserves future advertised tokens without breaking known neighbors.
func (r HumanChannelsRecord) RequireCapability(capability string) error {
	if err := hcValidate("Capabilities", r.Value); err != nil {
		return err
	}
	known := false
	for _, c := range hcProfile.Capabilities {
		if c == capability {
			known = true
		}
	}
	if known {
		for _, c := range r.Value["enabled"].([]any) {
			if c == capability {
				return nil
			}
		}
	}
	return hcError("unsupported", "capability")
}

func hcWithinDepth(v any, depth int) bool {
	if depth > 64 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for _, item := range x {
			if !hcWithinDepth(item, depth+1) {
				return false
			}
		}
	case []any:
		for _, item := range x {
			if !hcWithinDepth(item, depth+1) {
				return false
			}
		}
	}
	return true
}
