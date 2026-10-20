package awid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"regexp"
	"sort"
	"time"

	"github.com/awebai/aw/strictjson"
)

// OwnerActPrefix domain-separates owner acts: no team certificate, controller
// envelope or other team-key-signed object can verify as one.
const OwnerActPrefix = "aweb.owner-act/1\n"

// OwnerActMaxLifetime bounds expires_at - issued_at.
const OwnerActMaxLifetime = 10 * time.Minute

// OwnerActClockSkew is how far issued_at may run ahead of the verifier.
const OwnerActClockSkew = 60 * time.Second

const ownerActTimeLayout = "2006-01-02T15:04:05Z"

// Owner-act vocabularies. A verifier accepts only its own closed list.
var (
	// CoreOwnerActs are the acts the coordination server accepts.
	CoreOwnerActs = []string{"hook-binding.activate", "hook-binding.revoke"}
	// AppOwnerActs are the generic governance acts every naapp accepts.
	AppOwnerActs = []string{"app-role.designate", "app-role.revoke", "app-credential.recover"}
	// LogsOwnerActs are the acts logs accepts in addition to AppOwnerActs.
	LogsOwnerActs = []string{"logs.retention.set", "logs.erase", "logs.legal-hold.set", "logs.legal-hold.release"}
)

var (
	ownerUUID        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ownerTeamID      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
	ownerOrigin      = regexp.MustCompile(`^https://[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	ownerDIDKey      = regexp.MustCompile(`^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$`)
	ownerNonce       = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ownerTime        = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	ownerAppID       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	ownerDigest      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	ownerSHA256      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ownerToken       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	ownerAppScope    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$`)
	ownerRef         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	ownerPath        = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/%-]{0,511}$`)
	ownerMethod      = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE)$`)
	ownerHookName    = regexp.MustCompile(`^(post-secret-use-hook|post-governance-hook|post-manifest-command-hook|post-mutation-hook|post-command-hook)$`)
	ownerEventClass  = regexp.MustCompile(`^(all|post-secret-use-hook|post-governance-hook|post-manifest-command-hook|post-mutation-hook|post-command-hook)$`)
	ownerCatalogID   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	maxOwnerActItems = 64
)

// ownerField describes one subject field.
type ownerField struct {
	pattern  *regexp.Regexp
	integer  bool
	min, max int64
	list     bool
	enum     []string
}

func ownerString(p *regexp.Regexp) ownerField { return ownerField{pattern: p} }
func ownerList(p *regexp.Regexp) ownerField   { return ownerField{pattern: p, list: true} }
func ownerEnum(v ...string) ownerField        { return ownerField{enum: v} }
func ownerInteger(min, max int64) ownerField  { return ownerField{integer: true, min: min, max: max} }

// ownerSubject is one act's subject: its fields, those it always requires,
// and those required (and otherwise refused) when another field takes a value.
type ownerSubject struct {
	fields   map[string]ownerField
	required []string
	when     []ownerCondition
}

type ownerCondition struct {
	field, value string
	require      []string
}

func bindingSubject() ownerSubject {
	return ownerSubject{
		fields: map[string]ownerField{
			"binding_id": ownerString(ownerUUID), "installation_id": ownerString(ownerUUID),
			"generation": ownerInteger(1, strictjson.MaxSafeInteger), "app_id": ownerString(ownerAppID),
			"origin": ownerString(ownerOrigin), "digest": ownerString(ownerDigest),
			"kind":       ownerEnum("registration", "production"),
			"catalog_id": ownerString(ownerCatalogID), "catalog_version": ownerInteger(1, strictjson.MaxSafeInteger),
			"hook": ownerString(ownerHookName), "tool": ownerString(ownerToken), "method": ownerString(ownerMethod),
			"path": ownerString(ownerPath), "scopes": ownerList(ownerAppScope), "reads": ownerList(ownerToken),
		},
		required: []string{"binding_id", "installation_id", "generation", "app_id", "origin", "digest", "kind", "catalog_id", "catalog_version", "hook"},
		when: []ownerCondition{
			{field: "kind", value: "registration", require: []string{"tool", "method", "path", "scopes"}},
			{field: "kind", value: "production", require: []string{"reads"}},
		},
	}
}

// enrolmentSubject names a role holder who does not exist yet: the app mints
// the subject, and the act commits to the contact the enrolment link goes to by
// its SHA-256, without carrying it.
func enrolmentSubject() ownerSubject {
	return ownerSubject{
		fields: map[string]ownerField{
			"app_id": ownerString(ownerAppID), "installation_id": ownerString(ownerUUID),
			"role": ownerString(ownerToken), "contact_sha256": ownerString(ownerSHA256),
		},
		required: []string{"app_id", "installation_id", "role", "contact_sha256"},
	}
}

// revocationSubject names an existing role holder.
func revocationSubject() ownerSubject {
	return ownerSubject{
		fields: map[string]ownerField{
			"app_id": ownerString(ownerAppID), "installation_id": ownerString(ownerUUID),
			"role": ownerString(ownerToken), "subject_ref": ownerString(ownerRef),
		},
		required: []string{"app_id", "installation_id", "role", "subject_ref"},
	}
}

func appFields(extra map[string]ownerField) map[string]ownerField {
	fields := map[string]ownerField{"app_id": ownerString(ownerAppID), "installation_id": ownerString(ownerUUID)}
	for name, field := range extra {
		fields[name] = field
	}
	return fields
}

var ownerSubjects = map[string]ownerSubject{
	"hook-binding.activate":  bindingSubject(),
	"hook-binding.revoke":    bindingSubject(),
	"app-role.designate":     enrolmentSubject(),
	"app-role.revoke":        revocationSubject(),
	"app-credential.recover": enrolmentSubject(),
	"logs.retention.set": {
		fields: appFields(map[string]ownerField{
			"event_class": ownerString(ownerEventClass), "retention": ownerEnum("keep", "days"),
			"retention_days": ownerInteger(1, 36500),
		}),
		required: []string{"app_id", "installation_id", "event_class", "retention"},
		when:     []ownerCondition{{field: "retention", value: "days", require: []string{"retention_days"}}},
	},
	"logs.erase": {
		fields: appFields(map[string]ownerField{
			"erase_scope": ownerEnum("actor", "range"), "actor_ref": ownerString(ownerRef),
			"chain_epoch": ownerInteger(1, strictjson.MaxSafeInteger), "team_seq_first": ownerInteger(1, strictjson.MaxSafeInteger),
			"team_seq_last": ownerInteger(1, strictjson.MaxSafeInteger), "reason_code": ownerString(ownerToken),
		}),
		required: []string{"app_id", "installation_id", "erase_scope", "reason_code"},
		when: []ownerCondition{
			{field: "erase_scope", value: "actor", require: []string{"actor_ref"}},
			{field: "erase_scope", value: "range", require: []string{"chain_epoch", "team_seq_first", "team_seq_last"}},
		},
	},
	"logs.legal-hold.set": {
		fields: appFields(map[string]ownerField{
			"hold_id": ownerString(ownerRef), "hold_scope": ownerEnum("all", "actor"),
			"actor_ref": ownerString(ownerRef), "reason_code": ownerString(ownerToken),
		}),
		required: []string{"app_id", "installation_id", "hold_id", "hold_scope", "reason_code"},
		when:     []ownerCondition{{field: "hold_scope", value: "actor", require: []string{"actor_ref"}}},
	},
	"logs.legal-hold.release": {
		fields:   appFields(map[string]ownerField{"hold_id": ownerString(ownerRef)}),
		required: []string{"app_id", "installation_id", "hold_id"},
	},
}

// OwnerAct is a verified owner act.
type OwnerAct struct {
	Fields   map[string]any
	Act      string
	TeamID   string
	Audience string
	Subject  map[string]any
	Nonce    string

	issuedAt, expiresAt time.Time
}

// ownerActTime parses a time that must be in its one canonical spelling.
func ownerActTime(value string) (time.Time, error) {
	parsed, err := time.Parse(ownerActTimeLayout, value)
	if err != nil || parsed.UTC().Format(ownerActTimeLayout) != value {
		return time.Time{}, strictjson.Refuse("invalid_value", "time")
	}
	return parsed, nil
}

// OwnerActSigningBytes validates an owner act and returns the bytes the team
// key signs: the prefix followed by the act's canonical JSON.
func OwnerActSigningBytes(act map[string]any) ([]byte, error) {
	canonical, err := strictjson.Canonical(act)
	if err != nil {
		return nil, err
	}
	parsed, err := strictjson.ParseCanonicalObject(canonical)
	if err != nil {
		return nil, err
	}
	if _, err := checkOwnerAct(parsed); err != nil {
		return nil, err
	}
	return append([]byte(OwnerActPrefix), canonical...), nil
}

// SignOwnerAct signs an owner act with the team's controller key, which must
// be the act's team_key_did.
func SignOwnerAct(teamKey ed25519.PrivateKey, act map[string]any) ([]byte, string, error) {
	signing, err := OwnerActSigningBytes(act)
	if err != nil {
		return nil, "", err
	}
	if act["team_key_did"] != ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)) {
		return nil, "", strictjson.Refuse("owner_required", "the key is not the act's team key")
	}
	return signing, base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, signing)), nil
}

// OwnerActVerifyOptions are the verifier's own facts, all required.
// CurrentTeamKeyDID is the team key read fresh from the team's registry;
// Acts is the verifier's closed vocabulary; ExpectedSubject is the stored row
// the act must name exactly; and NonceUsed reports a nonce already consumed.
type OwnerActVerifyOptions struct {
	TeamID            string
	CurrentTeamKeyDID string
	Audience          string
	Acts              []string
	Now               time.Time
	ExpectedSubject   map[string]any
	NonceUsed         func(nonce string) bool
}

// VerifyOwnerAct checks an owner act in the contract's order and returns it,
// or the first refusal.
//
// It proves that the act was signed by the team's current controller key, for
// this verifier, within its lifetime, naming the expected subject. It cannot
// tell who held the key: that only the organization owner signs, after a
// fresh step-up, is the signing deployment's obligation. The caller inserts
// the nonce under a unique constraint in the act's effect transaction, so two
// concurrent uses of one act cannot both commit.
func VerifyOwnerAct(signing []byte, signature string, opts OwnerActVerifyOptions) (*OwnerAct, error) {
	if opts.TeamID == "" || opts.CurrentTeamKeyDID == "" || opts.Audience == "" || len(opts.Acts) == 0 ||
		opts.Now.IsZero() || opts.ExpectedSubject == nil || opts.NonceUsed == nil {
		return nil, strictjson.Refuse("verifier_misconfigured", "every verifier option is required")
	}
	if !bytes.HasPrefix(signing, []byte(OwnerActPrefix)) {
		return nil, strictjson.Refuse("wrong_prefix", "signing bytes do not start with %q", OwnerActPrefix)
	}
	fields, err := strictjson.ParseCanonicalObject(signing[len(OwnerActPrefix):])
	if err != nil {
		return nil, err
	}
	act, err := checkOwnerAct(fields)
	if err != nil {
		return nil, err
	}
	if act.TeamID != opts.TeamID {
		return nil, strictjson.Refuse("team_mismatch", "act for %s, expected %s", act.TeamID, opts.TeamID)
	}
	if act.Audience != opts.Audience {
		return nil, strictjson.Refuse("audience_mismatch", "act for %s", act.Audience)
	}
	if !containsString(opts.Acts, act.Act) {
		return nil, strictjson.Refuse("act_not_allowed", "%s is not in this verifier's vocabulary", act.Act)
	}
	issued, expires := act.issuedAt, act.expiresAt
	if expires.Sub(issued) > OwnerActMaxLifetime {
		return nil, strictjson.Refuse("lifetime_too_long", "an owner act lives at most %s", OwnerActMaxLifetime)
	}
	if issued.After(opts.Now.Add(OwnerActClockSkew)) {
		return nil, strictjson.Refuse("not_yet_valid", "issued at %s", fields["issued_at"])
	}
	if !opts.Now.Before(expires) {
		return nil, strictjson.Refuse("expired", "expired at %s", fields["expires_at"])
	}
	if fields["team_key_did"] != opts.CurrentTeamKeyDID {
		return nil, strictjson.Refuse("owner_required", "not signed for the team's current controller key")
	}
	public, err := ExtractPublicKey(opts.CurrentTeamKeyDID)
	if err != nil {
		return nil, strictjson.Refuse("bad_signature", "current team key does not decode")
	}
	sig, err := strictjson.DecodeSignature(signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(public, signing, sig) {
		return nil, strictjson.Refuse("bad_signature", "signature does not verify under the team key")
	}
	if opts.NonceUsed(act.Nonce) {
		return nil, strictjson.Refuse("nonce_reused", "%s", act.Nonce)
	}
	want, err := strictjson.Canonical(opts.ExpectedSubject)
	if err != nil {
		return nil, err
	}
	got, _ := strictjson.Canonical(act.Subject)
	if !bytes.Equal(want, got) {
		return nil, strictjson.Refuse("subject_mismatch", "the act names a different subject")
	}
	return act, nil
}

func checkOwnerAct(f map[string]any) (*OwnerAct, error) {
	if err := ownerKeys(f, "", []string{"v", "type", "act", "team_id", "aud", "team_key_did", "subject", "issued_at", "expires_at", "nonce"}, nil); err != nil {
		return nil, err
	}
	if v, ok := f["v"].(int64); !ok || v != 1 {
		return nil, strictjson.Refuse("invalid_value", "v")
	}
	if f["type"] != "aweb.owner-act" {
		return nil, strictjson.Refuse("invalid_value", "type")
	}
	actName, _ := f["act"].(string)
	spec, known := ownerSubjects[actName]
	if !known {
		return nil, strictjson.Refuse("unknown_act", "%v", f["act"])
	}
	for _, check := range []struct {
		name    string
		pattern *regexp.Regexp
	}{
		{"aud", ownerOrigin}, {"expires_at", ownerTime}, {"issued_at", ownerTime},
		{"nonce", ownerNonce}, {"team_id", ownerTeamID}, {"team_key_did", ownerDIDKey},
	} {
		if value, ok := f[check.name].(string); !ok || !check.pattern.MatchString(value) {
			return nil, strictjson.Refuse("invalid_value", "%s", check.name)
		}
	}
	issued, err := ownerActTime(f["issued_at"].(string))
	if err != nil {
		return nil, strictjson.Refuse("invalid_value", "issued_at")
	}
	expires, err := ownerActTime(f["expires_at"].(string))
	if err != nil {
		return nil, strictjson.Refuse("invalid_value", "expires_at")
	}
	if !expires.After(issued) {
		return nil, strictjson.Refuse("invalid_value", "expires_at must follow issued_at")
	}
	if _, err := ExtractPublicKey(f["team_key_did"].(string)); err != nil {
		return nil, strictjson.Refuse("invalid_value", "team_key_did is not an Ed25519 did:key")
	}
	subject, ok := f["subject"].(map[string]any)
	if !ok {
		return nil, strictjson.Refuse("invalid_value", "subject is not an object")
	}
	if err := checkOwnerSubject(spec, subject); err != nil {
		return nil, err
	}
	if first, ok := subject["team_seq_first"].(int64); ok && first > subject["team_seq_last"].(int64) {
		return nil, strictjson.Refuse("invalid_value", "subject.team_seq_last precedes team_seq_first")
	}
	return &OwnerAct{
		Fields: f, Act: actName, TeamID: f["team_id"].(string), Audience: f["aud"].(string),
		Subject: subject, Nonce: f["nonce"].(string), issuedAt: issued, expiresAt: expires,
	}, nil
}

func checkOwnerSubject(spec ownerSubject, subject map[string]any) error {
	required := append([]string{}, spec.required...)
	conditional := map[string]bool{}
	for _, c := range spec.when {
		for _, name := range c.require {
			conditional[name] = true
		}
	}
	for _, c := range spec.when {
		if subject[c.field] == c.value {
			required = append(required, c.require...)
		}
	}
	var optional []string
	for name := range spec.fields {
		if !conditional[name] && !containsString(spec.required, name) {
			optional = append(optional, name)
		}
	}
	allowedConditional := map[string]bool{}
	for _, name := range required {
		allowedConditional[name] = true
	}
	for name := range subject {
		if conditional[name] && !allowedConditional[name] {
			return strictjson.Refuse("unknown_field", "subject.%s", name)
		}
	}
	if err := ownerKeys(subject, "subject.", required, optional); err != nil {
		return err
	}
	names := make([]string, 0, len(subject))
	for name := range subject {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !spec.fields[name].accepts(subject[name]) {
			return strictjson.Refuse("invalid_value", "subject.%s", name)
		}
	}
	return nil
}

func (f ownerField) accepts(value any) bool {
	switch {
	case f.integer:
		n, ok := value.(int64)
		return ok && n >= f.min && n <= f.max
	case f.list:
		items, ok := value.([]any)
		if !ok || len(items) > maxOwnerActItems {
			return false
		}
		// Strictly ascending by code point, so the list is distinct and
		// every signer of the same subject signs the same bytes.
		previous := ""
		for i, item := range items {
			s, ok := item.(string)
			if !ok || !f.pattern.MatchString(s) || (i > 0 && s <= previous) {
				return false
			}
			previous = s
		}
		return true
	case f.enum != nil:
		s, ok := value.(string)
		return ok && containsString(f.enum, s)
	default:
		s, ok := value.(string)
		return ok && f.pattern.MatchString(s)
	}
}

func ownerKeys(object map[string]any, prefix string, required, optional []string) error {
	allowed := map[string]bool{}
	for _, name := range append(append([]string{}, required...), optional...) {
		allowed[name] = true
	}
	names := make([]string, 0, len(object))
	for name := range object {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !allowed[name] {
			return strictjson.Refuse("unknown_field", "%s%s", prefix, name)
		}
	}
	sorted := append([]string{}, required...)
	sort.Strings(sorted)
	for _, name := range sorted {
		if _, present := object[name]; !present {
			return strictjson.Refuse("missing_field", "%s%s", prefix, name)
		}
	}
	return nil
}

func containsString(options []string, value string) bool {
	for _, option := range options {
		if option == value {
			return true
		}
	}
	return false
}
