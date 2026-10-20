package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/awebai/aw/strictjson"
)

const ownerActVectorPath = "../../../docs/vectors/owner-act-v1.json"

func ownerSeed(start byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = start + byte(i)
	}
	return seed
}

var (
	ownerTeamSeed    = ownerSeed(0x80)
	ownerOldTeamSeed = ownerSeed(0xa0)
	ownerAdminSeed   = ownerSeed(0xc0)
)

const (
	ownerTeamIDValue = "demo:example.com"
	ownerCoreAud     = "https://aweb.example.com"
	ownerAppAud      = "https://secrets.example.com"
	ownerLogsAud     = "https://logs.example.com"
	ownerIssuedAt    = "2026-10-20T12:00:00Z"
	ownerExpiresAt   = "2026-10-20T12:05:00Z"
	ownerNow         = "2026-10-20T12:01:00Z"
	ownerInstall     = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
	ownerBinding     = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
	ownerManifest    = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

func ownerKey(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

func ownerDID(seed []byte) string {
	return ComputeDIDKey(ownerKey(seed).Public().(ed25519.PublicKey))
}

func registrationSubject() map[string]any {
	return map[string]any{
		"binding_id": ownerBinding, "installation_id": ownerInstall, "generation": int64(2),
		"app_id": "logs", "origin": ownerLogsAud, "digest": ownerManifest, "kind": "registration",
		"catalog_id": "aweb.hooks", "catalog_version": int64(1), "hook": "post-secret-use-hook",
		"tool": "ingest", "method": "POST", "path": "/hooks/ingest", "scopes": []any{"logs:ingest"},
	}
}

func productionSubject() map[string]any {
	return map[string]any{
		"binding_id": "0192f0c4-6f1e-7c3a-9a51-3d2b8e0f4c11", "installation_id": ownerInstall, "generation": int64(2),
		"app_id": "secrets", "origin": ownerAppAud, "digest": ownerManifest, "kind": "production",
		"catalog_id": "aweb.hooks", "catalog_version": int64(1), "hook": "post-secret-use-hook",
		"reads": []any{},
	}
}

func ownerAct(act, aud string, subject map[string]any, nonce string) map[string]any {
	return map[string]any{
		"v": int64(1), "type": "aweb.owner-act", "act": act, "team_id": ownerTeamIDValue, "aud": aud,
		"team_key_did": ownerDID(ownerTeamSeed), "subject": subject,
		"issued_at": ownerIssuedAt, "expires_at": ownerExpiresAt, "nonce": nonce,
	}
}

func nonceFor(i int) string { return hex.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, 16)) }

type ownerPositive struct {
	name, aud string
	acts      []string
	act       map[string]any
}

func ownerPositives() []ownerPositive {
	logsVocabulary := append(append([]string{}, AppOwnerActs...), LogsOwnerActs...)
	role := func(name string) map[string]any {
		return map[string]any{"app_id": "logs", "installation_id": ownerInstall, "role": name, "subject_ref": "member:c_41"}
	}
	enrol := func(app, name, contact string) map[string]any {
		return map[string]any{"app_id": app, "installation_id": ownerInstall, "role": name, "contact_sha256": contactSHA256(contact)}
	}
	app := func(extra map[string]any) map[string]any {
		subject := map[string]any{"app_id": "logs", "installation_id": ownerInstall}
		for k, v := range extra {
			subject[k] = v
		}
		return subject
	}
	cases := []struct {
		name, act, aud string
		acts           []string
		subject        map[string]any
	}{
		{"activate_registration", "hook-binding.activate", ownerCoreAud, CoreOwnerActs, registrationSubject()},
		{"activate_production", "hook-binding.activate", ownerCoreAud, CoreOwnerActs, productionSubject()},
		{"revoke_registration", "hook-binding.revoke", ownerCoreAud, CoreOwnerActs, registrationSubject()},
		{"designate_reader", "app-role.designate", ownerLogsAud, logsVocabulary, enrol("logs", "logs.reader", "reader@example.com")},
		{"revoke_reader", "app-role.revoke", ownerLogsAud, logsVocabulary, role("logs.reader")},
		{"recover_approver_credential", "app-credential.recover", ownerAppAud, AppOwnerActs, enrol("secrets", "secrets.owner", "owner@example.com")},
		{"retention_keep", "logs.retention.set", ownerLogsAud, logsVocabulary, app(map[string]any{"event_class": "all", "retention": "keep"})},
		{"retention_days", "logs.retention.set", ownerLogsAud, logsVocabulary, app(map[string]any{"event_class": "post-command-hook", "retention": "days", "retention_days": int64(90)})},
		{"erase_actor", "logs.erase", ownerLogsAud, logsVocabulary, app(map[string]any{"erase_scope": "actor", "actor_ref": "member:c_41", "reason_code": "subject_request"})},
		{"erase_range", "logs.erase", ownerLogsAud, logsVocabulary, app(map[string]any{"erase_scope": "range", "chain_epoch": int64(1), "team_seq_first": int64(10), "team_seq_last": int64(20), "reason_code": "owner_request"})},
		{"legal_hold_set", "logs.legal-hold.set", ownerLogsAud, logsVocabulary, app(map[string]any{"hold_id": "hold_1", "hold_scope": "all", "reason_code": "litigation"})},
		{"legal_hold_release", "logs.legal-hold.release", ownerLogsAud, logsVocabulary, app(map[string]any{"hold_id": "hold_1"})},
	}
	var out []ownerPositive
	for i, c := range cases {
		out = append(out, ownerPositive{c.name, c.aud, c.acts, ownerAct(c.act, c.aud, c.subject, nonceFor(i))})
	}
	return out
}

// contactSHA256 is the hex SHA-256 of a contact's UTF-8 bytes, as the app
// computes it from the contact it is asked to enrol.
func contactSHA256(contact string) string {
	sum := sha256.Sum256([]byte(contact))
	return hex.EncodeToString(sum[:])
}

func ownerOptions(aud string, acts []string, subject map[string]any) map[string]any {
	options := map[string]any{
		"team_id": ownerTeamIDValue, "current_team_key_did": ownerDID(ownerTeamSeed), "audience": aud,
		"acts": acts, "now": ownerNow, "nonce_used": false,
	}
	if subject != nil {
		options["expected_subject"] = subject
	}
	return options
}

func ownerSign(t *testing.T, seed []byte, act map[string]any) ([]byte, string) {
	t.Helper()
	canonical, err := strictjson.Canonical(act)
	if err != nil {
		t.Fatal(err)
	}
	signing := append([]byte(OwnerActPrefix), canonical...)
	return signing, base64.RawStdEncoding.EncodeToString(ed25519.Sign(ownerKey(seed), signing))
}

func ownerSet(act map[string]any, key string, value any) map[string]any {
	copied := map[string]any{}
	for k, v := range act {
		copied[k] = v
	}
	if value == nil {
		delete(copied, key)
	} else {
		copied[key] = value
	}
	return copied
}

func buildOwnerActVector(t *testing.T) map[string]any {
	var positives []map[string]any
	for _, p := range ownerPositives() {
		signing, signature, err := SignOwnerAct(ownerKey(ownerTeamSeed), p.act)
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		positives = append(positives, map[string]any{
			"name": p.name, "act": p.act, "signing_bytes_b64url": base64.RawURLEncoding.EncodeToString(signing),
			"signature_b64": signature, "verify": ownerOptions(p.aud, p.acts, p.act["subject"].(map[string]any)),
		})
	}

	base := ownerAct("hook-binding.activate", ownerCoreAud, registrationSubject(), nonceFor(40))
	baseOptions := func() map[string]any { return ownerOptions(ownerCoreAud, CoreOwnerActs, registrationSubject()) }
	withOption := func(key string, value any) map[string]any {
		options := baseOptions()
		options[key] = value
		return options
	}
	subjectWith := func(key string, value any) map[string]any {
		subject := registrationSubject()
		if value == nil {
			delete(subject, key)
		} else {
			subject[key] = value
		}
		return subject
	}
	adminAct := ownerSet(base, "team_key_did", ownerDID(ownerAdminSeed))
	oldAct := ownerSet(base, "team_key_did", ownerDID(ownerOldTeamSeed))
	logsAtCore := ownerAct("logs.erase", ownerCoreAud, map[string]any{"app_id": "logs", "installation_id": ownerInstall, "erase_scope": "actor", "actor_ref": "member:c_41", "reason_code": "owner_request"}, nonceFor(41))
	certificate := map[string]any{
		"version": int64(1), "certificate_id": "c_41", "team_id": ownerTeamIDValue,
		"team_did_key": ownerDID(ownerTeamSeed), "member_did_key": ownerDID(ownerAdminSeed),
		"alias": "bond", "lifetime": "persistent", "issued_at": ownerIssuedAt,
	}
	certBytes, _ := strictjson.Canonical(certificate)

	type negative struct {
		name, err string
		seed      []byte
		act       map[string]any
		raw       []byte
		options   map[string]any
	}
	designation := map[string]any{"app_id": "secrets", "installation_id": ownerInstall, "role": "secrets.owner", "contact_sha256": contactSHA256("owner@example.com")}
	designate := ownerAct("app-role.designate", ownerAppAud, designation, nonceFor(42))
	otherContact := map[string]any{"app_id": "secrets", "installation_id": ownerInstall, "role": "secrets.owner", "contact_sha256": contactSHA256("someone-else@example.com")}
	designationWithRef := map[string]any{"app_id": "secrets", "installation_id": ownerInstall, "role": "secrets.owner", "contact_sha256": contactSHA256("owner@example.com"), "subject_ref": "member:c_41"}
	production := productionSubject()
	production["tool"] = "ingest"
	negatives := []negative{
		{name: "admin_signer", err: "owner_required", seed: ownerAdminSeed, act: adminAct},
		{name: "rotated_out_team_key", err: "owner_required", seed: ownerOldTeamSeed, act: oldAct},
		{name: "team_key_claimed_but_admin_signed", err: "bad_signature", seed: ownerAdminSeed, act: base},
		{name: "expired", err: "expired", seed: ownerTeamSeed, act: base, options: withOption("now", "2026-10-20T12:05:00Z")},
		{name: "issued_in_the_future", err: "not_yet_valid", seed: ownerTeamSeed, act: base, options: withOption("now", "2026-10-20T11:58:59Z")},
		{name: "lifetime_over_ten_minutes", err: "lifetime_too_long", seed: ownerTeamSeed, act: ownerSet(base, "expires_at", "2026-10-20T12:10:01Z")},
		{name: "nonce_reused", err: "nonce_reused", seed: ownerTeamSeed, act: base, options: withOption("nonce_used", true)},
		{name: "subject_generation_mismatch", err: "subject_mismatch", seed: ownerTeamSeed, act: base, options: withOption("expected_subject", subjectWith("generation", int64(3)))},
		{name: "subject_digest_mismatch", err: "subject_mismatch", seed: ownerTeamSeed, act: base, options: withOption("expected_subject", subjectWith("digest", "sha256:"+hex.EncodeToString(make([]byte, 32))))},
		{name: "logs_act_at_core", err: "act_not_allowed", seed: ownerTeamSeed, act: logsAtCore},
		{name: "core_act_at_an_app", err: "act_not_allowed", seed: ownerTeamSeed, act: ownerSet(base, "aud", ownerAppAud),
			options: ownerOptions(ownerAppAud, AppOwnerActs, nil)},
		{name: "wrong_audience", err: "audience_mismatch", seed: ownerTeamSeed, act: ownerSet(base, "aud", ownerLogsAud)},
		{name: "wrong_team", err: "team_mismatch", seed: ownerTeamSeed, act: ownerSet(base, "team_id", "other:example.com")},
		{name: "team_certificate_presented_as_owner_act", err: "wrong_prefix", seed: ownerTeamSeed, raw: certBytes},
		{name: "unknown_act", err: "unknown_act", seed: ownerTeamSeed, act: ownerSet(base, "act", "hook-binding.delete")},
		{name: "registration_subject_with_reads", err: "unknown_field", seed: ownerTeamSeed, act: ownerSet(base, "subject", subjectWith("reads", []any{}))},
		{name: "production_subject_with_tool", err: "unknown_field", seed: ownerTeamSeed, act: ownerSet(base, "subject", production)},
		{name: "registration_subject_missing_scopes", err: "missing_field", seed: ownerTeamSeed, act: ownerSet(base, "subject", subjectWith("scopes", nil))},
		{name: "designation_for_another_contact", err: "subject_mismatch", seed: ownerTeamSeed, act: designate,
			options: ownerOptions(ownerAppAud, AppOwnerActs, otherContact)},
		{name: "designation_naming_a_subject", err: "unknown_field", seed: ownerTeamSeed, act: ownerSet(designate, "subject", designationWithRef),
			options: ownerOptions(ownerAppAud, AppOwnerActs, nil)},
		{name: "non_canonical_bytes", err: "not_canonical", seed: ownerTeamSeed,
			raw: append([]byte(OwnerActPrefix), bytes.Replace(mustOwnerCanonical(t, base), []byte(`{"act"`), []byte(`{ "act"`), 1)...)},
	}
	var out []map[string]any
	for _, n := range negatives {
		signing := n.raw
		if signing == nil {
			canonical := mustOwnerCanonical(t, n.act)
			signing = append([]byte(OwnerActPrefix), canonical...)
		}
		options := n.options
		if options == nil {
			options = baseOptions()
		}
		out = append(out, map[string]any{
			"name": n.name, "signing_bytes_b64url": base64.RawURLEncoding.EncodeToString(signing),
			"signature_b64": base64.RawStdEncoding.EncodeToString(ed25519.Sign(ownerKey(n.seed), signing)),
			"verify":        options, "error": n.err,
		})
	}

	return map[string]any{
		"name":   "owner-act-v1",
		"status": "proposed (aweb-acgh.16.3); frozen once reviewed",
		"scheme": map[string]any{
			"authority":     "docs/owner-act.md",
			"signing_bytes": "the ASCII prefix 'aweb.owner-act/1' and a newline, then the act's strict canonical JSON (the hook event rules: sorted keys, printable ASCII, no floats, no null)",
			"signature":     "detached Ed25519 by the team's current controller key, raw standard base64 without padding",
			"times":         "issued_at and expires_at are UTC to the second; expires_at - issued_at is at most 600 seconds; issued_at may lead the verifier by at most 60 seconds",
			"nonce":         "16 random bytes as 32 lowercase hex characters, single use per verifier; recorded only when the act's effect commits",
			"vocabularies":  map[string]any{"core": CoreOwnerActs, "app": AppOwnerActs, "logs": LogsOwnerActs},
			"verify":        "each case's verify object is what the verifier knows independently: its team, the team key read fresh from the registry, its own audience and vocabulary, its clock, the stored subject when it has one, and whether the nonce was used",
			"order":         "prefix; strict parse; canonical bytes; fields; known act; field values; subject; team; audience; vocabulary; lifetime; not yet valid; expired; the current team key; the signature; the nonce; the expected subject",
		},
		"positive_cases": positives,
		"negative_cases": out,
	}
}

func mustOwnerCanonical(t *testing.T, value map[string]any) []byte {
	t.Helper()
	data, err := strictjson.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// OWNERACT_WRITE_VECTOR=1 rewrites the vector from the definitions above.
func TestWriteOwnerActVector(t *testing.T) {
	if os.Getenv("OWNERACT_WRITE_VECTOR") != "1" {
		t.Skip("set OWNERACT_WRITE_VECTOR=1 to rewrite the owner-act vector")
	}
	data, err := json.MarshalIndent(buildOwnerActVector(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownerActVectorPath, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerActVectorRegeneratesByteForByte(t *testing.T) {
	committed, err := os.ReadFile(ownerActVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := json.MarshalIndent(buildOwnerActVector(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, append(rebuilt, '\n')) {
		t.Fatal("committed owner-act vector differs from the regenerated one; rewrite only for a reviewed change")
	}
}

type ownerVerifyCase struct {
	TeamID          string         `json:"team_id"`
	CurrentKey      string         `json:"current_team_key_did"`
	Audience        string         `json:"audience"`
	Acts            []string       `json:"acts"`
	Now             string         `json:"now"`
	ExpectedSubject map[string]any `json:"expected_subject"`
	NonceUsed       bool           `json:"nonce_used"`
}

func (c ownerVerifyCase) options(t *testing.T) OwnerActVerifyOptions {
	now, err := time.Parse(ownerActTimeLayout, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if c.ExpectedSubject != nil {
		data, _ := json.Marshal(c.ExpectedSubject)
		parsed, err := strictjson.ParseStrict(data)
		if err != nil {
			t.Fatal(err)
		}
		expected = parsed.(map[string]any)
	}
	return OwnerActVerifyOptions{
		TeamID: c.TeamID, CurrentTeamKeyDID: c.CurrentKey, Audience: c.Audience, Acts: c.Acts, Now: now,
		ExpectedSubject: expected, NonceUsed: func(string) bool { return c.NonceUsed },
	}
}

func TestOwnerActVectorCases(t *testing.T) {
	var vector struct {
		Positive []struct {
			Name      string          `json:"name"`
			Signing   string          `json:"signing_bytes_b64url"`
			Signature string          `json:"signature_b64"`
			Verify    ownerVerifyCase `json:"verify"`
		} `json:"positive_cases"`
		Negative []struct {
			Name      string          `json:"name"`
			Signing   string          `json:"signing_bytes_b64url"`
			Signature string          `json:"signature_b64"`
			Verify    ownerVerifyCase `json:"verify"`
			Error     string          `json:"error"`
		} `json:"negative_cases"`
	}
	data, err := os.ReadFile(ownerActVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Positive) == 0 || len(vector.Negative) == 0 {
		t.Fatal("vector has no cases")
	}
	for _, c := range vector.Positive {
		t.Run(c.Name, func(t *testing.T) {
			signing, _ := base64.RawURLEncoding.DecodeString(c.Signing)
			if _, err := VerifyOwnerAct(signing, c.Signature, c.Verify.options(t)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, c := range vector.Negative {
		t.Run(c.Name, func(t *testing.T) {
			signing, _ := base64.RawURLEncoding.DecodeString(c.Signing)
			_, err := VerifyOwnerAct(signing, c.Signature, c.Verify.options(t))
			if strictjson.Code(err) != c.Error {
				t.Fatalf("got %v, want %s", err, c.Error)
			}
		})
	}
}

func TestSignOwnerActRefusesAKeyThatIsNotTheTeamKey(t *testing.T) {
	act := ownerAct("hook-binding.activate", ownerCoreAud, registrationSubject(), nonceFor(0))
	if _, _, err := SignOwnerAct(ownerKey(ownerAdminSeed), act); strictjson.Code(err) != "owner_required" {
		t.Fatalf("got %v, want owner_required", err)
	}
}
