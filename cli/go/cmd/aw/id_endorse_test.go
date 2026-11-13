package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

const endorseTestOperation = "77777777-7777-4777-8777-77777777abcd"

// endorseTestProfile binds the human's identity key humanKey in
// customer.example, beside a team controller binding.
func endorseTestProfile(t *testing.T, humanKey ed25519.PrivateKey) *handoff.Profile {
	t.Helper()
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	scope := func(kind, id string) map[string]any {
		return map[string]any{"v": 1, "kind": "protected_key", "service_id": "customer-signer",
			"authority": map[string]any{"kind": kind, "id": id, "domain": "customer.example"},
			"human":     map[string]any{"id": admitTestHuman, "domain": "customer.example"}, "generation": 1}
	}
	_, teamKey, _ := ed25519.GenerateKey(nil)
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "service_id": "customer-signer", "request_origin": "https://signer.customer.example",
		"human_origin": "https://human.customer.example", "rp_id": "human.customer.example",
		"registry_origin":       "https://registry.customer.example",
		"namespace_authorities": []any{map[string]any{"domain": "customer.example", "controller_did": humanDID}},
		"bindings": []any{
			map[string]any{"scope": scope("human_identity", admitTestHuman), "authority_key_did": humanDID,
				"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}},
			map[string]any{"scope": scope("team_controller", "engineering:customer.example"),
				"authority_key_did": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
				"policy":            map[string]any{"ref": "aweb.human-assurance/1", "version": 1}},
		},
	})
	profile, err := handoff.ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func endorseTestRequest() endorsementRequest {
	return endorsementRequest{OperationID: endorseTestOperation, Human: admitTestHuman,
		Teams: []string{"zeta:customer.example", "engineering:customer.example"}, DeploymentLabel: "lab",
		RootID: "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f", RootKey: "did:key:zroot"}
}

// endorseTestPolicy is a valid default policy listing both test teams.
func endorseTestPolicy(version int) map[string]any {
	policy := map[string]any{
		"version": json.Number(strconv.Itoa(version)), "teams": []any{"engineering:customer.example", "zeta:customer.example"},
		"root_selector": map[string]any{"kind": "service_endorsed_root", "service_id": "customer-signer"},
		"subject_kinds": []any{"local_agent"}, "member_role": "member",
		"bounds": map[string]any{"max_active": json.Number("20"), "rate_window_seconds": json.Number("3600"), "max_per_window": json.Number("5")},
	}
	canonical, _ := awid.StrictCanonicalJSON(policy)
	sum := sha256.Sum256(append([]byte("aweb.admission-policy/1\n"), canonical...))
	policy["digest"] = "sha256:" + hex.EncodeToString(sum[:])
	return policy
}

func TestAnEndorsementNamesTheRootInTheHumansDomainAndItsSortedTeams(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	profile := endorseTestProfile(t, humanKey)
	binding, err := endorsementBinding(profile, admitTestHuman)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := endorsementIntent(profile, binding, endorseTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	subject, _ := json.Marshal(intent["subject"])
	want := `{"deployment_label":"lab","domain":"customer.example","root_id":"did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f","root_key":"did:key:zroot","teams":["engineering:customer.example","zeta:customer.example"]}`
	if string(subject) != want || intent["operation"] != "identity.root.endorse" || intent["audience"] != profile.RegistryOrigin {
		t.Fatalf("intent %v", intent)
	}
	for name, change := range map[string]func(*endorsementRequest){
		"repeated team":      func(r *endorsementRequest) { r.Teams = []string{"zeta:customer.example", "zeta:customer.example"} },
		"no team":            func(r *endorsementRequest) { r.Teams = nil },
		"non-canonical team": func(r *endorsementRequest) { r.Teams = []string{"Zeta:customer.example"} },
		"no label":           func(r *endorsementRequest) { r.DeploymentLabel = "" },
	} {
		request := endorseTestRequest()
		change(&request)
		if _, err := endorsementIntent(profile, binding, request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := endorsementBinding(profile, "did:aw:27zc4QzaQx7zjzNGJ4SUYdqJnqFL"); errorCodeOf(err) != "profile_scope_refused" {
		t.Errorf("unbound human: %v", err)
	}
}

// policyReads answers each team's policy read with read.
func policyReads(reads map[string]*handoff.AdmissionPolicyRead, err error) func(context.Context, string) (*handoff.AdmissionPolicyRead, error) {
	return func(_ context.Context, team string) (*handoff.AdmissionPolicyRead, error) {
		return reads[team], err
	}
}

func protectedRead(team string, policy map[string]any) *handoff.AdmissionPolicyRead {
	return &handoff.AdmissionPolicyRead{ServiceID: "customer-signer", TeamID: team, Mode: "protected",
		Policy: &handoff.AdmissionPolicy{Fields: policy}}
}

func TestTheLinkIsShownOnlyWhenEveryTeamsPolicyReadIsTheFrozenPolicy(t *testing.T) {
	frozen := endorseTestPolicy(3)
	request := map[string]any{"admission_policy": frozen, "artifact": map[string]any{"issuer_key": "did:key:zhuman"}}
	teams := []string{"engineering:customer.example", "zeta:customer.example"}
	same := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: protectedRead(teams[1], frozen)}
	var kept map[string]any
	check := endorsementCheck("did:key:zhuman", teams, policyReads(same, nil), &kept)
	if err := check(request); err != nil || kept == nil {
		t.Fatalf("err %v kept %v", err, kept)
	}
	newer := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: protectedRead(teams[1], endorseTestPolicy(4))}
	legacy := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: {Mode: "legacy"}}
	for name, tc := range map[string]struct {
		check func(map[string]any) error
		code  string
	}{
		"changed policy":   {endorsementCheck("did:key:zhuman", teams, policyReads(newer, nil), new(map[string]any)), "policy_changed"},
		"legacy team":      {endorsementCheck("did:key:zhuman", teams, policyReads(legacy, nil), new(map[string]any)), "admission_policy_missing"},
		"other issuer key": {endorsementCheck("did:key:zother", teams, policyReads(same, nil), new(map[string]any)), "operation_mismatch"},
	} {
		if err := tc.check(request); errorCodeOf(err) != tc.code {
			t.Errorf("%s: err %v", name, err)
		}
	}
	unavailable := errors.New("the read could not be answered")
	if err := endorsementCheck("did:key:zhuman", teams, policyReads(nil, unavailable), new(map[string]any))(request); !errors.Is(err, unavailable) {
		t.Errorf("unavailable read: %v", err)
	}
}

// endorsedArtifact is the unsigned certificate an endorsement froze.
func endorsedArtifact(issuer string) map[string]any {
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f",
		"domain": "customer.example", "parent": map[string]any{"kind": "identity", "id": admitTestHuman}, "kind": "agent",
		"issuer_key": issuer, "issued_at": "2026-11-13T10:00:00Z"}
}

func signedEndorsement(t *testing.T, key ed25519.PrivateKey, artifact map[string]any) []byte {
	t.Helper()
	signing, err := awid.IDCertificateSigningBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"signing": base64.StdEncoding.EncodeToString(signing),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing))})
	return raw
}

func TestTheEndorsedCertificateIsTheFrozenOneSignedByTheHumansPinnedKey(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	artifact := endorsedArtifact(humanDID)
	signed, err := endorsedCertificate(signedEndorsement(t, humanKey, artifact), artifact, humanDID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.VerifyIDCertificate(signed, humanDID); err != nil {
		t.Fatalf("the wrapper does not verify: %v", err)
	}
	_, otherKey, _ := ed25519.GenerateKey(nil)
	otherArtifact := endorsedArtifact(humanDID)
	otherArtifact["issued_at"] = "2026-11-13T11:00:00Z"
	for name, result := range map[string][]byte{
		"another key":         signedEndorsement(t, otherKey, artifact),
		"another certificate": signedEndorsement(t, humanKey, otherArtifact),
		"not a result":        []byte(`{"signing":"x"}`),
		"signing that is not what was signed": func() []byte {
			signing, _ := awid.IDCertificateSigningBytes(artifact)
			other, _ := awid.IDCertificateSigningBytes(otherArtifact)
			raw, _ := json.Marshal(map[string]any{"signing": base64.StdEncoding.EncodeToString(other),
				"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(humanKey, signing))})
			return raw
		}(),
	} {
		if _, err := endorsedCertificate(result, artifact, humanDID); errorCodeOf(err) != "signed_certificate_invalid" {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if _, err := endorsedCertificate(signedEndorsement(t, humanKey, artifact), nil, humanDID); errorCodeOf(err) != "signed_certificate_invalid" {
		t.Errorf("no frozen certificate: %v", err)
	}
}

// fakeRootRegistry records a registration and answers the root's current head.
type fakeRootRegistry struct {
	registerErr error
	current     string
	currentErr  error
	registered  map[string]any
	head        any
}

func (r *fakeRootRegistry) register(_ context.Context, bundle map[string]any, expectedHead *string) error {
	r.registered = bundle
	if expectedHead != nil {
		r.head = *expectedHead
	}
	return r.registerErr
}

func (r *fakeRootRegistry) currentHead(context.Context, map[string]any) (string, error) {
	return r.current, r.currentErr
}

func TestARegisteredEndorsementIsConfirmedOnlyByItsReadBack(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	artifact := endorsedArtifact(humanDID)
	signed, _ := endorsedCertificate(signedEndorsement(t, humanKey, artifact), artifact, humanDID)
	ours, _ := awid.IDCertificateID(signed["certificate"].(map[string]any))
	chain := []any{map[string]any{"certificate": "human"}}
	refused := errors.New("already registered")
	for name, tc := range map[string]struct {
		registry *fakeRootRegistry
		code     string
	}{
		"registered":            {&fakeRootRegistry{current: ours}, ""},
		"registered earlier":    {&fakeRootRegistry{registerErr: refused, current: ours}, ""},
		"another head":          {&fakeRootRegistry{current: "sha256:" + strings.Repeat("cd", 32)}, "registration_conflict"},
		"read-back unavailable": {&fakeRootRegistry{currentErr: errors.New("no answer")}, "registration_unconfirmed"},
		"refused and not ours":  {&fakeRootRegistry{registerErr: refused, current: "sha256:" + strings.Repeat("cd", 32)}, "registration_conflict"},
	} {
		err := registerEndorsement(context.Background(), tc.registry, chain, signed, nil)
		if errorCodeOf(err) != tc.code || (tc.code == "" && err != nil) {
			t.Errorf("%s: err %v", name, err)
		}
		certificates, _ := tc.registry.registered["certificates"].([]any)
		if len(certificates) != 2 || certificates[1].(map[string]any)["signature"] != signed["signature"] {
			t.Errorf("%s: registered %v", name, tc.registry.registered)
		}
	}
	head := "sha256:" + strings.Repeat("ab", 32)
	registry := &fakeRootRegistry{current: ours}
	if err := registerEndorsement(context.Background(), registry, chain, signed, &head); err != nil || registry.head != head {
		t.Fatalf("expected head %v err %v", registry.head, err)
	}
}

func TestAChangedEndorsementUnderASavedOperationIDIsAConflict(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, humanKey, _ := ed25519.GenerateKey(nil)
	profile := endorseTestProfile(t, humanKey)
	binding, _ := endorsementBinding(profile, admitTestHuman)
	intent, _ := endorsementIntent(profile, binding, endorseTestRequest())
	saved := map[string]any{"operation_id": endorseTestOperation, "redirect_uri": "http://127.0.0.1:5555/callback"}
	for k, v := range intent {
		saved[k] = v
	}
	raw, _ := json.Marshal(saved)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: endorseTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw}); err != nil {
		t.Fatal(err)
	}
	body, err := savedEndorsement(profile, endorseTestOperation, intent)
	if err != nil || string(body) != string(raw) {
		t.Fatalf("the same intent: body %s err %v", body, err)
	}
	changed := endorseTestRequest()
	changed.DeploymentLabel = "other"
	other, _ := endorsementIntent(profile, binding, changed)
	if _, err := savedEndorsement(profile, endorseTestOperation, other); errorCodeOf(err) != "operation_conflict" {
		t.Fatalf("changed intent: %v", err)
	}
	if body, err := savedEndorsement(profile, "88888888-8888-4888-8888-88888888abcd", intent); body != nil || err != nil {
		t.Fatalf("no saved operation: body %s err %v", body, err)
	}
}
