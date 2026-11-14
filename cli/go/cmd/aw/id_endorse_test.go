package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

const endorseTestOperation = "77777777-7777-4777-8777-77777777abcd"

// endorseTestProfile binds the human's identity key humanKey in
// customer.example, beside a team controller binding.
func endorseTestProfile(t *testing.T, humanKey ed25519.PrivateKey) *handoff.Profile {
	t.Helper()
	profile, err := handoff.ParseProfile(endorseTestProfileJSON(humanKey, "https://signer.customer.example", "https://human.customer.example"))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// endorseTestProfileJSON is endorseTestProfile's file, at the given service
// origins.
func endorseTestProfileJSON(humanKey ed25519.PrivateKey, requestOrigin, humanOrigin string) []byte {
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	scope := func(kind, id string) map[string]any {
		return map[string]any{"v": 1, "kind": "protected_key", "service_id": "customer-signer",
			"authority": map[string]any{"kind": kind, "id": id, "domain": "customer.example"},
			"human":     map[string]any{"id": admitTestHuman, "domain": "customer.example"}, "generation": 1}
	}
	_, teamKey, _ := ed25519.GenerateKey(nil)
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "service_id": "customer-signer", "request_origin": requestOrigin,
		"human_origin": humanOrigin, "rp_id": "human.customer.example",
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
	return raw
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
	if string(subject) != want || intent["operation"] != "identity.root.endorse" || intent["audience"] != profile.RegistryOrigin ||
		intent["approval_format"] != "intent_v1" {
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
	_, humanKey, _ := ed25519.GenerateKey(nil)
	request := endorseFrozenIntent(t, endorseTestProfile(t, humanKey), "did:key:zhuman")
	teams := []string{"engineering:customer.example", "zeta:customer.example"}
	same := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: protectedRead(teams[1], frozen)}
	var kept map[string]any
	check := endorsementCheck("did:key:zhuman", teams, policyReads(same, nil), &kept)
	if err := check(context.Background(), request); err != nil || kept == nil {
		t.Fatalf("err %v kept %v", err, kept)
	}
	newer := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: protectedRead(teams[1], endorseTestPolicy(4))}
	legacy := map[string]*handoff.AdmissionPolicyRead{teams[0]: protectedRead(teams[0], frozen), teams[1]: {Mode: "legacy"}}
	for name, tc := range map[string]struct {
		check func(context.Context, map[string]any) error
		code  string
	}{
		"changed policy":   {endorsementCheck("did:key:zhuman", teams, policyReads(newer, nil), new(map[string]any)), "policy_changed"},
		"legacy team":      {endorsementCheck("did:key:zhuman", teams, policyReads(legacy, nil), new(map[string]any)), "admission_policy_missing"},
		"other issuer key": {endorsementCheck("did:key:zother", teams, policyReads(same, nil), new(map[string]any)), "operation_mismatch"},
	} {
		if err := tc.check(context.Background(), request); errorCodeOf(err) != tc.code {
			t.Errorf("%s: err %v", name, err)
		}
	}
	unavailable := errors.New("the read could not be answered")
	if err := endorsementCheck("did:key:zhuman", teams, policyReads(nil, unavailable), new(map[string]any))(context.Background(), request); !errors.Is(err, unavailable) {
		t.Errorf("unavailable read: %v", err)
	}
	// A read that never answers ends with the caller's context, and is never
	// taken as the policy.
	ctx, cancel := context.WithCancel(context.Background())
	blocked := func(readCtx context.Context, _ string) (*handoff.AdmissionPolicyRead, error) {
		cancel()
		select {
		case <-readCtx.Done():
			return nil, readCtx.Err()
		case <-time.After(2 * time.Second):
			return nil, errors.New("the read never saw the caller's cancellation")
		}
	}
	kept = nil
	if err := endorsementCheck("did:key:zhuman", teams, blocked, &kept)(ctx, request); !errors.Is(err, context.Canceled) || kept != nil {
		t.Errorf("cancelled read: err %v kept %v", err, kept)
	}
}

// endorsedArtifact is the unsigned certificate an endorsement froze.
func endorsedArtifact(issuer string) map[string]any {
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f",
		"domain": "customer.example", "parent": map[string]any{"kind": "identity", "id": admitTestHuman}, "kind": "agent",
		"issuer_key": issuer, "issued_at": "2026-11-13T10:00:00Z"}
}

// signedCertificate is artifact signed by key, in the {certificate,
// signature} wrapper a verified endorsement yields.
func signedCertificate(t *testing.T, key ed25519.PrivateKey, artifact map[string]any) map[string]any {
	t.Helper()
	signing, err := awid.IDCertificateSigningBytes(artifact)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certificate": artifact, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signing))}
}

// endorseFrozenIntent is the request an endorsement of endorseTestRequest
// freezes for the human issuer: the certificate to issue, without its
// issued_at, inside a day's issuance window around endorsedArtifact's time.
func endorseFrozenIntent(t *testing.T, profile *handoff.Profile, issuer string) map[string]any {
	t.Helper()
	binding, err := endorsementBinding(profile, admitTestHuman)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := endorsementIntent(profile, binding, endorseTestRequest())
	if err != nil {
		t.Fatal(err)
	}
	template := endorsedArtifact(issuer)
	delete(template, "issued_at")
	intent["operation_id"] = endorseTestOperation
	intent["registry"], intent["expected_head"] = profile.RegistryOrigin, nil
	intent["responsibility_statement"], intent["admission_policy"] = handoff.RootResponsibilityStatement, endorseTestPolicy(3)
	intent["artifact"] = map[string]any{"v": 1, "type": "aweb.protected-artifact-intent", "template": template,
		"delivery":        map[string]any{"audience": profile.RegistryOrigin, "method": "POST", "path": "/v1/id-certificates/register"},
		"issuance_window": map[string]any{"not_before": "2026-11-13T09:00:00Z", "not_after": "2026-11-14T09:00:00Z"}}
	raw, _ := json.Marshal(intent)
	request, ok := handoff.DecodeObject(raw)
	if !ok {
		t.Fatal("the frozen intent does not decode")
	}
	return request
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
	frozen := endorseFrozenIntent(t, endorseTestProfile(t, humanKey), humanDID)
	signed, err := endorsedCertificate(signedEndorsement(t, humanKey, artifact), frozen, humanDID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.VerifyIDCertificate(signed, humanDID); err != nil {
		t.Fatalf("the wrapper does not verify: %v", err)
	}
	_, otherKey, _ := ed25519.GenerateKey(nil)
	otherArtifact := endorsedArtifact(humanDID)
	otherArtifact["id"] = "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"
	lateArtifact := endorsedArtifact(humanDID)
	lateArtifact["issued_at"] = "2026-11-14T10:00:00Z"
	for name, result := range map[string][]byte{
		"another key":               signedEndorsement(t, otherKey, artifact),
		"another certificate":       signedEndorsement(t, humanKey, otherArtifact),
		"issued outside its window": signedEndorsement(t, humanKey, lateArtifact),
		"not a result":              []byte(`{"signing":"x"}`),
		"signing that is not what was signed": func() []byte {
			signing, _ := awid.IDCertificateSigningBytes(artifact)
			other, _ := awid.IDCertificateSigningBytes(otherArtifact)
			raw, _ := json.Marshal(map[string]any{"signing": base64.StdEncoding.EncodeToString(other),
				"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(humanKey, signing))})
			return raw
		}(),
	} {
		if _, err := endorsedCertificate(result, frozen, humanDID); errorCodeOf(err) != "signed_certificate_invalid" {
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
	signed := signedCertificate(t, humanKey, artifact)
	ours, _ := awid.IDCertificateID(signed["certificate"].(map[string]any))
	chain := []any{signedHumanCertificate(t, humanKey)}
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
		home := t.TempDir()
		err := registerEndorsement(context.Background(), tc.registry, chain, signed, nil, home)
		if errorCodeOf(err) != tc.code || (tc.code == "" && err != nil) {
			t.Errorf("%s: err %v", name, err)
		}
		certificates, _ := tc.registry.registered["certificates"].([]any)
		if len(certificates) != 2 || certificates[1].(map[string]any)["signature"] != signed["signature"] {
			t.Errorf("%s: registered %v", name, tc.registry.registered)
		}
		// Only a confirmed endorsement installs the chain it registered.
		installed, loadErr := awconfig.LoadInstalledIDChain(home)
		if loadErr != nil {
			t.Fatalf("%s: %v", name, loadErr)
		}
		if tc.code == "" && (installed == nil || !sameJSONForTest(installed.Bundle, tc.registry.registered)) {
			t.Errorf("%s: installed %v, registered %v", name, installed, tc.registry.registered)
		}
		if tc.code != "" && installed != nil {
			t.Errorf("%s: an unconfirmed endorsement installed a chain", name)
		}
	}
	head := "sha256:" + strings.Repeat("ab", 32)
	registry := &fakeRootRegistry{current: ours}
	if err := registerEndorsement(context.Background(), registry, chain, signed, &head, t.TempDir()); err != nil || registry.head != head {
		t.Fatalf("expected head %v err %v", registry.head, err)
	}
}

// A rerun of a committed endorsement installs its chain when it is missing,
// and leaves an installed one exactly as it is.
func TestARerunOfAConfirmedEndorsementInstallsItsChainOnce(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	artifact := endorsedArtifact(humanDID)
	signed := signedCertificate(t, humanKey, artifact)
	ours, _ := awid.IDCertificateID(signed["certificate"].(map[string]any))
	chain := []any{signedHumanCertificate(t, humanKey)}
	home := t.TempDir()
	path := filepath.Join(home, "id-chain.json")
	if err := registerEndorsement(context.Background(), &fakeRootRegistry{current: ours}, chain, signed, nil, home); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("already registered")
	if err := registerEndorsement(context.Background(), &fakeRootRegistry{registerErr: refused, current: ours}, chain, signed, nil, home); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Fatal("the rerun changed the installed chain")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := registerEndorsement(context.Background(), &fakeRootRegistry{registerErr: refused, current: ours}, chain, signed, nil, home); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(first, again) {
		t.Fatal("the rerun did not install the missing chain")
	}
}

// signedHumanCertificate is example.com's human certificate signed by
// humanKey, the supporting chain an endorsement registers above the root.
func signedHumanCertificate(t *testing.T, humanKey ed25519.PrivateKey) map[string]any {
	t.Helper()
	human := map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": admitTestHuman, "domain": "example.com",
		"parent": map[string]any{"kind": "namespace", "id": "example.com"}, "kind": "human",
		"issuer_key": awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey)), "issued_at": "2026-11-13T09:00:00Z"}
	signing, err := awid.IDCertificateSigningBytes(human)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"certificate": human, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanKey, signing))}
}

func sameJSONForTest(a, b any) bool {
	left, errLeft := awid.StrictCanonicalJSON(a)
	right, errRight := awid.StrictCanonicalJSON(b)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
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

// statusRegistry is a registry whose status answer is status, and that
// refuses every registration.
func statusRegistry(t *testing.T, status any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/id-certificates/status" {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"detail":"head_conflict"}`))
	}))
	t.Cleanup(server.Close)
	return server
}

// vectorStatus is the published status fixture name for example.com.
func vectorStatus(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Statuses map[string]map[string]any `json:"status_fixtures"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	return vectors.Statuses[name]
}

// readBackAt is the real read-back adapter at a registry answering status,
// for an endorsed root of example.com whose certificate the vector's status
// does not hold as current. It answers the outcome of registering it.
func readBackAt(t *testing.T, status any, controller string) error {
	t.Helper()
	const root = "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj"
	humanPublic, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanPublic)
	human := map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": admitTestHuman, "domain": "example.com",
		"parent": map[string]any{"kind": "namespace", "id": "example.com"}, "kind": "human", "issuer_key": humanDID, "issued_at": "2026-11-13T09:00:00Z"}
	humanSigning, _ := awid.IDCertificateSigningBytes(human)
	humanSigned := map[string]any{"certificate": human, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(humanKey, humanSigning))}
	artifact := map[string]any{"v": json.Number("1"), "type": "aweb.id-certificate", "id": root, "domain": "example.com",
		"parent": map[string]any{"kind": "identity", "id": admitTestHuman}, "kind": "agent", "issuer_key": humanDID, "issued_at": "2026-11-13T10:00:00Z"}
	signed := signedCertificate(t, humanKey, artifact)
	server := statusRegistry(t, status)
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "service_id": "customer-signer", "request_origin": "https://signer.example.com",
		"human_origin": "https://human.example.com", "rp_id": "human.example.com", "registry_origin": server.URL,
		"namespace_authorities": []any{map[string]any{"domain": "example.com", "controller_did": controller}},
		"bindings": []any{map[string]any{
			"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "customer-signer",
				"authority": map[string]any{"kind": "human_identity", "id": admitTestHuman, "domain": "example.com"},
				"human":     map[string]any{"id": admitTestHuman, "domain": "example.com"}, "generation": 1},
			"authority_key_did": humanDID, "policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}}},
	})
	profile, err := handoff.ParseProfile(raw)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.TrustRegistryOrigin(server.URL); err != nil {
		t.Fatal(err)
	}
	_, rootKey, _ := ed25519.GenerateKey(nil)
	adapter := &pinnedRootRegistry{registry: registry, profile: profile, domain: "example.com", signer: awid.KeySigner(rootKey),
		root: awid.IDChainSubject{ID: root, DIDKey: awid.ComputeDIDKey(rootKey.Public().(ed25519.PublicKey))}}
	return registerEndorsement(context.Background(), adapter, []any{humanSigned}, signed, nil, t.TempDir())
}

// openEpochController is the controller key of status's open namespace epoch.
func openEpochController(status map[string]any) string {
	epochs := status["namespace"].(map[string]any)["epochs"].([]any)
	for i := len(epochs) - 1; i >= 0; i-- {
		if epoch := epochs[i].(map[string]any); epoch["retired_at"] == nil {
			return epoch["did_key"].(string)
		}
	}
	return ""
}

func TestTheRealReadBackReportsAVerifiedCompetingHeadAsAConflict(t *testing.T) {
	status := vectorStatus(t, "normal")
	var head string
	for _, value := range status["identities"].([]any) {
		if row := value.(map[string]any); row["id"] == "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj" {
			head = row["current_certificate_id"].(string)
		}
	}
	err := readBackAt(t, status, openEpochController(status))
	if errorCodeOf(err) != "registration_conflict" || head == "" || !strings.Contains(err.Error(), head) {
		t.Fatalf("err %v", err)
	}
}

func TestTheRealReadBackNeverTakesUnverifiedStatusAsAHead(t *testing.T) {
	normal := vectorStatus(t, "normal")
	for name, tc := range map[string]struct {
		status     any
		controller string
	}{
		"bare rows": {map[string]any{"identities": []any{map[string]any{"id": "did:aw:2e2SPDJNyxg5Dt6EFJX3Tcn8Tauj",
			"current_certificate_id": "garbage-head"}}}, openEpochController(normal)},
		"another namespace authority": {normal, func() string {
			public, _, _ := ed25519.GenerateKey(nil)
			return awid.ComputeDIDKey(public)
		}()},
		"another domain's status": {func() map[string]any {
			other := map[string]any{}
			for k, v := range normal {
				other[k] = v
			}
			other["domain"] = "other.example"
			return other
		}(), openEpochController(normal)},
	} {
		if err := readBackAt(t, tc.status, tc.controller); errorCodeOf(err) != "registration_unconfirmed" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestAPendingEndorsementReportsWhatTheCallerShowsTheHuman(t *testing.T) {
	expires := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	prepared := &handoff.Prepared{OperationID: endorseTestOperation, HandoffID: "h1",
		Digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", ExpiresAt: expires}
	report := pendingEndorsementReport(prepared, "https://human.customer.example/handoff/h1", &handoff.Receipt{State: "pending", Reason: "awaiting_human"})
	raw, _ := json.Marshal(report)
	want := `{"digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expires_at":"2026-11-13T12:00:00Z",` +
		`"fingerprint":"0123 4567 89ab cdef","operation_id":"` + endorseTestOperation + `","page":"https://human.customer.example/handoff/h1",` +
		`"reason":"awaiting_human","state":"pending"}`
	if string(raw) != want {
		t.Fatalf("report %s\nwant   %s", raw, want)
	}
}

func TestAPendingEndorsementSaysWhoDecidesWhereAndHowToContinue(t *testing.T) {
	saved := time.Local
	time.Local = time.UTC
	t.Cleanup(func() { time.Local = saved })
	prepared := &handoff.Prepared{OperationID: endorseTestOperation, Digest: strings.Repeat("ab", 32),
		ExpiresAt: time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)}
	report := pendingEndorsementReport(prepared, "https://human.customer.example/handoff/h1", &handoff.Receipt{State: "pending", Reason: "awaiting_human"})
	text := pendingEndorsementText(report)
	for _, want := range []string{"approver", "https://human.customer.example/handoff/h1", "2026-11-14 09:30 UTC",
		"Run the same command again", endorseTestOperation} {
		if !strings.Contains(text, want) {
			t.Errorf("%q lacks %q", text, want)
		}
	}
	for _, unwanted := range []string{"emailed", "--operation-id", "awaiting_human"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("%q shows %q", text, unwanted)
		}
	}
}

// The real command invites an agent child as a root whose chain endorsement
// installed, and refuses it as the same root without one.
func TestAnEndorsedRootInvitesAnAgentChildWithItsInstalledChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	_, humanKey, _ := ed25519.GenerateKey(nil)
	humanDID := awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))
	artifact := endorsedArtifact(humanDID)
	signed := signedCertificate(t, humanKey, artifact)
	ours, _ := awid.IDCertificateID(signed["certificate"].(map[string]any))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "root-home")
	_, rootKey, _ := ed25519.GenerateKey(nil)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID: awid.ComputeDIDKey(rootKey.Public().(ed25519.PublicKey)), StableID: artifact["id"].(string), Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://registry.customer.example", RegistryStatus: "registered",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), rootKey); err != nil {
		t.Fatal(err)
	}
	invite := func() (map[string]any, string, error) {
		command := exec.CommandContext(ctx, bin, "--json", "--identity-home", home, "id", "child", "invite", "--kind", "agent",
			"--recipient", "spawned agent", "--registry", "https://registry.customer.example")
		command.Dir, command.Env = root, testCommandEnv(root)
		out, err := command.CombinedOutput()
		var result map[string]any
		_ = json.Unmarshal(out, &result)
		return result, string(out), err
	}
	if _, out, err := invite(); err == nil || !strings.Contains(out, "no installed chain") {
		t.Fatalf("a root with no installed chain invited: %v %s", err, out)
	}
	if err := registerEndorsement(ctx, &fakeRootRegistry{current: ours}, []any{signedHumanCertificate(t, humanKey)}, signed, nil, home); err != nil {
		t.Fatal(err)
	}
	invited, out, err := invite()
	if err != nil || invited["kind"] != "agent" || invited["invitation_id"] == "" {
		t.Fatalf("invite: %v %s", err, out)
	}
	if parent, _ := invited["parent"].(map[string]any); parent["kind"] != "identity" || parent["id"] != artifact["id"] {
		t.Fatalf("parent %v", invited["parent"])
	}
}

func TestAnOldCommittedEndorsementIsKeptAndNeverRegistered(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	result := signedEndorsement(t, humanKey, endorsedArtifact(awid.ComputeDIDKey(humanKey.Public().(ed25519.PublicKey))))
	report, facts := endorsementReading(&awconfig.PendingGovernanceOperation{OperationID: endorseTestOperation}, nil, result)
	if report != nil || facts == nil || facts.State != "committed" || facts.Verification != "unverifiable" || len(facts.Signing) == 0 || len(facts.Signature) != 64 {
		t.Fatalf("report %v facts %+v", report, facts)
	}
}

// TestTheEndorseCommandStopsAtAQuarantinedEndorsementOfThisRoot runs aw id
// endorse itself, from a root's identity home, against a service that has an
// earlier endorsement of this root that aw cannot continue.
func TestTheEndorseCommandStopsAtAQuarantinedEndorsementOfThisRoot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	service := newReceiptService(t)
	_, humanKey, _ := ed25519.GenerateKey(nil)
	profilePath := filepath.Join(root, "protected-profile.json")
	if err := os.WriteFile(profilePath, endorseTestProfileJSON(humanKey, service.server.URL, "https://human.customer.example"), 0o600); err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "root", ".aw")
	public, key, _ := ed25519.GenerateKey(nil)
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(identityHome, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID: awid.ComputeDIDKey(public), StableID: awid.ComputeStableID(public), Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal, CreatedAt: "2026-11-13T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	profile, err := handoff.ParseProfile(endorseTestProfileJSON(humanKey, service.server.URL, "https://human.customer.example"))
	if err != nil {
		t.Fatal(err)
	}
	binding, err := endorsementBinding(profile, admitTestHuman)
	if err != nil {
		t.Fatal(err)
	}
	request := endorseTestRequest()
	request.RootID, request.RootKey = awid.ComputeStableID(public), awid.ComputeDIDKey(public)
	old, err := endorsementIntent(profile, binding, request)
	if err != nil {
		t.Fatal(err)
	}
	delete(old, "approval_format")
	old["operation_id"] = endorseTestOperation
	body, _ := json.Marshal(old)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: endorseTestOperation,
		RequestOrigin: service.server.URL, HumanOrigin: "https://human.customer.example", Body: body}); err != nil {
		t.Fatal(err)
	}
	service.receipts[endorseTestOperation] = `{"state":"unknown","code":"external_effect_unresolved"}`
	endorse := func(extra ...string) (string, error) {
		args := append([]string{"--identity-home", identityHome, "id", "endorse", "--protected-profile", profilePath, "--human", admitTestHuman,
			"--team", "engineering:customer.example", "--team", "zeta:customer.example", "--deployment-label", "lab", "--no-browser", "--no-wait", "--json"}, extra...)
		run := exec.CommandContext(ctx, bin, args...)
		run.Env = append(testCommandEnv(home), "HOME="+home)
		run.Dir = root
		out, err := run.CombinedOutput()
		return string(out), err
	}
	out, err := endorse()
	if err == nil || !strings.Contains(out, "operation_reconciliation_required") || service.reads != 1 || service.others != 0 {
		t.Fatalf("err %v reads %d others %d:\n%s", err, service.reads, service.others, out)
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(endorseTestOperation); saved == nil || saved.Quarantine == nil {
		t.Fatal("the earlier endorsement was not quarantined")
	}
	// A new operation id alone is not the explicit choice.
	if out, err := endorse("--operation-id", "99999999-9999-4999-8999-999999999999"); err == nil || service.others != 0 {
		t.Fatalf("a new operation id bypassed the guard: %v others %d:\n%s", err, service.others, out)
	}
	// --replace names it: a separately approved endorsement is asked for.
	_, _ = endorse("--replace", endorseTestOperation)
	if service.others != 1 {
		t.Fatalf("replace sent %d new requests", service.others)
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(endorseTestOperation); saved == nil || !bytes.Equal(saved.Body, body) {
		t.Fatal("the replaced endorsement's record changed")
	}
}
