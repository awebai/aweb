package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

const (
	admitTestOperation = "55555555-5555-4555-8555-55555555abcd"
	admitTestHuman     = "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w"
	admitTestDigest    = "sha256:abababababababababababababababababababababababababababababababab"
)

// admitTestProfile is a profile binding engineering:customer.example's
// controller key teamKey once per human in humans.
func admitTestProfile(t *testing.T, teamKey ed25519.PrivateKey, humans ...string) *handoff.Profile {
	t.Helper()
	profile, err := handoff.ParseProfile(admitTestProfileJSON(teamKey, humans...))
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// admitTestProfileJSON is admitTestProfile's provisioned file.
func admitTestProfileJSON(teamKey ed25519.PrivateKey, humans ...string) []byte {
	var bindings []any
	for _, human := range humans {
		bindings = append(bindings, map[string]any{
			"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "customer-signer",
				"authority": map[string]any{"kind": "team_controller", "id": "engineering:customer.example", "domain": "customer.example"},
				"human":     map[string]any{"id": human, "domain": "customer.example"}, "generation": 1},
			"authority_key_did": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)),
			"policy":            map[string]any{"ref": "aweb.human-assurance/1", "version": 1},
		})
	}
	raw, _ := json.Marshal(map[string]any{
		"v": 1, "service_id": "customer-signer", "request_origin": "https://signer.customer.example",
		"human_origin": "https://human.customer.example", "rp_id": "human.customer.example",
		"registry_origin":       "https://registry.customer.example",
		"namespace_authorities": []any{map[string]any{"domain": "customer.example", "controller_did": awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))}},
		"bindings":              bindings,
	})
	return raw
}

// admitService stands in for the protected service's bounded admission: it
// freezes the unsigned certificate of what was sent and signs it with
// signKey on execute. sign changes what it signs (see the cases).
type admitService struct {
	serviceOwned bool
	mu           sync.Mutex
	server       *httptest.Server
	signKey      ed25519.PrivateKey
	tamper       string
	sent         map[string]any
	artifact     map[string]any
	prepares     int
	executes     int
	// expired answers prepare with an operation already past its expiry,
	// and receipt (when set) is what a receipt read answers.
	expired bool
	receipt string
	reads   int
}

func newAdmitService(t *testing.T, signKey ed25519.PrivateKey) *admitService {
	s := &admitService{signKey: signKey}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/protected-operations":
			s.prepares++
			body, _ := io.ReadAll(r.Body)
			s.sent = nil
			_ = json.Unmarshal(body, &s.sent)
			_, _ = w.Write(s.prepared())
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/protected-operations/") && s.receipt != "":
			s.reads++
			_, _ = w.Write([]byte(s.receipt))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/execute"):
			s.executes++
			if s.tamper == "limit" {
				_, _ = w.Write([]byte(`{"state":"refused","code":"admission_limit_reached"}`))
				return
			}
			_, _ = w.Write(s.committed())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *admitService) prepared() []byte {
	subject := s.sent["subject"].(map[string]any)
	if s.artifact == nil {
		s.artifact = map[string]any{"version": 1, "certificate_id": "66666666-6666-4666-8666-666666666666",
			"team_id": subject["team_id"], "team_did_key": awid.ComputeDIDKey(s.signKey.Public().(ed25519.PublicKey)),
			"member_did_key": subject["child_key"], "alias": subject["member_alias"], "identity_scope": "local",
			"issued_at": "2026-11-13T10:00:00Z"}
		if subject["child_id"] != nil {
			s.artifact["member_did_aw"] = subject["child_id"]
			s.artifact["identity_scope"] = "global"
		}
	}
	if s.tamper == "artifact-key" {
		other, _, _ := ed25519.GenerateKey(nil)
		s.artifact["team_did_key"] = awid.ComputeDIDKey(other)
	}
	request := map[string]any{}
	for k, v := range s.sent {
		request[k] = v
	}
	request["requester"], request["policy_ref"], request["policy_version"] = "did:aw:root", "aweb.human-assurance/1", 1
	request["request_id"], request["admission_policy_version"] = s.sent["operation_id"], subject["expected_policy_version"]
	request["artifact"] = s.artifact
	payload := map[string]any{"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}, "request": request}
	digest, _ := handoff.CoveredRequestDigest(decodeForDigest(payload))
	raw, _ := json.Marshal(map[string]any{"operation_id": s.sent["operation_id"], "handoff_id": "h1", "digest": digest,
		"payload": payload, "expires_at": s.expiresAt().UTC().Format(time.RFC3339Nano)})
	return raw
}

func (s *admitService) expiresAt() time.Time {
	if s.expired {
		return time.Now().Add(-time.Minute)
	}
	return time.Now().Add(time.Minute)
}

func decodeForDigest(value map[string]any) map[string]any {
	raw, _ := json.Marshal(value)
	decoded, _ := handoff.DecodeObject(raw)
	return decoded
}

func (s *admitService) committed() []byte {
	signed := map[string]any{}
	for k, v := range s.artifact {
		signed[k] = v
	}
	if s.tamper == "certificate" {
		signed["certificate_id"] = "77777777-7777-4777-8777-777777777777"
	}
	signing, _ := awid.StrictCanonicalJSON(signed)
	key := s.signKey
	if s.tamper == "key" {
		_, key, _ = ed25519.GenerateKey(nil)
	}
	signature := ed25519.Sign(key, signing)
	var result any = map[string]any{"signing": base64.StdEncoding.EncodeToString(signing), "signature": base64.StdEncoding.EncodeToString(signature)}
	if s.serviceOwned {
		result = appliedTestResult(s.sent["operation_id"].(string), signing, signature)
	}
	raw, _ := json.Marshal(map[string]any{"state": "committed", "result": result})
	return raw
}

func (s *admitService) options() handoff.GovernanceOptions {
	return handoff.GovernanceOptions{
		Request: s.server.URL, Human: s.server.URL, Notify: io.Discard, PollInterval: 10 * time.Millisecond,
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			return http.DefaultClient.Do(req)
		},
	}
}

// admitTestChildKey is the admitted member's key.
var admitTestChildKey = func() string {
	public, _, _ := ed25519.GenerateKey(nil)
	return awid.ComputeDIDKey(public)
}()

func admitTestRequest(t *testing.T) admissionRequest {
	return admissionRequest{
		OperationID: admitTestOperation, Team: "engineering:customer.example", RootID: "did:aw:root", RootKey: "did:key:zroot",
		ChildKey: admitTestChildKey, Alias: "worker",
		PolicyVersion: 3, PolicyDigest: admitTestDigest, CertificateOut: filepath.Join(t.TempDir(), "team-cert.json"),
	}
}

func admitTestSetup(t *testing.T) (ed25519.PrivateKey, *handoff.Profile, *admitService) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	_, teamKey, _ := ed25519.GenerateKey(nil)
	return teamKey, admitTestProfile(t, teamKey, admitTestHuman), newAdmitService(t, teamKey)
}

func TestAnAdmissionWritesTheTeamsSignedCertificateForExactlyThatMember(t *testing.T) {
	for _, childID := range []string{"", "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"} {
		teamKey, profile, service := admitTestSetup(t)
		request := admitTestRequest(t)
		request.ChildID = childID
		report, err := admitMember(context.Background(), service.options(), profile, request)
		if err != nil {
			t.Fatalf("child %q: %v", childID, err)
		}
		if report["operation_id"] != admitTestOperation || report["state"] != "committed" || report["certificate_out"] != request.CertificateOut {
			t.Fatalf("report %v", report)
		}
		cert, err := awid.LoadTeamCertificate(request.CertificateOut)
		if err != nil {
			t.Fatal(err)
		}
		if err := awid.CheckDecodedTeamCertificate(cert, awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))); err != nil {
			t.Fatal(err)
		}
		if cert.Team != request.Team || cert.MemberDIDKey != request.ChildKey || cert.MemberDIDAW != childID || cert.Alias != "worker" {
			t.Fatalf("certificate %+v", cert)
		}
		if saved, _ := awconfig.LoadPendingGovernanceOperation(admitTestOperation); saved != nil || service.executes != 1 {
			t.Fatalf("saved %v after %d executes", saved, service.executes)
		}
	}
}

func TestTheSameOperationIDWithTheSameInputsReturnsTheOriginalCertificate(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	if _, err := admitMember(context.Background(), service.options(), profile, request); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(request.CertificateOut)
	if _, err := admitMember(context.Background(), service.options(), profile, request); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(request.CertificateOut)
	if !bytes.Equal(first, again) {
		t.Fatal("the certificate changed")
	}
}

func TestAChangedInputUnderASavedOperationIDIsAConflictAndSendsNothing(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	body := admissionBody(profile, mustAdmissionBinding(t, profile, request.Team), request)
	raw, _ := json.Marshal(body)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: admitTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*admissionRequest){
		"alias":          func(r *admissionRequest) { r.Alias = "other" },
		"policy digest":  func(r *admissionRequest) { r.PolicyDigest = "sha256:" + strings.Repeat("cd", 32) },
		"policy version": func(r *admissionRequest) { r.PolicyVersion = 4 },
		"member":         func(r *admissionRequest) { r.ChildID = "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f" },
	} {
		changed := request
		change(&changed)
		if _, err := admitMember(context.Background(), service.options(), profile, changed); errorCodeOf(err) != "operation_conflict" {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if service.prepares != 0 {
		t.Fatalf("%d prepares were sent", service.prepares)
	}
	saved, _ := awconfig.LoadPendingGovernanceOperation(admitTestOperation)
	if saved == nil || !bytes.Equal(saved.Body, raw) {
		t.Fatal("the saved request changed")
	}
}

func TestACertificateNotSignedByThePinnedKeyOrNotTheFrozenOneIsNeverWritten(t *testing.T) {
	for _, tamper := range []string{"key", "certificate"} {
		_, profile, service := admitTestSetup(t)
		service.tamper = tamper
		request := admitTestRequest(t)
		_, err := admitMember(context.Background(), service.options(), profile, request)
		if errorCodeOf(err) != "signed_certificate_invalid" {
			t.Errorf("%s: err %v", tamper, err)
		}
		if _, statErr := os.Stat(request.CertificateOut); !os.IsNotExist(statErr) {
			t.Errorf("%s: a certificate was written", tamper)
		}
		if saved, _ := awconfig.LoadPendingGovernanceOperation(admitTestOperation); saved == nil {
			t.Errorf("%s: the saved request was forgotten", tamper)
		}
	}
}

func TestAnotherFileAtTheCertificatePathIsNeverReplaced(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	if err := os.WriteFile(request.CertificateOut, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admitMember(context.Background(), service.options(), profile, request); errorCodeOf(err) != "certificate_out_exists" {
		t.Fatalf("err %v", err)
	}
	if data, _ := os.ReadFile(request.CertificateOut); string(data) != "{}" {
		t.Fatal("the file was replaced")
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(admitTestOperation); saved == nil {
		t.Fatal("the saved request was forgotten before the certificate was written")
	}
}

func mustAdmissionBinding(t *testing.T, profile *handoff.Profile, team string) *handoff.ProfileBinding {
	t.Helper()
	binding, err := admissionBinding(profile, team)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func TestTheAdmissionScopeIsTheTeamsOneControllerBinding(t *testing.T) {
	_, teamKey, _ := ed25519.GenerateKey(nil)
	if _, err := admissionBinding(admitTestProfile(t, teamKey, admitTestHuman), "sales:customer.example"); errorCodeOf(err) != "profile_scope_refused" {
		t.Errorf("unbound team: %v", err)
	}
	two := admitTestProfile(t, teamKey, admitTestHuman, "did:aw:27zc4QzaQx7zjzNGJ4SUYdqJnqFL")
	if _, err := admissionBinding(two, "engineering:customer.example"); errorCodeOf(err) != "profile_scope_ambiguous" {
		t.Errorf("two bindings: %v", err)
	}
}

func TestAnOperationIDMustBeALowercaseUUID(t *testing.T) {
	for _, id := range []string{"", "not-a-uuid", strings.ToUpper(admitTestOperation)} {
		if err := validOperationID(id); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
	if err := validOperationID(admitTestOperation); err != nil {
		t.Fatal(err)
	}
}

// committedResult is the result a service signs for artifact with key.
func committedResult(t *testing.T, key ed25519.PrivateKey, artifact map[string]any) []byte {
	t.Helper()
	signing, err := awid.StrictCanonicalJSON(artifact)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"signing":   base64.StdEncoding.EncodeToString(signing),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, signing)),
	})
	return raw
}

// frozenAs is a prepared operation that froze artifact.
func frozenAs(artifact map[string]any) *handoff.Prepared {
	raw, _ := json.Marshal(map[string]any{"request": map[string]any{"artifact": artifact}})
	return &handoff.Prepared{Payload: raw}
}

func TestACertificateWithoutItsVerifiedPreparedOperationIsNeverTaken(t *testing.T) {
	_, teamKey, _ := ed25519.GenerateKey(nil)
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	profile := admitTestProfile(t, teamKey, admitTestHuman)
	request := admitTestRequest(t)
	body := admissionBody(profile, mustAdmissionBinding(t, profile, request.Team), request)
	artifact := map[string]any{"version": 1, "certificate_id": "66666666-6666-4666-8666-666666666666", "team_id": request.Team,
		"team_did_key": teamDID, "member_did_key": request.ChildKey, "alias": request.Alias, "identity_scope": "local",
		"issued_at": "2026-11-13T10:00:00Z"}
	if _, err := admittedCertificate(committedResult(t, teamKey, artifact), nil, body, teamDID); errorCodeOf(err) != "signed_certificate_invalid" {
		t.Fatalf("err %v", err)
	}
}

func TestACertificateMustNameExactlyTheRequestedMemberEvenAsFrozen(t *testing.T) {
	_, teamKey, _ := ed25519.GenerateKey(nil)
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	profile := admitTestProfile(t, teamKey, admitTestHuman)
	request := admitTestRequest(t)
	body := admissionBody(profile, mustAdmissionBinding(t, profile, request.Team), request)
	artifact := func() map[string]any {
		return map[string]any{"version": 1, "certificate_id": "66666666-6666-4666-8666-666666666666", "team_id": request.Team,
			"team_did_key": teamDID, "member_did_key": request.ChildKey, "alias": request.Alias, "identity_scope": "local",
			"issued_at": "2026-11-13T10:00:00Z"}
	}
	if _, err := admittedCertificate(committedResult(t, teamKey, artifact()), frozenAs(artifact()), body, teamDID); err != nil {
		t.Fatalf("the requested member: %v", err)
	}
	for name, change := range map[string]func(map[string]any){
		"registered member": func(a map[string]any) {
			a["member_did_aw"] = "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"
			a["identity_scope"] = "global"
		},
		"other alias":  func(a map[string]any) { a["alias"] = "other" },
		"other team":   func(a map[string]any) { a["team_id"] = "sales:customer.example" },
		"global scope": func(a map[string]any) { a["identity_scope"] = "global" },
		"address":      func(a map[string]any) { a["member_address"] = "customer.example/worker" },
	} {
		changed := artifact()
		change(changed)
		if _, err := admittedCertificate(committedResult(t, teamKey, changed), frozenAs(changed), body, teamDID); errorCodeOf(err) != "signed_certificate_invalid" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestARegisteredMembersCertificateMustNameItsIDAndGlobalScopeEvenAsFrozen(t *testing.T) {
	_, teamKey, _ := ed25519.GenerateKey(nil)
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	profile := admitTestProfile(t, teamKey, admitTestHuman)
	request := admitTestRequest(t)
	request.ChildID = "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"
	body := admissionBody(profile, mustAdmissionBinding(t, profile, request.Team), request)
	artifact := func() map[string]any {
		return map[string]any{"version": 1, "certificate_id": "66666666-6666-4666-8666-666666666666", "team_id": request.Team,
			"team_did_key": teamDID, "member_did_key": request.ChildKey, "member_did_aw": request.ChildID, "alias": request.Alias,
			"identity_scope": "global", "issued_at": "2026-11-13T10:00:00Z"}
	}
	if _, err := admittedCertificate(committedResult(t, teamKey, artifact()), frozenAs(artifact()), body, teamDID); err != nil {
		t.Fatalf("the requested member: %v", err)
	}
	for name, change := range map[string]func(map[string]any){
		"another registered member": func(a map[string]any) { a["member_did_aw"] = "did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2" },
		"local scope":               func(a map[string]any) { a["identity_scope"] = "local" },
	} {
		changed := artifact()
		change(changed)
		if _, err := admittedCertificate(committedResult(t, teamKey, changed), frozenAs(changed), body, teamDID); errorCodeOf(err) != "signed_certificate_invalid" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestAnAdmissionWhoseFrozenCertificateNamesAnotherTeamKeyIsNeverExecuted(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	service.tamper = "artifact-key"
	if _, err := admitMember(context.Background(), service.options(), profile, admitTestRequest(t)); errorCodeOf(err) != "operation_mismatch" {
		t.Fatalf("err %v", err)
	}
	if service.executes != 0 {
		t.Fatalf("%d executes were sent", service.executes)
	}
}

func TestAnExistingCertificateCountsOnlyIfItIsTheWholeVerifiedOne(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	if _, err := admitMember(context.Background(), service.options(), profile, request); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(request.CertificateOut)
	var altered map[string]any
	_ = json.Unmarshal(original, &altered)
	altered["alias"] = "impostor" // the certificate ID and signature unchanged
	changed, _ := json.MarshalIndent(altered, "", "  ")
	if err := os.WriteFile(request.CertificateOut, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := admitMember(context.Background(), service.options(), profile, request); errorCodeOf(err) != "certificate_out_exists" {
		t.Fatalf("err %v", err)
	}
	if now, _ := os.ReadFile(request.CertificateOut); !bytes.Equal(now, changed) {
		t.Fatal("the altered file was replaced")
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(admitTestOperation); saved == nil {
		t.Fatal("the saved request was forgotten")
	}
}

func TestALinkAtTheCertificatePathIsNeverFollowedOrReplaced(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.Symlink(target, request.CertificateOut); err != nil {
		t.Fatal(err)
	}
	if _, err := admitMember(context.Background(), service.options(), profile, request); errorCodeOf(err) != "certificate_out_exists" {
		t.Fatalf("err %v", err)
	}
	if link, err := os.Readlink(request.CertificateOut); err != nil || link != target {
		t.Fatalf("the link was replaced: %q %v", link, err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("the link's target was written")
	}
}

func TestTheCertificateIsPublishedWithoutReplacingAFileCreatedMeanwhile(t *testing.T) {
	_, teamKey, _ := ed25519.GenerateKey(nil)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "engineering:customer.example", MemberDIDKey: admitTestChildKey, Alias: "worker", IdentityScope: "local"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "team-cert.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishCertificate(path, cert); !errors.Is(err, os.ErrExist) {
		t.Fatalf("err %v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "{}" {
		t.Fatal("the file created meanwhile was replaced")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}
}

func TestALinkToTheSameCertificateIsStillNotTheCertificateFile(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	if _, err := admitMember(context.Background(), service.options(), profile, request); err != nil {
		t.Fatal(err)
	}
	real := request.CertificateOut + ".real"
	if err := os.Rename(request.CertificateOut, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, request.CertificateOut); err != nil {
		t.Fatal(err)
	}
	if _, err := admitMember(context.Background(), service.options(), profile, request); errorCodeOf(err) != "certificate_out_exists" {
		t.Fatalf("err %v", err)
	}
}

func TestAnAdmissionOverTheLimitSaysHowManyAgentsTheRootHas(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	service.tamper = "limit"
	request := admitTestRequest(t)
	request.Counts = func(context.Context) (*handoff.AdmissionCounts, error) {
		return &handoff.AdmissionCounts{Active: 5, MaxActive: 5, InWindow: 1, MaxPerWindow: 10, WindowSeconds: 3600}, nil
	}
	_, err := admitMember(context.Background(), service.options(), profile, request)
	if errorCodeOf(err) != "admission_limit_reached" {
		t.Fatalf("code %q: %v", errorCodeOf(err), err)
	}
	for _, want := range []string{"5 of 5", request.Team, "aw id team remove-agent", admitTestOperation} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q lacks %q", err.Error(), want)
		}
	}
}

// An operation that expired before it was decided is settled by its receipt:
// the saved request is forgotten, so running the command again starts anew.
func TestAnExpiredSavedAdmissionIsSettledAndTheNextRunStartsANewOperation(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	binding, _ := admissionBinding(profile, request.Team)
	if _, err := operationBytes(profile, request.OperationID, admissionBody(profile, binding, request)); err != nil {
		t.Fatal(err)
	}
	service.expired, service.receipt = true, `{"state":"refused","code":"operation_expired"}`
	_, err := admitMember(context.Background(), service.options(), profile, request)
	if errorCodeOf(err) != "operation_expired" || service.executes != 0 || service.reads != 1 {
		t.Fatalf("code %q, %d executes, %d reads: %v", errorCodeOf(err), service.executes, service.reads, err)
	}
	again := request
	again.OperationID = ""
	next, resumed, err := protectedOperationID("", profile, admissionBody(profile, binding, again))
	if err != nil || resumed || next == request.OperationID {
		t.Fatalf("the next run %q resumed=%v %v", next, resumed, err)
	}
}

// A result that committed before expiry, whose answer was lost, is taken.
func TestACommittedAdmissionWhoseAnswerWasLostIsRecoveredAfterExpiry(t *testing.T) {
	teamKey, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	binding, _ := admissionBinding(profile, request.Team)
	if _, err := operationBytes(profile, request.OperationID, admissionBody(profile, binding, request)); err != nil {
		t.Fatal(err)
	}
	service.expired = true
	service.mu.Lock()
	service.sent = admissionBody(profile, binding, request)
	service.prepared()
	service.mu.Unlock()
	service.receipt = string(service.committed())
	report, err := admitMember(context.Background(), service.options(), profile, request)
	if err != nil || report["state"] != "committed" || service.executes != 0 {
		t.Fatalf("%v %v after %d executes", report, err, service.executes)
	}
	cert, err := awid.LoadTeamCertificate(request.CertificateOut)
	if err != nil || awid.CheckDecodedTeamCertificate(cert, awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))) != nil {
		t.Fatalf("certificate: %v", err)
	}
	if saved, _ := awconfig.LoadPendingGovernanceOperation(request.OperationID); saved != nil {
		t.Fatal("the recovered operation stayed saved")
	}
}

// When the outcome cannot be read, the operation and its id are kept.
func TestAnExpiredAdmissionWhoseReceiptCannotBeReadKeepsItsOperation(t *testing.T) {
	_, profile, service := admitTestSetup(t)
	request := admitTestRequest(t)
	binding, _ := admissionBinding(profile, request.Team)
	if _, err := operationBytes(profile, request.OperationID, admissionBody(profile, binding, request)); err != nil {
		t.Fatal(err)
	}
	service.expired, service.receipt = true, `{"state":`
	if _, err := admitMember(context.Background(), service.options(), profile, request); err == nil {
		t.Fatal("an unreadable outcome reported success")
	}
	again := request
	again.OperationID = ""
	if got, resumed, _ := protectedOperationID("", profile, admissionBody(profile, binding, again)); !resumed || got != request.OperationID {
		t.Fatalf("the uncertain operation was dropped: %q resumed=%v", got, resumed)
	}
}
