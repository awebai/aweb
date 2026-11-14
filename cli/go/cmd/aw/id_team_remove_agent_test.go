package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

const removeTestOperation = "88888888-8888-4888-8888-88888888abcd"

// removeService stands in for the protected service's bounded removal: it
// freezes the covering-v2 revoke request of what was sent and, on execute,
// signs its canonical bytes with signKey. tamper changes what it freezes or
// signs (see the cases).
type removeService struct {
	serviceOwned bool
	mu           sync.Mutex
	server       *httptest.Server
	signKey      ed25519.PrivateKey
	requesterKey string
	tamper       string
	sent         map[string]any
	artifact     map[string]any
	prepares     int
	executes     int
}

func newRemoveService(t *testing.T, signKey ed25519.PrivateKey, requesterKey string) *removeService {
	s := &removeService{signKey: signKey, requesterKey: requesterKey}
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
			_, _ = w.Write(s.prepared(t))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/execute"):
			s.executes++
			_, _ = w.Write(s.committed(t))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *removeService) revokeRequest(t *testing.T, team, certificateID, aud string) map[string]any {
	return s.revokeRequestAt(t, team, certificateID, aud, "2026-11-13T10:00:00Z")
}

func (s *removeService) revokeRequestAt(t *testing.T, team, certificateID, aud, timestamp string) map[string]any {
	t.Helper()
	name, domain, _ := strings.Cut(team, ":")
	body, _ := json.Marshal(map[string]any{"certificate_id": certificateID})
	raw, err := awid.ControllerRequestPayload(aud, "POST", "/v1/namespaces/"+domain+"/teams/"+name+"/certificates/revoke", body,
		timestamp, domain, "revoke_certificate", map[string]any{"team_name": name, "certificate_id": certificateID})
	if err != nil {
		t.Fatal(err)
	}
	request, ok := handoff.DecodeObject(raw)
	if !ok {
		t.Fatal("the revoke request does not decode")
	}
	return request
}

func (s *removeService) prepared(t *testing.T) []byte {
	subject := s.sent["subject"].(map[string]any)
	team, certificateID, aud := subject["team_id"].(string), subject["certificate_id"].(string), s.sent["audience"].(string)
	controller := awid.ComputeDIDKey(s.signKey.Public().(ed25519.PublicKey))
	switch s.tamper {
	case "another-certificate":
		certificateID = "99999999-9999-4999-8999-999999999999"
	case "another-registry":
		aud = "https://other-registry.example"
	case "another-controller":
		other, _, _ := ed25519.GenerateKey(nil)
		controller = awid.ComputeDIDKey(other)
	}
	s.artifact = map[string]any{"controller_did": controller, "request": s.revokeRequest(t, team, certificateID, aud)}
	if s.tamper == "artifact-extra" {
		s.artifact["note"] = "extra"
	}
	request := map[string]any{}
	for k, v := range s.sent {
		request[k] = v
	}
	request["requester"], request["policy_ref"], request["policy_version"] = "did:aw:root", "aweb.human-assurance/1", 1
	request["requester_key"] = s.requesterKey
	if s.tamper == "another-requester-key" {
		other, _, _ := ed25519.GenerateKey(nil)
		request["requester_key"] = awid.ComputeDIDKey(other)
	}
	request["artifact"] = s.artifact
	payload := map[string]any{"policy": map[string]any{"ref": "aweb.human-assurance/1", "version": 1}, "request": request}
	digest, _ := handoff.CoveredRequestDigest(decodeForDigest(payload))
	raw, _ := json.Marshal(map[string]any{"operation_id": s.sent["operation_id"], "handoff_id": "h1", "digest": digest,
		"payload": payload, "expires_at": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)})
	return raw
}

func (s *removeService) committed(t *testing.T) []byte {
	request := s.artifact["request"].(map[string]any)
	if s.tamper == "signed-another-request" {
		subject := s.sent["subject"].(map[string]any)
		request = s.revokeRequest(t, subject["team_id"].(string), "99999999-9999-4999-8999-999999999999", s.sent["audience"].(string))
	}
	signing, _ := awid.StrictCanonicalJSON(request)
	key := s.signKey
	if s.tamper == "signed-by-another-key" {
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

func (s *removeService) options() handoff.GovernanceOptions {
	return (&admitService{server: s.server}).options()
}

// removeTestCertificate is the admitted certificate of a local or, with
// memberID, a registered member, as a file.
func removeTestCertificate(t *testing.T, teamKey ed25519.PrivateKey, memberID string) string {
	t.Helper()
	scope := awid.IdentityModeLocal
	if memberID != "" {
		scope = awid.IdentityModeGlobal
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "engineering:customer.example",
		MemberDIDKey: admitTestChildKey, MemberDIDAW: memberID, Alias: "worker", IdentityScope: scope})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "worker.cert")
	if err := awid.SaveTeamCertificate(path, cert); err != nil {
		t.Fatal(err)
	}
	return path
}

const removeTestRootKey = "did:key:z6MkrootRootRootRootRootRootRootRootRootRoot"

func removeTestSetup(t *testing.T) (ed25519.PrivateKey, *handoff.Profile, *removeService) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	_, teamKey, _ := ed25519.GenerateKey(nil)
	return teamKey, admitTestProfile(t, teamKey, admitTestHuman), newRemoveService(t, teamKey, removeTestRootKey)
}

func removeTestRequest(certificate string) removalRequest {
	return removalRequest{OperationID: removeTestOperation, Certificate: certificate, RootID: "did:aw:root", RootKey: removeTestRootKey}
}

func TestARootRemovesExactlyTheMembershipItsCertificateNames(t *testing.T) {
	for _, memberID := range []string{"", "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"} {
		teamKey, profile, service := removeTestSetup(t)
		certificate := removeTestCertificate(t, teamKey, memberID)
		cert, _ := awid.LoadTeamCertificate(certificate)
		report, err := removeMember(context.Background(), service.options(), profile, removeTestRequest(certificate))
		if err != nil {
			t.Fatalf("member %q: %v", memberID, err)
		}
		if report["operation_id"] != removeTestOperation || report["state"] != "committed" || report["certificate_id"] != cert.CertificateID {
			t.Fatalf("report %v", report)
		}
		subject := service.sent["subject"].(map[string]any)
		expected := subject["expected_membership"].(map[string]any)
		wantMember, wantDIDAW, wantScope := any(admitTestChildKey), any(nil), "local"
		if memberID != "" {
			wantMember, wantDIDAW, wantScope = memberID, memberID, "global"
		}
		if service.sent["operation"] != "team.agent.remove" || service.sent["variant"] != "default" || service.sent["audience"] != profile.RegistryOrigin ||
			subject["team_id"] != "engineering:customer.example" || subject["root_id_or_self"] != "did:aw:root" ||
			subject["member_id"] != wantMember || subject["certificate_id"] != cert.CertificateID || len(subject) != 5 {
			t.Fatalf("sent %v", service.sent)
		}
		if expected["member_did_key"] != admitTestChildKey || expected["member_did_aw"] != wantDIDAW || expected["member_address"] != nil ||
			expected["alias"] != "worker" || expected["identity_scope"] != wantScope || len(expected) != 5 {
			t.Fatalf("expected membership %v", expected)
		}
		if _, present := expected["member_address"]; !present {
			t.Fatal("member_address is omitted, not null")
		}
		if saved, _ := awconfig.LoadPendingGovernanceOperation(removeTestOperation); saved != nil || service.executes != 1 {
			t.Fatalf("saved %v after %d executes", saved, service.executes)
		}
	}
}

func TestTheSameRemovalIDWithTheSameInputsResumesAndAChangedOneConflicts(t *testing.T) {
	teamKey, profile, service := removeTestSetup(t)
	request := removeTestRequest(removeTestCertificate(t, teamKey, ""))
	service.tamper = "signed-by-another-key" // the first run settles nothing
	if _, err := removeMember(context.Background(), service.options(), profile, request); err == nil {
		t.Fatal("an unverifiable result was taken")
	}
	service.tamper = ""
	if report, err := removeMember(context.Background(), service.options(), profile, request); err != nil || report["state"] != "committed" {
		t.Fatalf("resume %v, %v", report, err)
	}
	// Interrupted after saving its body: the id now holds this removal, and a
	// removal of another certificate under it sends nothing.
	prepares := service.prepares
	other := removeTestRequest(removeTestCertificate(t, teamKey, ""))
	if err := savePendingRemoval(t, profile, request); err != nil {
		t.Fatal(err)
	}
	if _, err := removeMember(context.Background(), service.options(), profile, other); errorCodeOf(err) != "operation_conflict" || service.prepares != prepares {
		t.Fatalf("changed inputs: %v after %d prepares", err, service.prepares-prepares)
	}
}

// savePendingRemoval keeps request's body under its operation id, as a run
// interrupted after saving it leaves it.
func savePendingRemoval(t *testing.T, profile *handoff.Profile, request removalRequest) error {
	t.Helper()
	binding := mustAdmissionBinding(t, profile, "engineering:customer.example")
	cert, err := awid.LoadTeamCertificate(request.Certificate)
	if err != nil {
		return err
	}
	_, err = operationBytes(profile, request.OperationID, removalBody(profile, binding, request, cert))
	return err
}

func TestAFrozenRemovalThatIsNotExactlyTheRequestedRevocationIsNeverExecuted(t *testing.T) {
	for _, tamper := range []string{"another-certificate", "another-registry", "artifact-extra", "another-controller", "another-requester-key"} {
		teamKey, profile, service := removeTestSetup(t)
		service.tamper = tamper
		_, err := removeMember(context.Background(), service.options(), profile, removeTestRequest(removeTestCertificate(t, teamKey, "")))
		if errorCodeOf(err) != "operation_mismatch" || service.executes != 0 {
			t.Errorf("%s: err %v after %d executes", tamper, err, service.executes)
		}
	}
}

func TestARemovalResultThatIsNotTheControllersSignatureOfTheFrozenRequestIsNeverTaken(t *testing.T) {
	for _, tamper := range []string{"signed-another-request", "signed-by-another-key"} {
		teamKey, profile, service := removeTestSetup(t)
		service.tamper = tamper
		report, err := removeMember(context.Background(), service.options(), profile, removeTestRequest(removeTestCertificate(t, teamKey, "")))
		if errorCodeOf(err) != "signed_request_invalid" || report != nil {
			t.Errorf("%s: report %v, err %v", tamper, report, err)
		}
	}
}

func TestARemovalNeedsATeamCertificateFile(t *testing.T) {
	_, profile, service := removeTestSetup(t)
	path := filepath.Join(t.TempDir(), "not.cert")
	_ = os.WriteFile(path, []byte("not a certificate\n"), 0o600)
	if _, err := removeMember(context.Background(), service.options(), profile, removeTestRequest(path)); errorCodeOf(err) != "certificate_invalid" || service.prepares != 0 {
		t.Fatalf("err %v after %d prepares", err, service.prepares)
	}
}
