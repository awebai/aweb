package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
)

const ownerRemoveTestOperation = "77777777-7777-4777-8777-77777777abcd"

// ownerRemoveService stands in for the protected service's owner-approved
// removal: it freezes the covering-v2 revoke request of what was sent, with
// the requester's key and the target's kind, and answers the receipt the
// owner's approval left. It never executes anything for aw.
type ownerRemoveService struct {
	mu       sync.Mutex
	server   *httptest.Server
	revoke   *removeService
	kind     any
	tamper   string
	receipt  string // committed, pending, refused or unavailable
	expired  bool
	loseNext bool // the next prepare reaches the service but its answer is lost

	prepareBodies [][]byte
	receiptReads  int
	executes      int
}

func newOwnerRemoveService(t *testing.T, signKey ed25519.PrivateKey, requesterKey string) *ownerRemoveService {
	s := &ownerRemoveService{revoke: &removeService{signKey: signKey, requesterKey: requesterKey}, kind: "agent", receipt: "committed"}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/protected-operations":
			body, _ := io.ReadAll(r.Body)
			s.prepareBodies = append(s.prepareBodies, body)
			s.revoke.sent = nil
			_ = json.Unmarshal(body, &s.revoke.sent)
			_, _ = w.Write(s.prepared(t))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/protected-operations/"):
			s.receiptReads++
			s.answerReceipt(t, w)
		case strings.HasSuffix(r.URL.Path, "/execute"):
			s.executes++
			w.WriteHeader(http.StatusConflict)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *ownerRemoveService) prepared(t *testing.T) []byte {
	var answer map[string]any
	_ = json.Unmarshal(s.revoke.prepared(t), &answer)
	payload := answer["payload"].(map[string]any)
	request := payload["request"].(map[string]any)
	request["target_kind"] = s.kind
	digest, _ := handoff.CoveredRequestDigest(decodeForDigest(payload))
	answer["digest"] = digest
	switch {
	case s.expired:
		answer["expires_at"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	case s.receipt == "unavailable":
		// aw reads an unavailable receipt until the operation expires.
		answer["expires_at"] = time.Now().Add(200 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	}
	raw, _ := json.Marshal(answer)
	return raw
}

func (s *ownerRemoveService) answerReceipt(t *testing.T, w http.ResponseWriter) {
	switch s.receipt {
	case "pending":
		_, _ = fmt.Fprintf(w, `{"state":"pending","reason":"awaiting_approval","expires_at":%q}`, time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))
	case "refused":
		_, _ = w.Write([]byte(`{"state":"refused","code":"live_approval_required"}`))
	case "unavailable":
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"detail":"unavailable"}`))
	default:
		_, _ = w.Write(s.revoke.committed(t))
	}
}

// options sends as the requester, and loses the answer of a prepare the
// service received when loseNext is set.
func (s *ownerRemoveService) options() handoff.GovernanceOptions {
	return handoff.GovernanceOptions{
		Request: s.server.URL, Human: s.server.URL, Notify: io.Discard, PollInterval: 10 * time.Millisecond, RetryWithin: 50 * time.Millisecond,
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			resp, err := http.DefaultClient.Do(req)
			s.mu.Lock()
			lose := s.loseNext && method == http.MethodPost
			if lose {
				s.loseNext = false
			}
			s.mu.Unlock()
			if lose && err == nil {
				resp.Body.Close()
				return nil, errors.New("connection reset")
			}
			return resp, err
		},
		Save: func(operationID string, body []byte) error {
			return awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{
				OperationID: operationID, RequestOrigin: s.server.URL, HumanOrigin: s.server.URL, Body: body,
			})
		},
	}
}

// listing is a fixed active listing of the team, counting its reads.
type listing struct {
	rows  []awid.RegistryCertificate
	err   error
	reads int
}

func (l *listing) list(_ context.Context, _ string) ([]awid.RegistryCertificate, error) {
	l.reads++
	return l.rows, l.err
}

func rowOf(cert *awid.TeamCertificate) awid.RegistryCertificate {
	return awid.RegistryCertificate{CertificateID: cert.CertificateID, TeamID: cert.Team, MemberDIDKey: cert.MemberDIDKey,
		MemberDIDAW: cert.MemberDIDAW, MemberAddress: cert.MemberAddress, Alias: cert.Alias, IdentityScope: cert.IdentityScope}
}

func ownerRemoveTestSetup(t *testing.T) (ed25519.PrivateKey, *handoff.Profile, *ownerRemoveService) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	_, teamKey, _ := ed25519.GenerateKey(nil)
	service := newOwnerRemoveService(t, teamKey, removeTestRootKey)
	profile := admitTestProfile(t, teamKey, admitTestHuman)
	profile.RequestOrigin, profile.HumanOrigin = service.server.URL, service.server.URL
	return teamKey, profile, service
}

func ownerRemoveByFile(certificate string) ownerRemovalRequest {
	return ownerRemovalRequest{OperationID: ownerRemoveTestOperation, Certificate: certificate, RequesterKey: removeTestRootKey}
}

func ownerRemoveBySelector(cert *awid.TeamCertificate, list *listing) ownerRemovalRequest {
	return ownerRemovalRequest{Team: cert.Team, CertificateID: cert.CertificateID, RequesterKey: removeTestRootKey, List: list.list}
}

func savedOwnerRemoval(t *testing.T, operationID string) *awconfig.PendingGovernanceOperation {
	t.Helper()
	saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func TestAnOwnerRemovalAsksForTheClosedSubjectAndWaitsForTheOwnersApproval(t *testing.T) {
	for _, memberID := range []string{"", "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		certificate := removeTestCertificate(t, teamKey, memberID)
		cert, _ := awid.LoadTeamCertificate(certificate)
		report, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveByFile(certificate))
		if err != nil {
			t.Fatalf("member %q: %v", memberID, err)
		}
		sent := service.revoke.sent
		subject := sent["subject"].(map[string]any)
		expected := subject["expected_membership"].(map[string]any)
		wantMember := any(admitTestChildKey)
		if memberID != "" {
			wantMember = memberID
		}
		if sent["operation"] != "team.agent.remove" || sent["variant"] != "owner_approved" || sent["audience"] != profile.RegistryOrigin ||
			len(subject) != 4 || subject["team_id"] != cert.Team || subject["member_id"] != wantMember || subject["certificate_id"] != cert.CertificateID {
			t.Fatalf("sent %v", sent)
		}
		if _, present := subject["root_id_or_self"]; present {
			t.Fatal("the owner's removal names a root")
		}
		if _, present := expected["member_address"]; !present || len(expected) != 5 || expected["alias"] != "worker" {
			t.Fatalf("expected membership %v", expected)
		}
		if service.executes != 0 || service.receiptReads == 0 {
			t.Fatalf("%d executes, %d receipt reads: an owner's removal is approved, never executed by aw", service.executes, service.receiptReads)
		}
		if report["state"] != "committed" || report["operation_id"] != ownerRemoveTestOperation || report["team_id"] != cert.Team ||
			report["certificate_id"] != cert.CertificateID || report["alias"] != "worker" || report["target_kind"] != "agent" {
			t.Fatalf("report %v", report)
		}
		if saved := savedOwnerRemoval(t, ownerRemoveTestOperation); saved != nil {
			t.Fatal("a verified removal stays saved")
		}
	}
}

func TestAnUnverifiedKindIsReportedAsTheServiceFroze(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	service.kind = "kind not verified"
	report, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveByFile(removeTestCertificate(t, teamKey, "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f")))
	if err != nil || report["target_kind"] != "kind not verified" {
		t.Fatalf("report %v, %v", report, err)
	}
}

func TestAFrozenOwnerRemovalThatIsNotExactlyTheRequestIsNeverShown(t *testing.T) {
	for _, tamper := range []string{"another-certificate", "another-registry", "another-controller", "another-requester-key"} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		service.revoke.tamper = tamper
		_, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveByFile(removeTestCertificate(t, teamKey, "")))
		if errorCodeOf(err) != "operation_mismatch" || service.receiptReads != 0 {
			t.Errorf("%s: err %v after %d receipt reads", tamper, err, service.receiptReads)
		}
	}
	for _, kind := range []any{"human", "service", nil} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		service.kind = kind
		_, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveByFile(removeTestCertificate(t, teamKey, "")))
		if err == nil || service.receiptReads != 0 {
			t.Errorf("kind %v: err %v after %d receipt reads", kind, err, service.receiptReads)
		}
	}
}

func TestAnInvalidCommittedRevocationKeepsTheSameRequestUntilItVerifies(t *testing.T) {
	for _, tamper := range []string{"signed-another-request", "signed-by-another-key"} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		request := ownerRemoveByFile(removeTestCertificate(t, teamKey, ""))
		service.revoke.tamper = tamper
		report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request)
		if errorCodeOf(err) != "signed_request_invalid" || report != nil {
			t.Fatalf("%s: report %v, err %v", tamper, report, err)
		}
		if savedOwnerRemoval(t, ownerRemoveTestOperation) == nil {
			t.Fatalf("%s: an unverified result forgot the request", tamper)
		}
		service.revoke.tamper = ""
		if report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); err != nil || report["state"] != "committed" {
			t.Fatalf("%s: resume %v, %v", tamper, report, err)
		}
		if len(service.prepareBodies) != 2 || !bytes.Equal(service.prepareBodies[0], service.prepareBodies[1]) {
			t.Fatalf("%s: the resume did not send the saved bytes", tamper)
		}
	}
}

func TestAPendingOwnerRemovalClaimsNothingAndContinuesTheSameRequest(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	request := ownerRemoveByFile(removeTestCertificate(t, teamKey, ""))
	request.OperationID = ""
	opts := service.options()
	opts.NoWait = true
	service.receipt = "pending"
	report, err := removeMemberAsOwner(context.Background(), opts, profile, request)
	if err != nil || report["state"] != "pending" || report["page"] == nil || report["target_kind"] != nil {
		t.Fatalf("pending report %v, %v", report, err)
	}
	first := report["operation_id"].(string)
	if savedOwnerRemoval(t, first) == nil {
		t.Fatal("a pending removal was forgotten")
	}
	service.receipt = "committed"
	report, err = removeMemberAsOwner(context.Background(), service.options(), profile, request)
	if err != nil || report["state"] != "committed" || report["operation_id"] != first {
		t.Fatalf("continued %v, %v", report, err)
	}
	if len(service.prepareBodies) != 2 || !bytes.Equal(service.prepareBodies[0], service.prepareBodies[1]) {
		t.Fatal("the continuation did not send the saved bytes")
	}
}

func TestOnlyAnOwnedRefusalForgetsTheRequest(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	request := ownerRemoveByFile(removeTestCertificate(t, teamKey, ""))
	service.receipt = "unavailable"
	if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); err == nil {
		t.Fatal("an unreadable receipt was taken")
	}
	if savedOwnerRemoval(t, ownerRemoveTestOperation) == nil {
		t.Fatal("an unreadable receipt forgot the request")
	}
	service.receipt = "refused"
	if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); errorCodeOf(err) != "live_approval_required" {
		t.Fatalf("refusal: %v", err)
	}
	if savedOwnerRemoval(t, ownerRemoveTestOperation) != nil {
		t.Fatal("a refused removal stays saved")
	}
}

func TestALostAnswerAfterTheRevocationRecoversByReceiptWithoutTheListing(t *testing.T) {
	for _, expired := range []bool{false, true} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
		list := &listing{rows: []awid.RegistryCertificate{rowOf(cert)}}
		request := ownerRemoveBySelector(cert, list)
		service.receipt = "unavailable" // the owner approved and the registry revoked; aw never heard
		if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); err == nil {
			t.Fatal("an unreadable receipt was taken")
		}
		// The certificate is revoked now, and the listing no longer serves it.
		list.rows, list.err, list.reads = nil, errors.New("forbidden"), 0
		service.receipt, service.expired = "committed", expired
		report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request)
		if err != nil || report["state"] != "committed" || report["certificate_id"] != cert.CertificateID || report["alias"] != "worker" {
			t.Fatalf("expired %v: recovery %v, %v", expired, report, err)
		}
		if list.reads != 0 || !bytes.Equal(service.prepareBodies[0], service.prepareBodies[len(service.prepareBodies)-1]) {
			t.Fatalf("expired %v: recovery read the listing %d times or sent other bytes", expired, list.reads)
		}
	}
}

func TestACommittedReceiptAfterALostPrepareIsNotTakenUnverified(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	request := ownerRemoveByFile(removeTestCertificate(t, teamKey, ""))
	service.loseNext = true
	if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); err == nil {
		t.Fatal("a result whose prepared operation was never verified was taken")
	}
	if savedOwnerRemoval(t, ownerRemoveTestOperation) == nil {
		t.Fatal("an unverified result forgot the request")
	}
	if report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); err != nil || report["state"] != "committed" {
		t.Fatalf("resume %v, %v", report, err)
	}
}

func TestAChangedTargetUnderASavedOwnerRemovalConflicts(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	service.receipt = "unavailable"
	first := removeTestCertificate(t, teamKey, "")
	if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveByFile(first)); err == nil {
		t.Fatal("an unreadable receipt was taken")
	}
	other, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	list := &listing{rows: []awid.RegistryCertificate{rowOf(other)}}
	for name, request := range map[string]ownerRemovalRequest{
		"file":     ownerRemoveByFile(removeTestCertificate(t, teamKey, "")),
		"selector": func() ownerRemovalRequest { r := ownerRemoveBySelector(other, list); r.OperationID = ownerRemoveTestOperation; return r }(),
	} {
		prepares := len(service.prepareBodies)
		if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); errorCodeOf(err) != "operation_conflict" || len(service.prepareBodies) != prepares {
			t.Errorf("%s: %v after %d prepares", name, err, len(service.prepareBodies)-prepares)
		}
	}
	if list.reads != 0 {
		t.Fatal("a saved operation's id read the listing")
	}
}

func TestAFreshSelectionRefusesAnythingButOneActiveRowBeforePreparing(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	revoked := rowOf(cert)
	revoked.RevokedAt = "2026-11-13T10:00:00Z"
	malformed := rowOf(cert)
	malformed.IdentityScope = "planetary"
	otherTeam := rowOf(cert)
	otherTeam.TeamID = "other:customer.example"
	for name, rows := range map[string][]awid.RegistryCertificate{
		"missing": nil, "revoked": {revoked}, "malformed": {malformed}, "duplicated": {rowOf(cert), rowOf(cert)}, "another team": {otherTeam},
	} {
		_, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveBySelector(cert, &listing{rows: rows}))
		if err == nil || len(service.prepareBodies) != 0 {
			t.Errorf("%s: %v after %d prepares", name, err, len(service.prepareBodies))
		}
	}
}

func TestAListingThatFailsIsNeverReportedAsAMissingCertificate(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	failure := errors.New("registry answered 403")
	_, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveBySelector(cert, &listing{err: failure}))
	if !errors.Is(err, failure) || errorCodeOf(err) == "certificate_not_found" || len(service.prepareBodies) != 0 {
		t.Fatalf("err %v (code %q) after %d prepares", err, errorCodeOf(err), len(service.prepareBodies))
	}
}

func TestAFreshSelectionRemovesTheListedMembership(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, "did:aw:29L9sa47RQVPv4wyy2Bp9jqCJh2f"))
	report, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemoveBySelector(cert, &listing{rows: []awid.RegistryCertificate{rowOf(cert)}}))
	if err != nil || report["state"] != "committed" || report["certificate_id"] != cert.CertificateID {
		t.Fatalf("report %v, %v", report, err)
	}
	subject := service.revoke.sent["subject"].(map[string]any)
	if subject["member_id"] != cert.MemberDIDAW || subject["expected_membership"].(map[string]any)["member_did_aw"] != cert.MemberDIDAW {
		t.Fatalf("subject %v", subject)
	}
}
