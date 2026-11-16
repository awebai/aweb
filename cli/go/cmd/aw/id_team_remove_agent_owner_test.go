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
	tamper   string // a change to the committed result
	window   [2]time.Time
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
	// The intent: the revocation without its execution-issued timestamp,
	// issued once the owner approves, inside the window fixed now.
	template := s.revoke.artifact
	delete(template["request"].(map[string]any), "timestamp")
	now := time.Now().UTC().Truncate(time.Second)
	s.window = [2]time.Time{now.Add(-time.Hour), now.Add(23 * time.Hour)}
	request["artifact"] = map[string]any{"v": 1, "type": "aweb.protected-artifact-intent", "template": template,
		"delivery":        map[string]any{"audience": request["audience"], "method": "POST", "path": template["request"].(map[string]any)["path"]},
		"issuance_window": map[string]any{"not_before": s.window[0].Format(time.RFC3339), "not_after": s.window[1].Format(time.RFC3339)}}
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

// committed is the receipt of the revocation issued at the owner's approval
// and applied at the registry by the service. tamper varies it.
func (s *ownerRemoveService) committed(t *testing.T) []byte {
	if s.revoke.sent == nil {
		// Nothing was prepared here, so this service has no committed result
		// for the operation read: an earlier request's outcome is unsettled.
		return []byte(`{"state":"unknown","code":"external_effect_unresolved"}`)
	}
	subject := s.revoke.sent["subject"].(map[string]any)
	team, certificateID, audience := subject["team_id"].(string), subject["certificate_id"].(string), s.revoke.sent["audience"].(string)
	issued := s.window[0].Add(2 * time.Hour)
	switch s.tamper {
	case "issued-outside-window":
		issued = s.window[1].Add(time.Hour)
	case "signed-another-request":
		certificateID = "99999999-9999-4999-8999-999999999999"
	}
	request := s.revoke.revokeRequestAt(t, team, certificateID, audience, issued.Format(time.RFC3339))
	signing, _ := awid.StrictCanonicalJSON(request)
	if s.tamper == "noncanonical-signing" {
		signing, _ = json.MarshalIndent(request, "", " ")
	}
	key := s.revoke.signKey
	if s.tamper == "signed-by-another-key" {
		_, key, _ = ed25519.GenerateKey(nil)
	}
	signature := ed25519.Sign(key, signing)
	reference := s.revoke.sent["operation_id"].(string)
	if s.tamper == "another-reference" {
		reference = "66666666-6666-4666-8666-666666666666"
	}
	raw, _ := json.Marshal(map[string]any{"state": "committed", "result": appliedTestResult(reference, signing, signature)})
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
		_, _ = w.Write(s.committed(t))
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
		// A caller's Forget would drop the request on any committed receipt;
		// the removal decides itself when its request is done.
		Forget: awconfig.RemovePendingGovernanceOperation,
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
		if sent["approval_format"] != "intent_v1" {
			t.Fatalf("sent %v: an owner's removal asks in the intent format", sent)
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
	for _, tamper := range []string{"signed-another-request", "signed-by-another-key", "issued-outside-window", "another-reference", "noncanonical-signing"} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		request := ownerRemoveByFile(removeTestCertificate(t, teamKey, ""))
		service.tamper = tamper
		report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request)
		if errorCodeOf(err) != "signed_request_invalid" || report != nil {
			t.Fatalf("%s: report %v, err %v", tamper, report, err)
		}
		if savedOwnerRemoval(t, ownerRemoveTestOperation) == nil {
			t.Fatalf("%s: an unverified result forgot the request", tamper)
		}
		service.tamper = ""
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
		"file": ownerRemoveByFile(removeTestCertificate(t, teamKey, "")),
		"selector": func() ownerRemovalRequest {
			r := ownerRemoveBySelector(other, list)
			r.OperationID = ownerRemoveTestOperation
			return r
		}(),
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
	noAlias, noKey, globalWithoutID := rowOf(cert), rowOf(cert), rowOf(cert)
	noAlias.Alias, noKey.MemberDIDKey, globalWithoutID.IdentityScope = "", "", awid.IdentityModeGlobal
	for name, rows := range map[string][]awid.RegistryCertificate{
		"missing": nil, "revoked": {revoked}, "malformed": {malformed}, "duplicated": {rowOf(cert), rowOf(cert)}, "another team": {otherTeam},
		"no alias": {noAlias}, "no member key": {noKey}, "global without did:aw": {globalWithoutID},
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

// listingRegistry answers a team's active certificate listing, page by page,
// recording who signed each read, and each certificate's public status as
// statuses names it ("" is unknown), under teamDID.
type listingRegistry struct {
	server   *httptest.Server
	status   int
	pages    [][]awid.RegistryCertificate
	failAt   int // the page index that fails, or -1
	signers  []string
	listings int
	statuses map[string]string
	teamDID  string
	// statusTeam, when set, is the team the status names.
	statusTeam string
}

func newListingRegistry(t *testing.T, teamDID string, pages ...[]awid.RegistryCertificate) *listingRegistry {
	r := &listingRegistry{status: http.StatusOK, pages: pages, failAt: -1, statuses: map[string]string{}, teamDID: teamDID}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if id, isStatus := strings.CutSuffix(req.URL.Path, "/status"); isStatus {
			id = id[strings.LastIndex(id, "/")+1:]
			switch status := r.statuses[id]; status {
			case "":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"detail":"not_found"}`))
			case "unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"detail":"unavailable"}`))
			default:
				team := "engineering:customer.example"
				if r.statusTeam != "" {
					team = r.statusTeam
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"team_id": team, "team_did_key": r.teamDID, "status": status, "revoked_at": nil})
			}
			return
		}
		r.listings++
		r.signers = append(r.signers, req.Header.Get("Authorization"))
		page := 0
		if cursor := req.URL.Query().Get("cursor"); cursor != "" {
			_, _ = fmt.Sscanf(cursor, "page-%d", &page)
		}
		if r.status != http.StatusOK || page == r.failAt {
			w.WriteHeader(failureStatus(r.status))
			_, _ = w.Write([]byte(`{"detail":"refused"}`))
			return
		}
		answer := map[string]any{"certificates": r.pages[page], "has_more": page+1 < len(r.pages)}
		if page+1 < len(r.pages) {
			answer["next_cursor"] = fmt.Sprintf("page-%d", page+1)
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func failureStatus(status int) int {
	if status == http.StatusOK {
		return http.StatusServiceUnavailable
	}
	return status
}

// membershipOf is the team certificate teamKey issues memberKey in team.
func membershipOf(t *testing.T, teamKey, memberKey ed25519.PrivateKey, team string) *awid.TeamCertificate {
	t.Helper()
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: team,
		MemberDIDKey: awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey)), Alias: "requester", IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func memberListingAt(t *testing.T, registryURL string, key ed25519.PrivateKey, own *awid.TeamCertificate) (func(context.Context, string) ([]awid.RegistryCertificate, error), error) {
	t.Helper()
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.TrustRegistryOrigin(registryURL); err != nil {
		t.Fatal(err)
	}
	ownCertificate := func(string) (*awid.TeamCertificate, error) { return own, nil }
	return memberCertificateListing(registry, &handoff.Profile{RegistryOrigin: registryURL}, key, ownCertificate)
}

func TestTheListingIsReadAtThePinnedRegistryAsACurrentMember(t *testing.T) {
	teamKey, _, _ := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	public, key, _ := ed25519.GenerateKey(nil)
	own := membershipOf(t, teamKey, key, cert.Team)
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	pinned := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
	pinned.statuses[own.CertificateID] = "active"
	configured := newListingRegistry(t, teamDID, nil)
	t.Setenv("AWID_REGISTRY_URL", configured.server.URL)
	list, err := memberListingAt(t, pinned.server.URL, key, own)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := list(context.Background(), cert.Team)
	if err != nil || len(rows) != 1 || rows[0].CertificateID != cert.CertificateID {
		t.Fatalf("rows %v, %v", rows, err)
	}
	if configured.listings != 0 || pinned.listings != 1 || !strings.Contains(pinned.signers[0], awid.ComputeDIDKey(public)) {
		t.Fatalf("pinned %d signed %v; configured %d", pinned.listings, pinned.signers, configured.listings)
	}
}

func TestOnlyACurrentMemberOfThatTeamMaySelectFromItsListing(t *testing.T) {
	teamKey, _, _ := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	_, key, _ := ed25519.GenerateKey(nil)
	_, otherKey, _ := ed25519.GenerateKey(nil)
	_, otherTeamKey, _ := ed25519.GenerateKey(nil)
	for name, tc := range map[string]struct {
		own    *awid.TeamCertificate
		status string
	}{
		"no membership":                {nil, "active"},
		"another member's certificate": {membershipOf(t, teamKey, otherKey, cert.Team), "active"},
		"another team's certificate":   {membershipOf(t, teamKey, key, "other:customer.example"), "active"},
		"a revoked membership":         {membershipOf(t, teamKey, key, cert.Team), "revoked"},
		"an unregistered membership":   {membershipOf(t, teamKey, key, cert.Team), ""},
		"not issued by the team's key": {membershipOf(t, otherTeamKey, key, cert.Team), "active"},
	} {
		registry := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
		if tc.own != nil {
			registry.statuses[tc.own.CertificateID] = tc.status
		}
		list, err := memberListingAt(t, registry.server.URL, key, tc.own)
		if err == nil {
			_, err = list(context.Background(), cert.Team)
		}
		if errorCodeOf(err) != "selector_unauthorized" || registry.listings != 0 {
			t.Errorf("%s: err %v after %d listings", name, err, registry.listings)
		}
	}
	// A status for another team is not this membership.
	own := membershipOf(t, teamKey, key, cert.Team)
	elsewhere := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
	elsewhere.statuses[own.CertificateID], elsewhere.statusTeam = "active", "other:customer.example"
	if list, _ := memberListingAt(t, elsewhere.server.URL, key, own); list != nil {
		if _, err := list(context.Background(), cert.Team); errorCodeOf(err) != "selector_unauthorized" || elsewhere.listings != 0 {
			t.Errorf("another team's status: %v after %d listings", err, elsewhere.listings)
		}
	}
	// A membership certificate that could not be loaded is not a membership,
	// whatever was read.
	registryClient, _ := newConfiguredRegistryClient(nil)
	partial := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
	partial.statuses[own.CertificateID] = "active"
	_ = registryClient.TrustRegistryOrigin(partial.server.URL)
	broken := func(string) (*awid.TeamCertificate, error) {
		return own, errors.New("the certificate file could not be read whole")
	}
	list, _ := memberCertificateListing(registryClient, &handoff.Profile{RegistryOrigin: partial.server.URL}, key, broken)
	if _, err := list(context.Background(), cert.Team); errorCodeOf(err) != "selector_unauthorized" || partial.listings != 0 {
		t.Errorf("a load error: %v after %d listings", err, partial.listings)
	}
	// A status that cannot be read is its own failure, not a missing
	// certificate and not a membership.
	registry := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
	registry.statuses[own.CertificateID] = "unavailable"
	list, _ = memberListingAt(t, registry.server.URL, key, own)
	if _, err := list(context.Background(), cert.Team); err == nil || errorCodeOf(err) == "certificate_not_found" || registry.listings != 0 {
		t.Errorf("unavailable status: err %v after %d listings", err, registry.listings)
	}
}

func TestAHomeWithoutItsKeyCannotSelectFromThePrivateListing(t *testing.T) {
	pinned := newListingRegistry(t, "", nil)
	if _, err := memberListingAt(t, pinned.server.URL, nil, nil); errorCodeOf(err) != "selector_unauthorized" || pinned.listings != 0 {
		t.Fatalf("err %v after %d reads", err, pinned.listings)
	}
}

func TestARefusedOrIncompleteListingSelectsNothing(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	cert, _ := awid.LoadTeamCertificate(removeTestCertificate(t, teamKey, ""))
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	_, key, _ := ed25519.GenerateKey(nil)
	own := membershipOf(t, teamKey, key, cert.Team)
	forbidden := newListingRegistry(t, teamDID, []awid.RegistryCertificate{rowOf(cert)})
	forbidden.status = http.StatusForbidden
	midway := newListingRegistry(t, teamDID, nil, []awid.RegistryCertificate{rowOf(cert)})
	midway.failAt = 1
	for name, registry := range map[string]*listingRegistry{"forbidden": forbidden, "failed second page": midway} {
		registry.statuses[own.CertificateID] = "active"
		list, err := memberListingAt(t, registry.server.URL, key, own)
		if err != nil {
			t.Fatal(err)
		}
		request := ownerRemovalRequest{Team: cert.Team, CertificateID: cert.CertificateID, RequesterKey: removeTestRootKey, List: list}
		_, err = removeMemberAsOwner(context.Background(), service.options(), profile, request)
		if err == nil || errorCodeOf(err) == "certificate_not_found" || len(service.prepareBodies) != 0 {
			t.Errorf("%s: err %v (code %q) after %d prepares", name, err, errorCodeOf(err), len(service.prepareBodies))
		}
	}
}

func TestAnOwnerRemovalNamesItsTargetOneWay(t *testing.T) {
	for name, flags := range map[string][3]string{
		"nothing":            {"", "", ""},
		"file and selector":  {"worker.cert", "engineering:customer.example", "d511db2c-430c-41ab-a823-87fe43070cf3"},
		"team without id":    {"", "engineering:customer.example", ""},
		"id without team":    {"", "", "d511db2c-430c-41ab-a823-87fe43070cf3"},
		"file and team only": {"worker.cert", "engineering:customer.example", ""},
	} {
		var usage *cliError
		if err := ownerRemovalTargetFlags(flags[0], flags[1], flags[2]); !errors.As(err, &usage) || usage.ExitCode() != 2 {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, flags := range map[string][3]string{
		"file":     {"worker.cert", "", ""},
		"selector": {"", "engineering:customer.example", "d511db2c-430c-41ab-a823-87fe43070cf3"},
	} {
		if err := ownerRemovalTargetFlags(flags[0], flags[1], flags[2]); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOwnerOnlyFlagsAreRefusedWithoutOwnerApproval(t *testing.T) {
	// Every root-mode input is otherwise in place, so only the owner-only
	// flags make this a usage error.
	teamKey, _, _ := ownerRemoveTestSetup(t)
	profilePath := filepath.Join(t.TempDir(), "protected-profile.json")
	if err := os.WriteFile(profilePath, admitTestProfileJSON(teamKey, admitTestHuman), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWEB_PROTECTED_PROFILE", profilePath)
	teamRemoveAgentCertificateFlag = removeTestCertificate(t, teamKey, "")
	t.Cleanup(func() {
		teamRemoveAgentCertificateFlag, teamRemoveAgentTeamFlag, teamRemoveAgentCertificateIDFlag, teamRemoveAgentNoWaitFlag, teamRemoveAgentNoBrowserFlag, teamRemoveAgentReplaceFlag = "", "", "", false, false, ""
	})
	set := map[string]func(){
		"team":           func() { teamRemoveAgentTeamFlag = "engineering:customer.example" },
		"certificate-id": func() { teamRemoveAgentCertificateIDFlag = "d511db2c-430c-41ab-a823-87fe43070cf3" },
		"no-wait":        func() { teamRemoveAgentNoWaitFlag = true },
		"no-browser":     func() { teamRemoveAgentNoBrowserFlag = true },
		"replace":        func() { teamRemoveAgentReplaceFlag = ownerRemoveTestOperation },
	}
	for name, apply := range set {
		teamRemoveAgentTeamFlag, teamRemoveAgentCertificateIDFlag, teamRemoveAgentNoWaitFlag, teamRemoveAgentNoBrowserFlag, teamRemoveAgentReplaceFlag = "", "", false, false, ""
		apply()
		// A usage error, before any profile or identity is read.
		var usage *cliError
		if err := runTeamRemoveAgent(teamRemoveAgentCmd, nil); !errors.As(err, &usage) || usage.ExitCode() != 2 {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestASavedOperationForAnythingElseIsNeverContinued(t *testing.T) {
	type variant struct {
		explicitID bool
		change     func(saved *awconfig.PendingGovernanceOperation, body map[string]any)
	}
	for name, v := range map[string]variant{
		"another service": {true, func(saved *awconfig.PendingGovernanceOperation, _ map[string]any) {
			saved.RequestOrigin = "https://other-signer.example"
		}},
		"another binding": {true, func(_ *awconfig.PendingGovernanceOperation, body map[string]any) {
			body["scope"].(map[string]any)["generation"] = 2
		}},
		"another registry": {true, func(_ *awconfig.PendingGovernanceOperation, body map[string]any) {
			body["audience"] = "https://other-registry.example"
		}},
		"the root's removal": {true, func(_ *awconfig.PendingGovernanceOperation, body map[string]any) { body["variant"] = "default" }},
		"another snapshot": {true, func(_ *awconfig.PendingGovernanceOperation, body map[string]any) {
			body["subject"].(map[string]any)["expected_membership"].(map[string]any)["alias"] = "renamed"
		}},
		"another snapshot, found by target": {false, func(_ *awconfig.PendingGovernanceOperation, body map[string]any) {
			body["subject"].(map[string]any)["expected_membership"].(map[string]any)["alias"] = "renamed"
		}},
	} {
		teamKey, profile, service := ownerRemoveTestSetup(t)
		certificate := removeTestCertificate(t, teamKey, "")
		cert, _ := awid.LoadTeamCertificate(certificate)
		body := ownerRemovalIntent(profile, mustAdmissionBinding(t, profile, cert.Team), cert)
		body["operation_id"] = ownerRemoveTestOperation
		raw, _ := json.Marshal(body)
		body, _ = handoff.DecodeObject(raw)
		saved := &awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin}
		v.change(saved, body)
		saved.Body, _ = json.Marshal(body)
		if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
			t.Fatal(err)
		}
		request := ownerRemoveByFile(certificate)
		if !v.explicitID {
			request.OperationID = ""
		}
		report, err := removeMemberAsOwner(context.Background(), service.options(), profile, request)
		// The same membership under another authority generation is an
		// unfinished removal to reconcile, not merely another request.
		want := "operation_conflict"
		if name == "another binding" {
			want = "operation_reconciliation_required"
		}
		if v.explicitID && errorCodeOf(err) != want || !v.explicitID && report["operation_id"] == ownerRemoveTestOperation {
			t.Errorf("%s: report %v, err %v", name, report, err)
		}
		for _, sent := range service.prepareBodies {
			if bytes.Equal(sent, saved.Body) {
				t.Errorf("%s: the saved request was sent", name)
			}
		}
	}
}

func TestASavedOperationIsContinuedFromItsOwnBytes(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	certificate := removeTestCertificate(t, teamKey, "")
	cert, _ := awid.LoadTeamCertificate(certificate)
	body := ownerRemovalIntent(profile, mustAdmissionBinding(t, profile, cert.Team), cert)
	body["operation_id"] = ownerRemoveTestOperation
	body["redirect_uri"] = "http://127.0.0.1:1/callback"
	raw, _ := json.Marshal(body)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []ownerRemovalRequest{ownerRemoveByFile(certificate), ownerRemoveBySelector(cert, &listing{err: errors.New("unreadable")})} {
		service.receipt = "unavailable"
		_, _ = removeMemberAsOwner(context.Background(), service.options(), profile, request)
		last := service.prepareBodies[len(service.prepareBodies)-1]
		if !bytes.Equal(last, raw) {
			t.Fatalf("sent %s, saved %s", last, raw)
		}
	}
}

func TestAnOwnerRemovalUnderAnotherAuthorityGenerationIsNeverSilentlyReplaced(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	certificate := removeTestCertificate(t, teamKey, "")
	cert, _ := awid.LoadTeamCertificate(certificate)
	binding := mustAdmissionBinding(t, profile, cert.Team)
	earlier := ownerRemovalIntent(profile, binding, cert)
	raw, _ := json.Marshal(earlier)
	body, _ := handoff.DecodeObject(raw)
	body["scope"].(map[string]any)["generation"] = 2
	body["operation_id"] = ownerRemoveTestOperation
	raw, _ = json.Marshal(body)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw}); err != nil {
		t.Fatal(err)
	}
	// By file, or by selector once the certificate has left the listing: the
	// earlier request stops the run, and nothing is prepared.
	for name, request := range map[string]ownerRemovalRequest{
		"file":     {Certificate: certificate, RequesterKey: removeTestRootKey},
		"selector": {Team: cert.Team, CertificateID: cert.CertificateID, RequesterKey: removeTestRootKey, List: (&listing{}).list},
	} {
		_, err := removeMemberAsOwner(context.Background(), service.options(), profile, request)
		if errorCodeOf(err) != "operation_reconciliation_required" || len(service.prepareBodies) != 0 {
			t.Fatalf("%s: err %v after %d prepares", name, err, len(service.prepareBodies))
		}
	}
	// Its receipt is read only through its own binding, which this profile
	// no longer has.
	if service.receiptReads != 0 {
		t.Fatalf("read %d receipts through another generation's binding", service.receiptReads)
	}
	// Another membership of the same team is not held up by it.
	other := removeTestCertificate(t, teamKey, "")
	if report, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemovalRequest{Certificate: other, RequesterKey: removeTestRootKey}); err != nil || report["state"] != "committed" {
		t.Fatalf("another membership: %v, %v", report, err)
	}
	replace := ownerRemovalRequest{Certificate: certificate, RequesterKey: removeTestRootKey, Replace: ownerRemoveTestOperation}
	if report, err := removeMemberAsOwner(context.Background(), service.options(), profile, replace); err != nil || report["state"] != "committed" {
		t.Fatalf("replace: %v, %v", report, err)
	}
	if op := savedOwnerRemoval(t, ownerRemoveTestOperation); op == nil || op.Quarantine == nil {
		t.Fatal("the replaced earlier request is gone")
	}
}

func TestAnUnfinishedRemovalsAppliedReceiptKeepsItsSignedBytes(t *testing.T) {
	signing, signature := []byte(`{"request":"revoke"}`), make([]byte, 64)
	result, _ := json.Marshal(appliedTestResult(ownerRemoveTestOperation, signing, signature))
	report, facts := keepUnverifiedRemoval(&awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation}, nil, result)
	if report != nil || facts == nil || !bytes.Equal(facts.Signing, signing) || len(facts.Signature) != 64 || facts.Verification != "unverifiable" {
		t.Fatalf("report %v facts %+v", report, facts)
	}
	other, _ := json.Marshal(appliedTestResult("66666666-6666-4666-8666-666666666666", signing, signature))
	if _, facts := keepUnverifiedRemoval(&awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation}, nil, other); len(facts.Signing) != 0 {
		t.Fatalf("another operation's receipt kept as this one's: %+v", facts)
	}
}

func TestAQuarantinedCurrentRemovalIsNeverResumedOnlyExplicitlyReplaced(t *testing.T) {
	teamKey, profile, service := ownerRemoveTestSetup(t)
	certificate := removeTestCertificate(t, teamKey, "")
	cert, _ := awid.LoadTeamCertificate(certificate)
	body := ownerRemovalIntent(profile, mustAdmissionBinding(t, profile, cert.Team), cert)
	body["operation_id"] = ownerRemoveTestOperation
	raw, _ := json.Marshal(body)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: ownerRemoveTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
		Quarantine: &awconfig.GovernanceQuarantine{State: "unknown", Code: "external_effect_unresolved", Verification: "unsettled"}}); err != nil {
		t.Fatal(err)
	}
	service.receipt = "unavailable"
	for name, request := range map[string]ownerRemovalRequest{
		"by target":           {Certificate: certificate, RequesterKey: removeTestRootKey},
		"by its operation id": {OperationID: ownerRemoveTestOperation, Certificate: certificate, RequesterKey: removeTestRootKey},
	} {
		if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, request); errorCodeOf(err) != "operation_reconciliation_required" || len(service.prepareBodies) != 0 {
			t.Fatalf("%s: err %v after %d prepares", name, err, len(service.prepareBodies))
		}
	}
	service.receipt = "committed"
	// Naming it both to replace and to continue is refused.
	both := ownerRemovalRequest{OperationID: ownerRemoveTestOperation, Certificate: certificate, RequesterKey: removeTestRootKey, Replace: ownerRemoveTestOperation}
	if _, err := removeMemberAsOwner(context.Background(), service.options(), profile, both); errorCodeOf(err) != "operation_reconciliation_required" || len(service.prepareBodies) != 0 {
		t.Fatalf("continued the quarantined request: %v after %d prepares", err, len(service.prepareBodies))
	}
	report, err := removeMemberAsOwner(context.Background(), service.options(), profile, ownerRemovalRequest{Certificate: certificate, RequesterKey: removeTestRootKey, Replace: ownerRemoveTestOperation})
	if err != nil || report["operation_id"] == ownerRemoveTestOperation || len(service.prepareBodies) != 1 || bytes.Equal(service.prepareBodies[0], raw) {
		t.Fatalf("replace: report %v err %v; the quarantined request was resumed or nothing new was asked", report, err)
	}
	if op := savedOwnerRemoval(t, ownerRemoveTestOperation); op == nil || op.Quarantine == nil {
		t.Fatal("the replaced request's record is gone")
	}
}
