package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
)

const unfinishedOld = "55555555-5555-4555-8555-555555555555"

// receiptService answers each operation's receipt as receipts names it,
// counting reads, and counts every other request it is sent.
type receiptService struct {
	mu       sync.Mutex
	server   *httptest.Server
	receipts map[string]string
	reads    int
	others   int
}

func newReceiptService(t *testing.T) *receiptService {
	s := &receiptService{receipts: map[string]string{}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		id, isRead := strings.CutPrefix(r.URL.Path, "/protected-operations/")
		if r.Method != http.MethodGet || !isRead {
			s.others++
			w.WriteHeader(http.StatusConflict)
			return
		}
		s.reads++
		switch answer := s.receipts[id]; answer {
		case "":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"detail":"unavailable"}`))
		case "404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"detail":"not_found"}`))
		default:
			_, _ = w.Write([]byte(answer))
		}
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *receiptService) reader(scope map[string]any) (handoff.GovernanceOptions, bool) {
	return handoff.GovernanceOptions{Request: s.server.URL, Human: s.server.URL, Notify: io.Discard, RetryWithin: 50 * time.Millisecond,
		Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
			req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
			return http.DefaultClient.Do(req)
		}}, true
}

// unfinishedWorld is a profile at service's origins and the intent a command
// is about to send: a role revoke under generation 2 of the team's binding.
func unfinishedWorld(t *testing.T) (*receiptService, *handoff.Profile, map[string]any) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	service := newReceiptService(t)
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL}
	intent := map[string]any{"operation": "human-role.revoke", "variant": "default", "approval_format": "intent_v1",
		"scope": map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
			"authority": map[string]any{"kind": "team_controller", "id": "h:example.com", "domain": "example.com"},
			"human":     map[string]any{"id": "did:aw:approver", "domain": "example.com"}, "generation": 2},
		"audience": "https://app.example.com",
		"subject":  map[string]any{"app_id": "example", "installation_id": "11111111-1111-4111-8111-111111111111", "role": "example.owner", "principal": "did:aw:principal"}}
	return service, profile, intent
}

// saveUnfinished saves intent, changed by change, as operation id at
// profile's origins.
func saveUnfinished(t *testing.T, profile *handoff.Profile, id string, intent map[string]any, change func(map[string]any)) {
	t.Helper()
	raw, _ := json.Marshal(intent)
	body, _ := handoff.DecodeObject(raw)
	body["operation_id"] = id
	change(body)
	raw, _ = json.Marshal(body)
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: id,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw}); err != nil {
		t.Fatal(err)
	}
}

func oldFormat(body map[string]any) { delete(body, "approval_format") }

func savedRecord(t *testing.T, id string) *awconfig.PendingGovernanceOperation {
	t.Helper()
	op, err := awconfig.LoadPendingGovernanceOperation(id)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// keepCommitted reads every committed result as signed bytes it cannot settle.
func keepCommitted(_ *awconfig.PendingGovernanceOperation, _ map[string]any, result []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
	return nil, &awconfig.GovernanceQuarantine{State: "committed", Signing: result, Verification: "unverifiable"}
}

func TestAnUnfinishedOldRequestStopsTheRunAndIsQuarantinedWithWhatWasRead(t *testing.T) {
	for _, answer := range []string{`{"state":"pending","reason":"awaiting_human","expires_at":"2099-01-01T00:00:00Z"}`, `{"state":"unknown","code":"receipt_unavailable"}`, "", "404"} {
		service, profile, intent := unfinishedWorld(t)
		saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
		service.receipts[unfinishedOld] = answer
		settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted)
		if settled != nil || errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 1 || service.others != 0 {
			t.Fatalf("%q: settled %v err %v reads %d others %d", answer, settled, err, service.reads, service.others)
		}
		if op := savedRecord(t, unfinishedOld); op == nil || op.Quarantine == nil {
			t.Fatalf("%q: not quarantined: %+v", answer, op)
		}
		if ops, _ := awconfig.ListPendingGovernanceOperations(); len(ops) != 1 {
			t.Fatalf("%q: %d saved operations; a new one was minted", answer, len(ops))
		}
	}
}

func TestADefiniteRefusalRetiresTheOldRequestAndStillStartsNothing(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	service.receipts[unfinishedOld] = `{"state":"refused","code":"human_refused"}`
	settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted)
	if settled != nil || errorCodeOf(err) != "earlier_operation_refused" || service.others != 0 || savedRecord(t, unfinishedOld) != nil {
		t.Fatalf("settled %v err %v others %d", settled, err, service.others)
	}
}

func TestAVerifiedAppliedOldRequestSettlesAndEndsTheRun(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	service.receipts[unfinishedOld] = `{"state":"committed","result":{"v":2}}`
	applied := func(saved *awconfig.PendingGovernanceOperation, _ map[string]any, _ []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
		return map[string]any{"operation_id": saved.OperationID, "state": "committed", "applied": "service"}, nil
	}
	settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", applied)
	if err != nil || settled["operation_id"] != unfinishedOld || service.others != 0 || savedRecord(t, unfinishedOld) != nil {
		t.Fatalf("settled %v err %v others %d", settled, err, service.others)
	}
}

func TestQuarantinedEvidenceSurvivesALaterUnreadableReceipt(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	service.receipts[unfinishedOld] = `{"state":"committed","result":{"signing":"c2lnbmVk","signature":"c2ln"}}`
	_, _ = guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted)
	first := savedRecord(t, unfinishedOld).Quarantine
	if first == nil || first.State != "committed" || len(first.Signing) == 0 {
		t.Fatalf("first observation %+v", first)
	}
	for _, later := range []string{"", "404"} {
		service.receipts[unfinishedOld] = later
		if _, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted); errorCodeOf(err) != "operation_reconciliation_required" {
			t.Fatalf("%q: %v", later, err)
		}
		if kept := savedRecord(t, unfinishedOld).Quarantine; kept.State != "committed" || !bytes.Equal(kept.Signing, first.Signing) {
			t.Fatalf("%q: the observed signed bytes were lost: %+v", later, kept)
		}
	}
}

func TestReplacingAQuarantinedRequestNeedsItsOwnIDAndKeepsItsRecord(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	service.receipts[unfinishedOld] = `{"state":"pending","reason":"awaiting_human","expires_at":"2099-01-01T00:00:00Z"}`
	if _, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "66666666-6666-4666-8666-666666666666", keepCommitted); !isUsageError(err) {
		t.Fatalf("another id replaced it: %v", err)
	}
	settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, unfinishedOld, keepCommitted)
	if settled != nil || err != nil || service.others != 0 {
		t.Fatalf("replace: settled %v err %v others %d", settled, err, service.others)
	}
	if op := savedRecord(t, unfinishedOld); op == nil || op.Quarantine == nil {
		t.Fatal("the replaced request's record is gone")
	}
	// With nothing unfinished for this request, --replace names nothing.
	if _, err := guardUnfinished(context.Background(), io.Discard, &handoff.Profile{RequestOrigin: "https://other.example", HumanOrigin: "https://other.example"},
		service.reader, intent, sameCanonical, unfinishedOld, keepCommitted); !isUsageError(err) {
		t.Fatal("--replace named no unfinished request and was accepted")
	}
}

func TestAnUnfinishedRequestUnderAnotherAuthorityGenerationIsNotHidden(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, func(body map[string]any) {
		body["scope"].(map[string]any)["generation"] = 1
	})
	service.receipts[unfinishedOld] = `{"state":"pending","reason":"awaiting_human","expires_at":"2099-01-01T00:00:00Z"}`
	if _, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted); errorCodeOf(err) != "operation_reconciliation_required" {
		t.Fatalf("generation change hid it: %v", err)
	}
}

func TestOnlyTheSameRequestAtTheSameServiceIsGuarded(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"current format and generation": func(map[string]any) {},
		"another team": func(b map[string]any) {
			b["scope"].(map[string]any)["authority"].(map[string]any)["id"] = "x:example.com"
			oldFormat(b)
		},
		"another principal": func(b map[string]any) { b["subject"].(map[string]any)["principal"] = "did:aw:other"; oldFormat(b) },
		"another act":       func(b map[string]any) { b["operation"] = "identity.root.endorse"; oldFormat(b) },
		"another audience":  func(b map[string]any) { b["audience"] = "https://other.example.com"; oldFormat(b) },
	} {
		service, profile, intent := unfinishedWorld(t)
		saveUnfinished(t, profile, unfinishedOld, intent, change)
		if settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted); settled != nil || err != nil || service.reads != 0 {
			t.Errorf("%s: settled %v err %v reads %d", name, settled, err, service.reads)
		}
	}
	service, profile, intent := unfinishedWorld(t)
	other := &handoff.Profile{RequestOrigin: "https://other-signer.example", HumanOrigin: "https://other-human.example"}
	saveUnfinished(t, other, unfinishedOld, intent, oldFormat)
	if settled, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted); settled != nil || err != nil || service.reads != 0 {
		t.Errorf("another service: settled %v err %v reads %d", settled, err, service.reads)
	}
}

func TestAnOldRequestWhoseBindingIsGoneIsQuarantinedUnread(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	gone := func(map[string]any) (handoff.GovernanceOptions, bool) { return handoff.GovernanceOptions{}, false }
	_, err := guardUnfinished(context.Background(), io.Discard, profile, gone, intent, sameCanonical, "", keepCommitted)
	if errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 0 {
		t.Fatalf("err %v reads %d", err, service.reads)
	}
	if q := savedRecord(t, unfinishedOld).Quarantine; q == nil || q.State != "unread" {
		t.Fatalf("quarantine %+v", q)
	}
}

func isUsageError(err error) bool {
	var usage *cliError
	return errors.As(err, &usage) && usage.ExitCode() == 2
}

// Controls from security-fixes' source review of d34cebe6f2 (e019d7cf),
// kept as written.

func TestSecurityReviewKnownQuarantineEvidenceSurvivesAnUnverifiableCommittedRead(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	saved := savedRecord(t, unfinishedOld)
	body, _ := handoff.DecodeObject(saved.Body)
	profile.Bindings = []handoff.ProfileBinding{{Scope: body["scope"].(map[string]any), AuthorityKeyDID: "did:key:original-pin"}}
	signing, signature := []byte("previously observed signed bytes"), []byte("previously observed signature")
	saved.Quarantine = &awconfig.GovernanceQuarantine{State: "committed", Signing: signing, Signature: signature, Verification: "signature_verified", Code: "original-observation"}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	service.receipts[unfinishedOld] = `{"state":"committed","result":{}}`
	_, refused, err := reconcileUnfinished(context.Background(), service.reader, saved, roleActReading(profile, time.Now()))
	if err != nil || refused {
		t.Fatalf("refused=%v err=%v", refused, err)
	}
	kept := savedRecord(t, unfinishedOld).Quarantine
	if !bytes.Equal(kept.Signing, signing) || !bytes.Equal(kept.Signature, signature) || kept.Verification != "signature_verified" {
		t.Fatalf("later unverifiable committed receipt erased prior facts: %+v", kept)
	}
	if service.reads != 1 || service.others != 0 {
		t.Fatalf("reads=%d others=%d", service.reads, service.others)
	}
}

func TestSecurityReviewQuarantineRemainsInactiveWhenItsScopeMatchesAgain(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, func(map[string]any) {})
	saved := savedRecord(t, unfinishedOld)
	saved.Quarantine = &awconfig.GovernanceQuarantine{State: "unknown", Code: "external_effect_unresolved", Verification: "unsettled"}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	service.receipts[unfinishedOld] = `{"state":"unknown","code":"external_effect_unresolved"}`
	report, err := guardUnfinished(context.Background(), io.Discard, profile, service.reader, intent, sameCanonical, "", keepCommitted)
	if report != nil || errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 1 || service.others != 0 {
		t.Fatalf("explicit quarantine was skipped when format/scope matched: report=%v err=%v reads=%d others=%d", report, err, service.reads, service.others)
	}
}

func TestSecurityReviewRoleRevokeDoesNotPrepareOverMatchingQuarantine(t *testing.T) {
	app := newOwnerActApp(t)
	frozen, binding, _, id := settleWorld(t, app, time.Now())
	service, optionsFor := roleService(t)
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL, Bindings: []handoff.ProfileBinding{*binding}}
	subject := frozen["subject"].(map[string]any)
	body := protectedRoleIntent("human-role.revoke", binding.Scope, app.server.URL, subject)
	body["operation_id"] = id
	raw, _ := json.Marshal(body)
	saved := &awconfig.PendingGovernanceOperation{OperationID: id, RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
		Quarantine: &awconfig.GovernanceQuarantine{State: "unknown", Code: "external_effect_unresolved", Verification: "unsettled"}}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	service.receipts[id] = `{"state":"unknown","code":"external_effect_unresolved"}`
	err := requestProtectedRoleAct(context.Background(), settleCommand(), profile, binding, optionsFor, "human-role.revoke", app.server.URL, subject, "")
	if errorCodeOf(err) != "operation_reconciliation_required" || service.reads != 1 || service.others != 0 || len(app.posts) != 0 {
		t.Fatalf("new command prepared over quarantine: err=%v reads=%d new-prepares=%d app-posts=%d", err, service.reads, service.others, len(app.posts))
	}
}

func TestAConflictingLaterSignedResultKeepsTheOriginalAndRecordsTheConflict(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	saved := savedRecord(t, unfinishedOld)
	saved.Quarantine = &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte("first signed bytes"), Signature: []byte("first signature"), Verification: "signature_verified"}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	service.receipts[unfinishedOld] = `{"state":"committed","result":{}}`
	other := func(*awconfig.PendingGovernanceOperation, map[string]any, []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
		return nil, &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte("other signed bytes"), Signature: []byte("other signature"), Verification: "unverifiable"}
	}
	if _, _, err := reconcileUnfinished(context.Background(), service.reader, saved, other); err != nil {
		t.Fatal(err)
	}
	kept := savedRecord(t, unfinishedOld).Quarantine
	if !bytes.Equal(kept.Signing, []byte("first signed bytes")) || kept.Verification != "signature_verified" || len(kept.Conflicts) != 1 || !bytes.Equal(kept.Conflicts[0].Signing, []byte("other signed bytes")) {
		t.Fatalf("kept %+v", kept)
	}
}

// observing reads one committed result carrying signing and signature,
// verified as verification.
func observing(signing, verification string) committedReading {
	return func(*awconfig.PendingGovernanceOperation, map[string]any, []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
		return nil, &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte(signing), Signature: []byte(signing + "-signature"), Verification: verification}
	}
}

func TestEverySignedResultObservedIsKeptAcrossSavedReads(t *testing.T) {
	for name, sequence := range map[string][]committedReading{
		"A, B, A again verified": {observing("A", "unverifiable"), observing("B", "unverifiable"), observing("A", "signature_verified")},
		"A, B, C":                {observing("A", "unverifiable"), observing("B", "unverifiable"), observing("C", "unverifiable")},
		"A, B, B, nothing":       {observing("A", "unverifiable"), observing("B", "unverifiable"), observing("B", "unverifiable"), keepCommittedWithoutBytes},
	} {
		service, profile, intent := unfinishedWorld(t)
		saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
		service.receipts[unfinishedOld] = `{"state":"committed","result":{}}`
		for _, read := range sequence {
			// Each read starts from the record as saved by the last.
			if _, _, err := reconcileUnfinished(context.Background(), service.reader, savedRecord(t, unfinishedOld), read); err != nil {
				t.Fatal(err)
			}
		}
		kept := savedRecord(t, unfinishedOld).Quarantine
		var conflicts []string
		for _, c := range kept.Conflicts {
			conflicts = append(conflicts, string(c.Signing))
		}
		want := map[string][]string{"A, B, A again verified": {"B"}, "A, B, C": {"B", "C"}, "A, B, B, nothing": {"B"}}[name]
		if string(kept.Signing) != "A" || strings.Join(conflicts, ",") != strings.Join(want, ",") {
			t.Errorf("%s: kept %s with conflicts %v", name, kept.Signing, conflicts)
		}
		if name == "A, B, A again verified" && kept.Verification != "signature_verified" {
			t.Errorf("%s: verification %s", name, kept.Verification)
		}
	}
}

func TestSignedEvidenceSurvivesAnEmptyCommittedReadAndThenNoAnswer(t *testing.T) {
	service, profile, intent := unfinishedWorld(t)
	saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
	saved := savedRecord(t, unfinishedOld)
	saved.Quarantine = &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte("signed"), Signature: []byte("signature"), Verification: "expired"}
	if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
		t.Fatal(err)
	}
	for _, answer := range []string{`{"state":"committed","result":{}}`, ""} {
		service.receipts[unfinishedOld] = answer
		if _, _, err := reconcileUnfinished(context.Background(), service.reader, savedRecord(t, unfinishedOld), keepCommittedWithoutBytes); err != nil {
			t.Fatal(err)
		}
		if kept := savedRecord(t, unfinishedOld).Quarantine; !bytes.Equal(kept.Signing, []byte("signed")) || kept.Verification != "expired" {
			t.Fatalf("after %q: %+v", answer, kept)
		}
	}
}

func keepCommittedWithoutBytes(*awconfig.PendingGovernanceOperation, map[string]any, []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
	return nil, &awconfig.GovernanceQuarantine{State: "committed", Verification: "unverifiable"}
}

func TestTheStrongerObservationOfTheSameBytesAndTheMoreTellingStateAreKept(t *testing.T) {
	expired := &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte("s"), Signature: []byte("g"), Verification: "expired"}
	verified := &awconfig.GovernanceQuarantine{State: "committed", Signing: []byte("s"), Signature: []byte("g"), Verification: "signature_verified"}
	if got := mergedFacts(expired, verified); got.Verification != "expired" {
		t.Fatalf("a weaker read of the same bytes replaced expired: %+v", got)
	}
	if got := mergedFacts(verified, expired); got.Verification != "expired" {
		t.Fatalf("expiry of the same bytes was not recorded: %+v", got)
	}
	pending := &awconfig.GovernanceQuarantine{State: "pending", Verification: "unsettled"}
	unread := &awconfig.GovernanceQuarantine{State: "unread", Code: "receipt_unavailable", Verification: "unread"}
	if got := mergedFacts(pending, unread); got.State != "pending" {
		t.Fatalf("no answer replaced a receipt's state: %+v", got)
	}
}

func TestAQuarantinedRequestIsNeverTheOneAnEndorsementResumes(t *testing.T) {
	_, humanKey, _ := ed25519.GenerateKey(nil)
	t.Setenv("HOME", t.TempDir())
	profile := endorseTestProfile(t, humanKey)
	binding, _ := endorsementBinding(profile, admitTestHuman)
	intent, _ := endorsementIntent(profile, binding, endorseTestRequest())
	raw, _ := json.Marshal(func() map[string]any {
		b := map[string]any{"operation_id": endorseTestOperation}
		for k, v := range intent {
			b[k] = v
		}
		return b
	}())
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: endorseTestOperation,
		RequestOrigin: profile.RequestOrigin, HumanOrigin: profile.HumanOrigin, Body: raw,
		Quarantine: &awconfig.GovernanceQuarantine{State: "unknown", Verification: "unsettled"}}); err != nil {
		t.Fatal(err)
	}
	id, resumed, err := protectedOperationID("", profile, intent)
	if err != nil || resumed || id == endorseTestOperation {
		t.Fatalf("id %s resumed %v err %v", id, resumed, err)
	}
	if _, err := savedEndorsement(profile, endorseTestOperation, intent); errorCodeOf(err) != "operation_reconciliation_required" {
		t.Fatalf("named quarantined endorsement: %v", err)
	}
}

// From security-fixes' review of 624de91543 (ede1fefc), adapted from the two
// single conflict fields to the conflicts list that replaced them: the same
// sequence through the private store, for an equal and a stronger
// verification of the original bytes.
func TestSecurityReviewARecordedConflictSurvivesAnotherReadOfTheOriginalBytes(t *testing.T) {
	for _, verification := range []string{"signature_verified", "expired"} {
		t.Run(verification, func(t *testing.T) {
			service, profile, intent := unfinishedWorld(t)
			saveUnfinished(t, profile, unfinishedOld, intent, oldFormat)
			saved := savedRecord(t, unfinishedOld)
			first, firstSig := []byte("original signed bytes"), []byte("original signature")
			other, otherSig := []byte("conflicting signed bytes"), []byte("conflicting signature")
			saved.Quarantine = &awconfig.GovernanceQuarantine{State: "committed", Signing: first, Signature: firstSig, Verification: "signature_verified"}
			if err := awconfig.SavePendingGovernanceOperation(saved); err != nil {
				t.Fatal(err)
			}
			service.receipts[unfinishedOld] = `{"state":"committed","result":{}}`
			conflicting := func(*awconfig.PendingGovernanceOperation, map[string]any, []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
				return nil, &awconfig.GovernanceQuarantine{State: "committed", Signing: other, Signature: otherSig, Verification: "unverifiable"}
			}
			if _, _, err := reconcileUnfinished(context.Background(), service.reader, saved, conflicting); err != nil {
				t.Fatal(err)
			}
			if kept := savedRecord(t, unfinishedOld).Quarantine; len(kept.Conflicts) != 1 || !bytes.Equal(kept.Conflicts[0].Signing, other) {
				t.Fatalf("conflict not established: %+v", kept)
			}
			originalAgain := func(*awconfig.PendingGovernanceOperation, map[string]any, []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
				return nil, &awconfig.GovernanceQuarantine{State: "committed", Signing: first, Signature: firstSig, Verification: verification}
			}
			if _, _, err := reconcileUnfinished(context.Background(), service.reader, savedRecord(t, unfinishedOld), originalAgain); err != nil {
				t.Fatal(err)
			}
			kept := savedRecord(t, unfinishedOld).Quarantine
			if !bytes.Equal(kept.Signing, first) || len(kept.Conflicts) != 1 || !bytes.Equal(kept.Conflicts[0].Signing, other) ||
				!bytes.Equal(kept.Conflicts[0].Signature, otherSig) || kept.Verification != verification {
				t.Fatalf("reading original bytes again erased the recorded conflict: %+v", kept)
			}
		})
	}
}
