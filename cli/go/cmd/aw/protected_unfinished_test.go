package main

import (
	"bytes"
	"context"
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
