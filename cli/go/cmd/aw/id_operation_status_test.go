package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
)

const statusOperation = "66666666-6666-4666-8666-666666666666"

// statusService answers one receipt read with status and body, and records
// every request it is sent.
type statusService struct {
	mu       sync.Mutex
	server   *httptest.Server
	status   int
	body     string
	requests []string
}

func newStatusService(t *testing.T, status int, body string) *statusService {
	s := &statusService{status: status, body: body}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests = append(s.requests, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.server.Close)
	return s
}

func (s *statusService) sent() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// statusScope is a protected scope for team h:example.com's controller at
// generation, approved by human.
func statusScope(human string, generation int) map[string]any {
	return map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
		"authority": map[string]any{"kind": "team_controller", "id": "h:example.com", "domain": "example.com"},
		"human":     map[string]any{"id": human, "domain": "example.com"}, "generation": generation}
}

// statusWorld is a profile at service's origins binding scopes, and the
// options a read is signed with, recording the scope each was asked for.
func statusWorld(t *testing.T, service *statusService, scopes ...map[string]any) (*handoff.Profile, func(map[string]any) handoff.GovernanceOptions, *[]map[string]any) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	profile := &handoff.Profile{RequestOrigin: service.server.URL, HumanOrigin: service.server.URL}
	for _, scope := range scopes {
		profile.Bindings = append(profile.Bindings, handoff.ProfileBinding{Scope: scope})
	}
	var signedUnder []map[string]any
	optionsFor := func(scope map[string]any) handoff.GovernanceOptions {
		signedUnder = append(signedUnder, scope)
		return handoff.GovernanceOptions{Request: profile.RequestOrigin, Human: profile.HumanOrigin,
			Sign: func(ctx context.Context, method string, target *url.URL, body []byte) (*http.Response, error) {
				req, _ := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
				return http.DefaultClient.Do(req)
			}}
	}
	return profile, optionsFor, &signedUnder
}

// saveStatusOperation saves a request for statusOperation under scope at the
// given origins, as aw does before it sends one, and returns its stored bytes.
func saveStatusOperation(t *testing.T, requestOrigin, humanOrigin string, scope any, quarantine *awconfig.GovernanceQuarantine) []byte {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"operation_id": statusOperation, "operation": "team.agent.admit", "variant": "default", "scope": scope})
	if err := awconfig.SavePendingGovernanceOperation(&awconfig.PendingGovernanceOperation{OperationID: statusOperation,
		RequestOrigin: requestOrigin, HumanOrigin: humanOrigin, Body: body, Quarantine: quarantine}); err != nil {
		t.Fatal(err)
	}
	return storedStatusOperation(t)
}

func storedStatusOperation(t *testing.T) []byte {
	t.Helper()
	op, err := awconfig.LoadPendingGovernanceOperation(statusOperation)
	if err != nil {
		t.Fatal(err)
	}
	if op == nil {
		return nil
	}
	raw, _ := json.Marshal(op)
	return raw
}

func TestOperationStatusReportsEachReceiptStateAsServedWithOneRead(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       map[string]any
	}{
		{"pending", `{"state":"pending","reason":"effect_in_progress","expires_at":"2026-11-14T10:00:00Z"}`,
			map[string]any{"state": "pending", "reason": "effect_in_progress", "expires_at": "2026-11-14T10:00:00Z"}},
		{"committed", `{"state":"committed","result":{"certificate_id":"cert-1"}}`,
			map[string]any{"state": "committed", "result": map[string]any{"certificate_id": "cert-1"}, "result_verification": "not_performed"}},
		{"refused", `{"state":"refused","code":"approval_expired"}`, map[string]any{"state": "refused", "code": "approval_expired"}},
		{"unknown", `{"state":"unknown","code":"external_effect_unresolved"}`, map[string]any{"state": "unknown", "code": "external_effect_unresolved"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newStatusService(t, http.StatusOK, tc.body)
			scope := statusScope("did:aw:approver", 2)
			profile, optionsFor, _ := statusWorld(t, service, scope)
			before := saveStatusOperation(t, profile.RequestOrigin, profile.HumanOrigin, scope, nil)
			got, err := operationStatus(context.Background(), profile, statusOperation, optionsFor)
			if err != nil {
				t.Fatal(err)
			}
			tc.want["operation_id"] = statusOperation
			if !sameCanonical(roundTrip(t, got), tc.want) {
				t.Fatalf("status = %v, want %v", roundTrip(t, got), tc.want)
			}
			if sent := service.sent(); len(sent) != 1 || sent[0] != "GET /protected-operations/"+statusOperation {
				t.Fatalf("requests = %v, want the one receipt read", sent)
			}
			if after := storedStatusOperation(t); !bytes.Equal(after, before) {
				t.Fatalf("the saved request changed:\n%s\n%s", before, after)
			}
		})
	}
}

func TestOperationStatusLeavesAQuarantinedSaveAsItWasOnACommittedReceipt(t *testing.T) {
	service := newStatusService(t, http.StatusOK, `{"state":"committed","result":{"signing":"c2lnbmluZw","signature":"c2ln"}}`)
	scope := statusScope("did:aw:approver", 2)
	profile, optionsFor, _ := statusWorld(t, service, scope)
	before := saveStatusOperation(t, profile.RequestOrigin, profile.HumanOrigin, scope,
		&awconfig.GovernanceQuarantine{State: "unread", Code: "receipt_unavailable", Verification: "unread"})
	if _, err := operationStatus(context.Background(), profile, statusOperation, optionsFor); err != nil {
		t.Fatal(err)
	}
	if after := storedStatusOperation(t); !bytes.Equal(after, before) {
		t.Fatalf("the quarantined request changed:\n%s\n%s", before, after)
	}
}

func TestOperationStatusIsNoneOnlyForTheServicesTypedNotFound(t *testing.T) {
	service := newStatusService(t, http.StatusNotFound, `{"detail":"operation_not_found"}`)
	scope := statusScope("did:aw:approver", 2)
	profile, optionsFor, _ := statusWorld(t, service, scope)
	got, err := operationStatus(context.Background(), profile, statusOperation, optionsFor)
	if err != nil {
		t.Fatal(err)
	}
	if !sameCanonical(roundTrip(t, got), map[string]any{"operation_id": statusOperation, "state": "none"}) {
		t.Fatalf("status = %v", got)
	}
}

func TestOperationStatusTellsEveryOtherAnswerAsAnErrorNotAState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"bare 404", http.StatusNotFound, `{"detail":"not_found"}`},
		{"404 without a body", http.StatusNotFound, ``},
		{"not found under another status", http.StatusConflict, `{"detail":"operation_not_found"}`},
		{"requester refused", http.StatusUnauthorized, `{"detail":"requester_invalid"}`},
		{"scope refused", http.StatusForbidden, `{"detail":"scope_refused"}`},
		{"throttled", http.StatusTooManyRequests, `{"detail":"rate_limited"}`},
		{"unavailable", http.StatusServiceUnavailable, `{"detail":"receipt_unavailable"}`},
		{"malformed receipt", http.StatusOK, `{"state":"pending"}`},
		{"unknown state", http.StatusOK, `{"state":"prepared","reason":"awaiting_execute","expires_at":"2026-11-14T10:00:00Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newStatusService(t, tc.status, tc.body)
			scope := statusScope("did:aw:approver", 2)
			profile, optionsFor, _ := statusWorld(t, service, scope)
			got, err := operationStatus(context.Background(), profile, statusOperation, optionsFor)
			if err == nil {
				t.Fatalf("status = %v, want an error", got)
			}
			if len(service.sent()) != 1 {
				t.Fatalf("requests = %v, want one read", service.sent())
			}
		})
	}
	t.Run("transport failure", func(t *testing.T) {
		service := newStatusService(t, http.StatusOK, `{}`)
		scope := statusScope("did:aw:approver", 2)
		profile, optionsFor, _ := statusWorld(t, service, scope)
		service.server.Close()
		if got, err := operationStatus(context.Background(), profile, statusOperation, optionsFor); err == nil {
			t.Fatalf("status = %v, want an error", got)
		}
	})
}

func TestOperationStatusReadsASavedRequestUnderItsOwnBindingAtTheCurrentGeneration(t *testing.T) {
	service := newStatusService(t, http.StatusOK, `{"state":"refused","code":"operation_expired"}`)
	current := statusScope("did:aw:approver", 3)
	other := statusScope("did:aw:other", 3)
	profile, optionsFor, signedUnder := statusWorld(t, service, other, current)
	saveStatusOperation(t, profile.RequestOrigin, profile.HumanOrigin, statusScope("did:aw:approver", 2), nil)
	if _, err := operationStatus(context.Background(), profile, statusOperation, optionsFor); err != nil {
		t.Fatal(err)
	}
	if len(*signedUnder) != 1 || !sameCanonical((*signedUnder)[0], current) {
		t.Fatalf("read under %v, want the saved request's binding %v", *signedUnder, current)
	}
}

func TestOperationStatusRefusesASavedRequestItCannotPinToOneBinding(t *testing.T) {
	scope := statusScope("did:aw:approver", 2)
	for _, tc := range []struct {
		name          string
		bindings      []map[string]any
		requestOrigin string
		humanOrigin   string
		savedScope    any
		code          string
	}{
		{"another request origin", []map[string]any{scope}, "https://elsewhere.example", "", scope, "operation_conflict"},
		{"another human origin", []map[string]any{scope}, "", "https://elsewhere.example", scope, "operation_conflict"},
		{"no scope", []map[string]any{scope}, "", "", nil, "operation_conflict"},
		{"scope not an object", []map[string]any{scope}, "", "", "svc", "operation_conflict"},
		{"no binding for it, though the profile has one", []map[string]any{statusScope("did:aw:other", 2)}, "", "", scope, "profile_scope_refused"},
		{"two bindings for it", []map[string]any{scope, statusScope("did:aw:approver", 3)}, "", "", scope, "profile_scope_ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newStatusService(t, http.StatusOK, `{"state":"refused","code":"operation_expired"}`)
			profile, optionsFor, _ := statusWorld(t, service, tc.bindings...)
			saveStatusOperation(t, cmp.Or(tc.requestOrigin, profile.RequestOrigin), cmp.Or(tc.humanOrigin, profile.HumanOrigin), tc.savedScope, nil)
			before := storedStatusOperation(t)
			_, err := operationStatus(context.Background(), profile, statusOperation, optionsFor)
			if code := errorCodeOf(err); code != tc.code {
				t.Fatalf("error = %v (code %q), want code %q", err, code, tc.code)
			}
			if sent := service.sent(); len(sent) != 0 {
				t.Fatalf("requests = %v, want none", sent)
			}
			if after := storedStatusOperation(t); !bytes.Equal(after, before) {
				t.Fatalf("the saved request changed")
			}
		})
	}
}

func TestOperationStatusWithoutASavedRequestNeedsTheProfilesOneBinding(t *testing.T) {
	t.Run("one binding", func(t *testing.T) {
		service := newStatusService(t, http.StatusOK, `{"state":"refused","code":"operation_expired"}`)
		scope := statusScope("did:aw:approver", 2)
		profile, optionsFor, signedUnder := statusWorld(t, service, scope)
		if _, err := operationStatus(context.Background(), profile, statusOperation, optionsFor); err != nil {
			t.Fatal(err)
		}
		if len(*signedUnder) != 1 || !sameCanonical((*signedUnder)[0], scope) {
			t.Fatalf("read under %v", *signedUnder)
		}
	})
	for _, tc := range []struct {
		name     string
		bindings []map[string]any
		code     string
	}{
		{"none", nil, "profile_scope_refused"},
		{"two", []map[string]any{statusScope("did:aw:approver", 2), statusScope("did:aw:other", 2)}, "profile_scope_ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := newStatusService(t, http.StatusOK, `{"state":"refused","code":"operation_expired"}`)
			profile, optionsFor, _ := statusWorld(t, service, tc.bindings...)
			_, err := operationStatus(context.Background(), profile, statusOperation, optionsFor)
			if code := errorCodeOf(err); code != tc.code {
				t.Fatalf("error = %v (code %q), want code %q", err, code, tc.code)
			}
			if sent := service.sent(); len(sent) != 0 {
				t.Fatalf("requests = %v, want none", sent)
			}
		})
	}
}

func TestOperationStatusRefusesAnOperationIDThatIsNotAUUID(t *testing.T) {
	service := newStatusService(t, http.StatusOK, `{"state":"refused","code":"operation_expired"}`)
	profile, optionsFor, _ := statusWorld(t, service, statusScope("did:aw:approver", 2))
	if _, err := operationStatus(context.Background(), profile, "../"+strings.ToUpper(statusOperation), optionsFor); err == nil {
		t.Fatal("an invalid operation id was read")
	}
	if sent := service.sent(); len(sent) != 0 {
		t.Fatalf("requests = %v, want none", sent)
	}
}

func roundTrip(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
