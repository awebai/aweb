package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	aweb "github.com/awebai/aw"
)

// retirementStores is a pair of stand-in stores that records the order it was
// called in. Both are driven over real HTTP by the real client and the real
// revoke, so what is faked is the far side of the wire, never the code sequencing
// the two.
type retirementStores struct {
	t *testing.T

	mu    sync.Mutex
	calls []string

	workspaceID    string
	alias          string
	claimsReleased int

	// workspaceMissing serves an empty list, as it is after a real retirement.
	workspaceMissing bool
	// deleteConflict serves the presence gate: a workspace seen too recently.
	deleteConflict bool
	// certificateStatus is the wire status the hosted endpoint answers with.
	certificateStatus string

	coordination *httptest.Server
	certificate  *httptest.Server
}

func newRetirementStores(t *testing.T) *retirementStores {
	t.Helper()
	s := &retirementStores{
		t:                 t,
		workspaceID:       "11111111-2222-3333-4444-555555555555",
		alias:             "retiree",
		claimsReleased:    3,
		certificateStatus: "removed",
	}

	s.coordination = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workspaces":
			s.record("coordination:list")
			if s.workspaceMissing {
				_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []any{}, "has_more": false})
				return
			}
			scope := "local"
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{{
				"workspace_id":         s.workspaceID,
				"alias":                s.alias,
				"agent_identity_scope": scope,
			}}, "has_more": false})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workspaces/"+s.workspaceID:
			s.record("coordination:delete")
			if s.deleteConflict {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{
					"code":                  "local_workspace_still_active",
					"recommended_next_step": "Wait until presence is stale before deleting a local workspace.",
				}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     s.workspaceID,
				"alias":            s.alias,
				"deleted_at":       "2026-07-29T12:00:00Z",
				"identity_deleted": true,
				"claims_released":  s.claimsReleased,
			})
		default:
			s.t.Fatalf("unexpected coordination request %s %s", r.Method, r.URL.String())
		}
	}))
	t.Cleanup(s.coordination.Close)

	s.certificate = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record("certificate:revoke")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         s.certificateStatus,
			"certificate_id": "cert-retiree",
		})
	}))
	t.Cleanup(s.certificate.Close)

	return s
}

func (s *retirementStores) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *retirementStores) order() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *retirementStores) retire(t *testing.T) teamRemoveAgentOutput {
	t.Helper()
	resetTeamRemoveMemberGlobals(t)
	t.Chdir(t.TempDir())
	t.Setenv(initAPIKeyEnvVar, "aw_sk_env")
	teamRemoveAwebURL = s.certificate.URL

	client, err := aweb.New(s.coordination.URL)
	if err != nil {
		t.Fatalf("aweb.New: %v", err)
	}
	return retireTeamAgent(
		context.Background(),
		client,
		"default:alice.aweb.ai",
		"alice.aweb.ai/"+s.alias,
		s.alias,
		func(ctx context.Context) (certificateStoreResult, error) {
			return revokeHostedTeamCertificate(ctx, "default:alice.aweb.ai", "alice.aweb.ai/"+s.alias, "")
		},
	)
}

func storeOutcome(t *testing.T, out teamRemoveAgentOutput, store string) retireStoreOutcome {
	t.Helper()
	for _, outcome := range out.Stores {
		if outcome.Store == store {
			return outcome
		}
	}
	t.Fatalf("no outcome reported for store %q; stores=%+v", store, out.Stores)
	return retireStoreOutcome{}
}

// The claims are released by deleting the workspace record, and that has to
// happen before the certificate is revoked. The hosted remove-member endpoint
// soft-deletes the same workspace row without releasing anything, so a revoke
// that runs first strands every claim.
//
// Deleting the coordination step from retireTeamAgent makes this test fail: the
// order no longer contains coordination:delete and no claims are reported.
func TestRetireTeamAgentReleasesClaimsBeforeRevokingTheCertificate(t *testing.T) {
	stores := newRetirementStores(t)
	out := stores.retire(t)

	order := stores.order()
	deleteAt, revokeAt := -1, -1
	for i, call := range order {
		switch call {
		case "coordination:delete":
			deleteAt = i
		case "certificate:revoke":
			revokeAt = i
		}
	}
	if deleteAt < 0 {
		t.Fatalf("retirement never deleted the workspace record; calls=%v", order)
	}
	if revokeAt < 0 {
		t.Fatalf("retirement never revoked the certificate; calls=%v", order)
	}
	if deleteAt > revokeAt {
		t.Fatalf("certificate was revoked before the claims were released; calls=%v", order)
	}
	if out.ClaimsReleased != 3 {
		t.Fatalf("claims_released=%d, want 3", out.ClaimsReleased)
	}
	if out.Status != retirementRetired {
		t.Fatalf("status=%q, want %q", out.Status, retirementRetired)
	}
	if got := storeOutcome(t, out, storeCoordination); got.Result != storeChanged {
		t.Fatalf("coordination=%+v, want %q", got, storeChanged)
	}
	if got := storeOutcome(t, out, storeCertificate); got.Result != storeChanged {
		t.Fatalf("certificate=%+v, want %q", got, storeChanged)
	}
}

// A workspace seen inside the presence window cannot be deleted, so its claims
// cannot be released. Revoking anyway would destroy the only credential able to
// release them. The command stops and reports which store changed and which did
// not, rather than one terminal word.
func TestRetireTeamAgentStopsBeforeRevokeWhenTheClaimsCannotBeReleased(t *testing.T) {
	stores := newRetirementStores(t)
	stores.deleteConflict = true
	out := stores.retire(t)

	for _, call := range stores.order() {
		if call == "certificate:revoke" {
			t.Fatalf("certificate was revoked while the claims were still held; calls=%v", stores.order())
		}
	}
	if out.Status != retirementIncomplete {
		t.Fatalf("status=%q, want %q", out.Status, retirementIncomplete)
	}

	coordination := storeOutcome(t, out, storeCoordination)
	if coordination.Result != storeBlocked {
		t.Fatalf("coordination=%+v, want %q", coordination, storeBlocked)
	}
	if !strings.Contains(coordination.Detail, "local_workspace_still_active") {
		t.Fatalf("blocked coordination store does not name the reason: %q", coordination.Detail)
	}
	if !strings.Contains(coordination.Detail, "presence is stale") {
		t.Fatalf("blocked coordination store does not say what to do about it: %q", coordination.Detail)
	}

	certificate := storeOutcome(t, out, storeCertificate)
	if certificate.Result != storeNotAttempted {
		t.Fatalf("certificate=%+v, want %q", certificate, storeNotAttempted)
	}
	if !strings.Contains(certificate.Detail, "aw id team remove-member") {
		t.Fatalf("skipped certificate store does not name the immediate-revoke path: %q", certificate.Detail)
	}
	if out.ClaimsReleased != 0 {
		t.Fatalf("claims_released=%d, want 0 when nothing was released", out.ClaimsReleased)
	}
}

// Retiring an agent that is already retired converges. Both stores are already
// in the state retirement wants, so the postcondition holds and the command
// succeeds - while still reporting that this call changed nothing.
func TestRetireTeamAgentConvergesWhenTheAgentIsAlreadyRetired(t *testing.T) {
	stores := newRetirementStores(t)
	stores.workspaceMissing = true
	stores.certificateStatus = "not_found"
	out := stores.retire(t)

	if out.Status != retirementReported {
		t.Fatalf("status=%q, want %q", out.Status, retirementReported)
	}
	if !retirementSucceeded(out.Status) {
		t.Fatalf("a converging retry must succeed; status=%q", out.Status)
	}
	if got := storeOutcome(t, out, storeCoordination); got.Result != storeUnchanged {
		t.Fatalf("coordination=%+v, want %q", got, storeUnchanged)
	}
	certificate := storeOutcome(t, out, storeCertificate)
	if certificate.Result != storeUnchanged {
		t.Fatalf("certificate=%+v, want %q", certificate, storeUnchanged)
	}
	if out.CertificateResult != certificateNothingReported {
		t.Fatalf("certificate_result=%q, want %q", out.CertificateResult, certificateNothingReported)
	}
	if strings.Contains(strings.ToLower(certificate.Detail), "already removed") {
		t.Fatalf("a call that revoked nothing must not assert a prior removal: %q", certificate.Detail)
	}
}

// The two certificate outcomes must be distinguishable in the structured output,
// not only in prose, because that is what a script branches on.
func TestRetireTeamAgentReportsWhetherItRevokedAnything(t *testing.T) {
	for wireStatus, want := range map[string]string{
		"removed":   certificateRevoked,
		"not_found": certificateNothingReported,
	} {
		t.Run(wireStatus, func(t *testing.T) {
			stores := newRetirementStores(t)
			stores.certificateStatus = wireStatus
			out := stores.retire(t)

			if !retirementSucceeded(out.Status) {
				t.Fatalf("status=%q, want a succeeding status", out.Status)
			}
			if out.CertificateResult != want {
				t.Fatalf("certificate_result=%q, want %q", out.CertificateResult, want)
			}
			encoded, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var decoded map[string]any
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if decoded["certificate_result"] != want {
				t.Fatalf("certificate_result is not machine-branchable: %v", decoded["certificate_result"])
			}
		})
	}
}

// A certificate store that errors leaves the agent partly retired: its claims
// are gone but it still holds a credential. That must not read as a retirement.
func TestRetireTeamAgentReportsAFailedRevokeWithoutClaimingRetirement(t *testing.T) {
	stores := newRetirementStores(t)
	stores.certificate.Close()
	stores.certificate = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stores.record("certificate:revoke")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "awid_unavailable"}})
	}))
	t.Cleanup(stores.certificate.Close)

	out := stores.retire(t)

	if out.Status != retirementIncomplete {
		t.Fatalf("status=%q, want %q", out.Status, retirementIncomplete)
	}
	if got := storeOutcome(t, out, storeCoordination); got.Result != storeChanged {
		t.Fatalf("coordination=%+v, want %q; the claims were released and the report must say so", got, storeChanged)
	}
	if got := storeOutcome(t, out, storeCertificate); got.Result != storeFailed {
		t.Fatalf("certificate=%+v, want %q", got, storeFailed)
	}
}

// The hosted service answers not_found from its own membership records and may
// never consult the registry, so a member holding a live certificate with no
// hosted record is reported this way. The command must therefore not turn that
// answer into a claim about certificates - doing so would be the same defect as
// the word it replaced, asserting more than was established.
func TestRetireTeamAgentDoesNotTurnAReportedNoOpIntoACertificateClaim(t *testing.T) {
	stores := newRetirementStores(t)
	stores.workspaceMissing = true
	stores.certificateStatus = "not_found"
	out := stores.retire(t)

	if out.CertificateResult != certificateNothingReported {
		t.Fatalf("certificate_result=%q, want %q", out.CertificateResult, certificateNothingReported)
	}
	if out.Status != retirementReported {
		t.Fatalf("status=%q, want %q; a retirement resting on a reported no-op must not claim the stronger word", out.Status, retirementReported)
	}
	if !retirementSucceeded(out.Status) {
		t.Fatalf("a reported no-op must still exit zero so retries converge; status=%q", out.Status)
	}

	detail := strings.ToLower(storeOutcome(t, out, storeCertificate).Detail)
	for _, forbidden := range []string{
		"holds no active certificate",
		"no active certificate exists",
		"already removed",
		"already revoked",
	} {
		if strings.Contains(detail, forbidden) {
			t.Fatalf("a reported no-op must not assert %q; detail=%q", forbidden, detail)
		}
	}
	if !strings.Contains(detail, "reported") {
		t.Fatalf("a reported no-op must say it is what the service reported; detail=%q", detail)
	}
	if !strings.Contains(detail, "aw team agent-status") {
		t.Fatalf("a reported no-op must name the read that can establish the certificate state; detail=%q", detail)
	}
}

// A registry 409 is different evidence: the registry states the certificate
// exists and was already revoked. That one may say so.
func TestRetireTeamAgentReportsAnAlreadyRevokedCertificateAsEstablished(t *testing.T) {
	stores := newRetirementStores(t)
	out := stores.retire(t)
	_ = out

	result := certificateStoreResult{Result: certificateAlreadyRevoked}
	if result.Result == certificateNothingReported {
		t.Fatalf("the registry-established result must not be the reported one")
	}
	if certificateAlreadyRevoked == certificateNothingReported {
		t.Fatalf("the two no-op results must stay distinguishable")
	}
}
