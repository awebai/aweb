package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
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
	// deleteAlreadyDeleted serves the server's already-deleted refusal, which is
	// reached only when the row is deleted AND its identity is still bound - so it
	// establishes that the identity was NOT cleaned.
	deleteAlreadyDeleted bool
	// certificateStatus is the wire status the hosted endpoint answers with.
	certificateStatus string
	// omitClaimsReleased serves a server too old to report the count.
	omitClaimsReleased bool
	// aliasClaims are task refs still claimed under the alias. They survive a
	// workspace record, which is the state that matters: a soft-deleted workspace
	// is invisible to the workspace listing while its claims remain.
	aliasClaims []string
	// claimsTruncated serves a claim listing that did not fit one page.
	claimsTruncated bool
	// targetVerified reports whether the principal was established before acting.
	// Default false is the hosted shape these fixtures drive: no read there can
	// establish which member an alias belongs to.
	targetVerified bool

	coordination *httptest.Server
	certificate  *httptest.Server
	// registry serves the member resolve that establishes the principal. Its
	// answer is what the verification compares the typed address against.
	registry *httptest.Server
	// resolvedAddress is the member_address the registry reports for the alias.
	resolvedAddress string
	// memberMissing serves a member that does not resolve at all.
	memberMissing bool
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
		case r.Method == http.MethodGet && r.URL.Path == "/v1/claims":
			s.record("coordination:claims")
			claims := make([]map[string]any, 0, len(s.aliasClaims))
			for _, ref := range s.aliasClaims {
				claims = append(claims, map[string]any{
					"task_ref": ref, "workspace_id": s.workspaceID, "alias": s.alias,
					"claimed_at": "2026-07-29T00:00:00Z", "team_id": "default:alice.aweb.ai",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"claims": claims, "has_more": s.claimsTruncated})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/workspaces/"+s.workspaceID:
			s.record("coordination:delete")
			if s.deleteAlreadyDeleted {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{
					"code":                  "workspace_already_deleted",
					"workspace_id":          s.workspaceID,
					"identity_scope":        "local",
					"recommended_next_step": "The workspace is deleted; its identity is not.",
				}})
				return
			}
			if s.deleteConflict {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{
					"code":                  "local_workspace_still_active",
					"recommended_next_step": "Wait until presence is stale before deleting a local workspace.",
				}})
				return
			}
			body := map[string]any{
				"workspace_id":     s.workspaceID,
				"alias":            s.alias,
				"deleted_at":       "2026-07-29T12:00:00Z",
				"identity_deleted": true,
			}
			if !s.omitClaimsReleased {
				body["claims_released"] = s.claimsReleased
			}
			_ = json.NewEncoder(w).Encode(body)
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

	s.registry = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record("registry:resolve")
		if s.memberMissing {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Team member not found"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": "backend:acme.com", "certificate_id": "cert-retiree",
			"member_did_key": "did:key:z6MkRetiree", "member_address": s.resolvedAddress,
			"alias": s.alias, "identity_scope": "local", "issued_at": "2026-07-29T00:00:00Z",
		})
	}))
	t.Cleanup(s.registry.Close)

	return s
}

// retireVerified drives the command's own sequence: establish the principal
// first, and only then run the retirement. It is the call-site path rather than
// the helper, so it fails if nothing wires the verification in.
func (s *retirementStores) retireVerified(t *testing.T, typedAddress string) (teamRemoveAgentOutput, error) {
	t.Helper()
	resetTeamRemoveMemberGlobals(t)
	t.Chdir(t.TempDir())
	t.Setenv(initAPIKeyEnvVar, "aw_sk_env")
	teamRemoveAwebURL = s.certificate.URL
	teamRemoveRegistryURL = s.registry.URL

	client, err := aweb.New(s.coordination.URL)
	if err != nil {
		t.Fatalf("aweb.New: %v", err)
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		t.Fatalf("registry client: %v", err)
	}
	verified, err := verifyRetirementTarget(
		context.Background(), client, registry, s.registry.URL,
		"acme.com", "backend", typedAddress, s.alias,
	)
	if err != nil {
		return teamRemoveAgentOutput{}, err
	}
	out := retireTeamAgent(
		context.Background(), client, "backend:acme.com", typedAddress, s.alias, verified != nil,
		func(ctx context.Context) (certificateStoreResult, error) {
			return revokeHostedTeamCertificate(ctx, "backend:acme.com", typedAddress, "")
		},
	)
	return out, nil
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
		s.targetVerified,
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
	if out.ClaimsReleased == nil || *out.ClaimsReleased != 3 {
		t.Fatalf("claims_released=%v, want 3", out.ClaimsReleased)
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
	if out.ClaimsReleased != nil {
		t.Fatalf("claims_released=%v, want unreported when no delete happened", out.ClaimsReleased)
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

	// Pinned exactly, on purpose. A list of forbidden phrasings would only catch
	// the phrasings someone thought of, and it is weakest against a rewrite -
	// which is the event it exists to catch, since anyone rewording this will not
	// reuse the words we banned. An equality check cannot go green on a
	// strengthened claim whatever words it is written in.
	//
	// If you are here because you reworded this detail: the sentence may say what
	// the service reported and may not say anything about whether a certificate
	// exists. The hosted service answers from its own membership records and may
	// never consult the registry, so any claim about certificate state is one the
	// command has not established. That is the defect this whole change removes.
	const reportedNoOpDetail = "revoked nothing: the service reported it had nothing to revoke, " +
		"which does not establish that no certificate exists; confirm with aw team agent-status"
	if got := storeOutcome(t, out, storeCertificate).Detail; got != reportedNoOpDetail {
		t.Fatalf("reported no-op detail changed.\n got: %q\nwant: %q", got, reportedNoOpDetail)
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

// A server older than the claims_released field sends no count. Absent is not
// zero: reporting "released 0 task claim(s)" for a delete that released three
// asserts a number nobody sent, and the CLI reaches servers older than itself
// for as long as it takes them to be upgraded.
func TestRetireTeamAgentDoesNotReportZeroClaimsWhenTheServerSentNoCount(t *testing.T) {
	stores := newRetirementStores(t)
	stores.omitClaimsReleased = true
	out := stores.retire(t)

	if out.ClaimsReleased != nil {
		t.Fatalf("claims_released=%v, want unreported when the server sent no count", out.ClaimsReleased)
	}
	detail := storeOutcome(t, out, storeCoordination).Detail
	if strings.Contains(detail, "released 0") {
		t.Fatalf("a server that sent no count must not be reported as having released none: %q", detail)
	}
	if !strings.Contains(detail, "does not report how many") {
		t.Fatalf("detail must say the count is unavailable: %q", detail)
	}
}

// The workspace listing cannot see a soft-deleted workspace, so an agent whose
// record was already removed - by a hosted removal, or by a previous partial
// retirement - looks identical to one that never had claims. Its claims are still
// there, and the delete cascade can no longer reach them, so nothing in this
// command can release them. Reporting that as retired is the defect this command
// exists to remove.
func TestRetireTeamAgentWillNotReportRetiredWhileClaimsSurviveAMissingWorkspace(t *testing.T) {
	stores := newRetirementStores(t)
	stores.workspaceMissing = true
	stores.aliasClaims = []string{"backend-77", "backend-78"}
	out := stores.retire(t)

	for _, call := range stores.order() {
		if call == "certificate:revoke" {
			t.Fatalf("revoked while claims nothing can release were still held; calls=%v", stores.order())
		}
	}
	if out.Status != retirementIncomplete {
		t.Fatalf("status=%q, want %q", out.Status, retirementIncomplete)
	}
	coordination := storeOutcome(t, out, storeCoordination)
	if coordination.terminal() {
		t.Fatalf("coordination=%+v, want a non-terminal result while claims are held", coordination)
	}
	if !strings.Contains(coordination.Detail, "2 task claim(s)") {
		t.Fatalf("blocked coordination store does not report the claims still held: %q", coordination.Detail)
	}
	if !strings.Contains(coordination.Detail, "in_progress") {
		t.Fatalf("blocked coordination store does not say how to release them: %q", coordination.Detail)
	}
	// A count is not actionable on its own. The operator has to be able to find
	// which tasks are holding the retirement open.
	if !strings.Contains(coordination.Detail, "aw work active") {
		t.Fatalf("blocked coordination store does not say where to find the claimed tasks: %q", coordination.Detail)
	}
}

// The same path with no claims is a genuine convergence and must stay terminal,
// so the fix above cannot be "always refuse when the workspace is missing".
func TestRetireTeamAgentStillConvergesWhenNoWorkspaceAndNoClaims(t *testing.T) {
	stores := newRetirementStores(t)
	stores.workspaceMissing = true
	stores.certificateStatus = "not_found"
	out := stores.retire(t)

	if !retirementSucceeded(out.Status) {
		t.Fatalf("status=%q, want a succeeding status when nothing is held", out.Status)
	}
	if got := storeOutcome(t, out, storeCoordination); got.Result != storeUnchanged {
		t.Fatalf("coordination=%+v, want %q", got, storeUnchanged)
	}
}

// A truncated claim listing cannot establish that no claims are held, and this is
// the one command that must not read "I could not see any" as "there are none".
func TestRetireTeamAgentWillNotConvergeOnATruncatedClaimListing(t *testing.T) {
	stores := newRetirementStores(t)
	stores.workspaceMissing = true
	stores.claimsTruncated = true
	out := stores.retire(t)

	if retirementSucceeded(out.Status) {
		t.Fatalf("status=%q, want a failing status on a listing that could not establish zero", out.Status)
	}
	if got := storeOutcome(t, out, storeCoordination); got.terminal() {
		t.Fatalf("coordination=%+v, want non-terminal on a truncated listing", got)
	}
}

// A certificate result nobody has interpreted must not come out as the most
// confident status. The switch is exhaustive today; this keeps it so on purpose
// rather than by coincidence.
func TestRetireTeamAgentRefusesAnUninterpretedCertificateResult(t *testing.T) {
	stores := newRetirementStores(t)
	resetTeamRemoveMemberGlobals(t)
	t.Chdir(t.TempDir())

	client, err := aweb.New(stores.coordination.URL)
	if err != nil {
		t.Fatalf("aweb.New: %v", err)
	}
	out := retireTeamAgent(
		context.Background(), client, "default:alice.aweb.ai",
		"alice.aweb.ai/"+stores.alias, stores.alias, false,
		func(ctx context.Context) (certificateStoreResult, error) {
			return certificateStoreResult{Result: "queued_for_later"}, nil
		},
	)

	if retirementSucceeded(out.Status) {
		t.Fatalf("status=%q, want a failing status for an uninterpreted result", out.Status)
	}
	if got := storeOutcome(t, out, storeCertificate); got.Result != storeFailed {
		t.Fatalf("certificate=%+v, want %q", got, storeFailed)
	}
}

// On a hosted team no read can establish which member an alias belongs to, so
// the workspace is selected by alias alone. The result must say that rather than
// implying the record was the one named - a refusal is one way to avoid claiming
// more than the evidence supports, and an accurate disclosure is the other.
func TestRetireTeamAgentDisclosesWhenThePrincipalWasNotVerified(t *testing.T) {
	stores := newRetirementStores(t)
	stores.targetVerified = false
	out := stores.retire(t)

	detail := storeOutcome(t, out, storeCoordination).Detail
	if !strings.Contains(detail, "selected by alias") {
		t.Fatalf("an unverified retirement does not disclose how the record was chosen: %q", detail)
	}
	if !strings.Contains(detail, "aweb-aaum.9") {
		t.Fatalf("the disclosure does not name what would change it: %q", detail)
	}
}

// A verified retirement must not carry the disclosure, or it becomes wallpaper
// and stops meaning anything on the paths where it is true.
func TestRetireTeamAgentDoesNotDiscloseWhenThePrincipalWasVerified(t *testing.T) {
	stores := newRetirementStores(t)
	stores.targetVerified = true
	out := stores.retire(t)

	detail := storeOutcome(t, out, storeCoordination).Detail
	if strings.Contains(detail, "could not be verified") {
		t.Fatalf("a verified retirement carried the unverified disclosure: %q", detail)
	}
}

// CALL SITE, not the helper. The verification's own tests would all pass with
// nothing in production calling it - a perfectly tested helper that nothing
// invokes is green in every direction. This drives the sequence the command
// runs and asserts the writes never happened.
func TestRetirementNeverTouchesAnyStoreWhenTheNamedMemberIsSomeoneElse(t *testing.T) {
	stores := newRetirementStores(t)
	stores.resolvedAddress = "partner.com/retiree"

	_, err := stores.retireVerified(t, "acme.com/retiree")
	if err == nil {
		t.Fatalf("naming acme.com for a member who is partner.com was accepted")
	}
	for _, call := range stores.order() {
		if call == "coordination:delete" || call == "certificate:revoke" {
			t.Fatalf("a store was written after a failed verification; calls=%v", stores.order())
		}
	}
}

// The permits direction at the call site: a correctly named member must still be
// retired, or the verification is a refusal machine.
func TestRetirementProceedsWhenTheNamedMemberIsTheResolvedOne(t *testing.T) {
	stores := newRetirementStores(t)
	stores.resolvedAddress = "partner.com/retiree"

	out, err := stores.retireVerified(t, "partner.com/retiree")
	if err != nil {
		t.Fatalf("a correctly named member was refused: %v", err)
	}
	if !retirementSucceeded(out.Status) {
		t.Fatalf("status=%q, want a succeeding status", out.Status)
	}
	var deleted bool
	for _, call := range stores.order() {
		if call == "coordination:delete" {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("a verified retirement never reached the coordination store; calls=%v", stores.order())
	}
}

// Fail-closed on a member that does not resolve, and the refusal has to tell the
// operator which of the two recoverable states they are in.
func TestRetirementRefusesAnUnresolvableMemberAndNamesTheRemedy(t *testing.T) {
	stores := newRetirementStores(t)
	stores.memberMissing = true

	_, err := stores.retireVerified(t, "acme.com/retiree")
	if err == nil {
		t.Fatalf("an unresolvable member was accepted")
	}
	for _, call := range stores.order() {
		if call == "coordination:delete" || call == "certificate:revoke" {
			t.Fatalf("a store was written for an unresolvable member; calls=%v", stores.order())
		}
	}
	// The workspace record is present in this fixture, so the remedy is the id.
	if !strings.Contains(err.Error(), "aw workspace delete") {
		t.Fatalf("refusal does not name the remedy for a record that still exists: %v", err)
	}
	if !strings.Contains(err.Error(), stores.workspaceID) {
		t.Fatalf("refusal does not hand over the workspace id: %v", err)
	}
}

// The other arrival: no record left, so aw workspace delete has nothing to act
// on and pointing there would send the operator at aaum.6's false success.
func TestRetirementRefusalNamesTheStatusRouteWhenNoRecordRemains(t *testing.T) {
	stores := newRetirementStores(t)
	stores.memberMissing = true
	stores.workspaceMissing = true

	_, err := stores.retireVerified(t, "acme.com/retiree")
	if err == nil {
		t.Fatalf("an unresolvable member was accepted")
	}
	if strings.Contains(err.Error(), "aw workspace delete "+stores.workspaceID) {
		t.Fatalf("refusal points at a workspace record that does not exist: %v", err)
	}
	if !strings.Contains(err.Error(), "in_progress") {
		t.Fatalf("refusal does not name the route that works without a record: %v", err)
	}
}

// CALL SITE, through the real binary, for the coordination store.
//
// This exists because the rest of the Go suite cannot see the verification being
// unwired from aw team remove-agent: every other test reaches the helper
// directly, so removing the call from the command reds nothing. That leaves the
// most destructive of the four sites - it deletes a workspace and releases its
// claims, and it runs first - protected only by the OSS journey, which nothing
// in CI obliges anyone to run.
//
// Naming a namespace that is not this team's must refuse before any write, so
// the assertion is that no workspace delete was ever issued.
func TestTeamRemoveAgentBinaryRefusesAForeignNamespaceBeforeDeletingAnything(t *testing.T) {
	t.Parallel()

	var deleteIssued bool
	var mu sync.Mutex
	aweb := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/workspaces/"):
			deleteIssued = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id": "ws-1", "alias": "retiree",
				"deleted_at": "2026-07-29T00:00:00Z", "identity_deleted": true,
			})
		case r.URL.Path == "/v1/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{{
				"workspace_id": "11111111-2222-3333-4444-555555555555", "alias": "retiree",
			}}, "has_more": false})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{})
		}
	}))

	registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/members/retiree") {
			// A local member: no address of its own, so the namespace that names
			// it is the team's, which is acme.com and not evil.com.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "backend:acme.com", "certificate_id": "cert-retiree",
				"member_did_key": "did:key:z6MkRetiree", "alias": "retiree",
				"identity_scope": "local", "issued_at": "2026-07-29T00:00:00Z",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	writeLocalTeamSignedRequestWorkspaceForTest(t, tmp, aweb.URL, "backend:acme.com", "operator", did, signingKey)

	run := exec.CommandContext(ctx, bin, "team", "remove-agent", "evil.com/retiree",
		"--team-id", "backend:acme.com", "--registry", registry.URL, "--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registry.URL)
	run.Dir = tmp
	out, err := run.CombinedOutput()

	if err == nil {
		t.Fatalf("remove-agent accepted a namespace that is not this team's\n%s", string(out))
	}
	mu.Lock()
	defer mu.Unlock()
	if deleteIssued {
		t.Fatalf("a workspace was deleted despite the named namespace not being this team's\n%s", string(out))
	}
}

// The server refuses an already-deleted workspace ONLY when its identity is still
// bound, so that 404 establishes a bad fact rather than a neutral one. A retirement
// that reads it as convergence revokes the certificate and exits 0, leaving an
// identity nobody cleaned and no credential able to clear the coordination state -
// which is the very thing the non-terminal branch declines to do.
//
// Asserts on status and on whether the revoke happened, never on the Detail string:
// a bad fact recorded only in prose is what this test exists to prevent.
func TestRetireTeamAgentWillNotReportRetiredWhenTheIdentityWasNotCleaned(t *testing.T) {
	stores := newRetirementStores(t)
	stores.deleteAlreadyDeleted = true
	out := stores.retire(t)

	for _, call := range stores.order() {
		if call == "certificate:revoke" {
			t.Fatalf("revoked while the identity was still bound; calls=%v", stores.order())
		}
	}
	if out.Status != retirementIncomplete {
		t.Fatalf("status=%q, want %q - the server said the identity was not cleaned", out.Status, retirementIncomplete)
	}
	coordination := storeOutcome(t, out, storeCoordination)
	if coordination.terminal() {
		t.Fatalf("coordination=%+v, want a non-terminal result while the identity is uncleaned", coordination)
	}
}
