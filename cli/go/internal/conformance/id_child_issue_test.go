package conformance_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type idChildIssueCase struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Input  struct {
		Request               string   `json:"request"`
		Mode                  string   `json:"mode"`
		Parent                string   `json:"parent"`
		InvitationID          string   `json:"invitation_id"`
		Recipient             string   `json:"recipient"`
		InvitationLive        bool     `json:"invitation_live"`
		Interactive           bool     `json:"interactive"`
		AgentRun              bool     `json:"agent_run"`
		AutoApprove           string   `json:"auto_approve"`
		Confirmed             bool     `json:"confirmed"`
		IssuedAt              string   `json:"issued_at"`
		SelectedParent        string   `json:"selected_parent"`
		PriorRequest          string   `json:"prior_request"`
		PriorState            string   `json:"prior_state"`
		PriorResponse         string   `json:"prior_response"`
		SameRequestID         bool     `json:"same_request_id"`
		Changed               string   `json:"changed"`
		ParentStatusAfterWait string   `json:"parent_status_after_wait"`
		StoredRequests        []string `json:"stored_requests"`
	} `json:"input"`
	Expected struct {
		Accepted                    bool     `json:"accepted"`
		Reason                      string   `json:"reason"`
		RequestState                string   `json:"request_state"`
		Response                    string   `json:"response"`
		ParentSignatures            *int     `json:"parent_signatures"`
		Writes                      *int     `json:"writes"`
		NewStores                   *int     `json:"new_stores"`
		InvitationVoid              bool     `json:"invitation_void"`
		PreviousIssuedBytesRetained bool     `json:"previous_issued_bytes_retained"`
		IssuanceRecordedBeforeOut   bool     `json:"issuance_recorded_before_output"`
		RequestIDs                  []string `json:"request_ids"`
		IssuedCertificateIDVisible  bool     `json:"issued_certificate_id_visible"`
		InvitationVoidVisible       bool     `json:"invitation_void_visible"`
		IssuedResponseRetrievable   bool     `json:"issued_response_retrievable"`
	} `json:"expected"`
}

// The issue-side frozen cases of the CSR exchange this library decides. The
// child's register retry is consumed with registration.
var idChildIssueCaseNames = []string{
	"csr-receive-stores-only-parent-local-invitation",
	"csr-parent-local-list-and-show",
	"csr-host-managed-mode-cannot-downgrade",
	"csr-bad-subject-proof-refuses",
	"csr-wrong-issuer-record-refuses",
	"csr-token-only-substituted-key-does-not-sign",
	"csr-noninteractive-approval-refuses",
	"csr-agent-run-approval-refuses",
	"csr-yes-flag-cannot-approve-human",
	"csr-declined-fingerprint-confirmation-refuses",
	"csr-human-exact-interactive-approval",
	"csr-byte-identical-retry-returns-exact-response",
	"csr-second-request-same-key-refuses",
	"csr-competing-keys-void-pending-invite",
	"csr-competing-key-after-approval-voids-invite",
	"csr-conflicting-request-id-refuses",
	"csr-refusal-issues-nothing",
	"csr-expired-invite-approval-refuses",
	"csr-parent-revoked-after-wait-refuses",
	"csr-root-human-exact-interactive-approval",
	"csr-root-human-agent-run-refuses",
	"csr-root-human-noninteractive-refuses",
	"csr-root-human-declined-confirmation-refuses",
}

// invitationStore is an in-memory invitation store. Records round-trip
// through JSON, as on disk.
type invitationStore struct {
	records map[string][]byte
	writes  int
}

func (s *invitationStore) Invitation(id string) (*awid.IDInvitation, error) {
	raw, ok := s.records[id]
	if !ok {
		return nil, nil
	}
	var inv awid.IDInvitation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (s *invitationStore) PutInvitation(inv *awid.IDInvitation) error {
	raw, err := json.Marshal(inv)
	if err != nil {
		return err
	}
	s.records[inv.InvitationID] = raw
	s.writes++
	return nil
}

func (s *invitationStore) Invitations() ([]*awid.IDInvitation, error) {
	ids := make([]string, 0, len(s.records))
	for id := range s.records {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []*awid.IDInvitation{}
	for _, id := range ids {
		inv, err := s.Invitation(id)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}

// issueRun is one issuer's local state for a frozen case: the invitation it
// fixed, its issuance log, its signer and the evidence its locked step sees.
type issueRun struct {
	x           idChildExchange
	invitations *invitationStore
	issuance    *issuedStore
	issuer      map[string]any
	parentChain []any
	status      string
	signer      string
	calls       int
	now         time.Time
}

func (x idChildExchange) issuerParent(name string) map[string]any {
	if name == "root" {
		return map[string]any{"kind": "namespace", "id": "example.com"}
	}
	return map[string]any{"kind": "identity", "id": x.v.Keys[name].DIDAW}
}

func (x idChildExchange) issueRun(t *testing.T, c idChildIssueCase) *issueRun {
	t.Helper()
	issuedAt := c.Input.IssuedAt
	if issuedAt == "" {
		issuedAt = "2026-10-26T00:02:00Z"
	}
	now, err := time.Parse(time.RFC3339, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Hour)
	if !c.Input.InvitationLive {
		expires = now.Add(-time.Second)
	}
	inv := &awid.IDInvitation{
		InvitationID: c.Input.InvitationID,
		Mode:         c.Input.Mode,
		Parent:       x.issuerParent(c.Input.Parent),
		Domain:       "example.com",
		Kind:         "human",
		Recipient:    c.Input.Recipient,
		ExpiresAt:    expires.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if len(c.Input.StoredRequests) > 0 {
		// A listing case names only its stored requests; their invitation is
		// the one each request names, fixed self-custodially for a recipient.
		inv.InvitationID = requestInvitationID(x, c.Input.StoredRequests[0])
		inv.Mode = awid.IDInvitationSelfCustodial
		inv.Recipient = "fixed privately"
	}
	r := &issueRun{x: x, invitations: &invitationStore{records: map[string][]byte{}}, issuance: newIssuedStore(t, x.v), issuer: inv.Parent, status: "normal", signer: c.Input.Parent, now: now}
	if c.Input.SelectedParent != "" {
		r.issuer = x.issuerParent(c.Input.SelectedParent)
	}
	if c.Input.ParentStatusAfterWait != "" {
		// The evidence that reaches the locked signing step is the one after the wait.
		r.status = c.Input.ParentStatusAfterWait
	}
	if c.Input.Parent != "root" {
		r.parentChain = x.parentChain(t, "normal", inv.Parent["id"].(string))
	}
	prior := c.Input.PriorRequest
	if c.Input.PriorResponse != "" && prior == "" {
		prior = c.Input.Request
	}
	if prior != "" {
		raw := x.requests[prior].CanonicalUTF8
		inv.Request = &awid.IDRequestRecord{RequestID: requestIDOf(t, raw), Request: raw, State: awid.IDRequestPending}
		response := c.Input.PriorResponse
		if c.Input.PriorState == awid.IDRequestIssued {
			response = "human-issued"
		}
		if response != "" {
			inv.Request.State = awid.IDRequestIssued
			inv.Request.Response = x.responses[response].CanonicalUTF8
			inv.Request.NewCertificateID = responseChildID(t, inv.Request.Response)
		}
	}
	if err := r.invitations.PutInvitation(inv); err != nil {
		t.Fatal(err)
	}
	r.invitations.writes = 0
	return r
}

func (r *issueRun) receive(raw string) (*awid.IDInvitation, error) {
	return awid.ReceiveIDChildRequest(r.invitations, r.issuer, []byte(raw))
}

func (r *issueRun) approve(t *testing.T, requestID string, approval awid.IDHumanApproval) ([]byte, error) {
	t.Helper()
	return awid.ApproveIDChildRequest(r.invitations, r.issuance, requestID, approval, r.parentChain, r.x.evidence(r.status), vectorSigner(t, r.x.v, r.signer, &r.calls), r.now)
}

func (r *issueRun) invitation(t *testing.T, id string) *awid.IDInvitation {
	t.Helper()
	inv, err := r.invitations.Invitation(id)
	if err != nil || inv == nil {
		t.Fatalf("invitation %s: %v", id, err)
	}
	return inv
}

func caseApproval(c idChildIssueCase) awid.IDHumanApproval {
	return awid.IDHumanApproval{
		Interactive: c.Input.Interactive,
		AgentRun:    c.Input.AgentRun,
		AutoApprove: c.Input.AutoApprove != "",
		Confirmed:   c.Input.Confirmed,
	}
}

func requestInvitationID(x idChildExchange, name string) string {
	return x.requests[name].Signed["request"].(map[string]any)["invitation_id"].(string)
}

func requestIDOf(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := awid.ParseIDCertificateRequest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return parsed["request"].(map[string]any)["request_id"].(string)
}

func responseChildID(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := awid.ParseIDCertificateResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	certificates := parsed["chain"].(map[string]any)["certificates"].([]any)
	id, err := awid.IDCertificateID(certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// caseRequest is the request bytes the case presents. A changed field under
// the prior request's id is re-signed by the same child key.
func (x idChildExchange) caseRequest(t *testing.T, c idChildIssueCase) string {
	t.Helper()
	raw := x.requests[c.Input.Request].CanonicalUTF8
	if c.Input.Changed == "" {
		return raw
	}
	parsed, err := awid.ParseIDCertificateRequest([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{}
	for k, v := range parsed["request"].(map[string]any) {
		request[k] = v
	}
	if c.Input.Changed != "domain" {
		t.Fatalf("unhandled changed field %q", c.Input.Changed)
	}
	request["domain"] = "example.org"
	return signRequest(t, x.v, "bob", request)
}

func loadIDChildIssueCases(t *testing.T) map[string]idChildIssueCase {
	t.Helper()
	var all struct {
		Cases []json.RawMessage `json:"operation_cases"`
	}
	if err := json.Unmarshal(readRootVector(t, "id-certificates-v1.json"), &all); err != nil {
		t.Fatal(err)
	}
	cases := map[string]idChildIssueCase{}
	for _, item := range all.Cases {
		var named struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(item, &named); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(named.Name, "csr-") {
			continue
		}
		var c idChildIssueCase
		if err := json.Unmarshal(item, &c); err != nil {
			t.Fatalf("%s: %v", named.Name, err)
		}
		cases[c.Name] = c
	}
	return cases
}

func TestIDChildIssueFrozenCases(t *testing.T) {
	x := loadIDChildExchange(t)
	raw := loadIDChildIssueCases(t)
	for _, name := range idChildIssueCaseNames {
		c, ok := raw[name]
		if !ok {
			t.Fatalf("missing frozen case %s", name)
		}
		t.Run(name, func(t *testing.T) {
			r := x.issueRun(t, c)
			request := x.caseRequest(t, c)
			var response []byte
			var err error
			switch c.Action {
			case "child_request_receive":
				before, _ := r.invitations.Invitations()
				_, err = r.receive(request)
				after, _ := r.invitations.Invitations()
				if c.Expected.NewStores != nil && len(after)-len(before) != *c.Expected.NewStores {
					t.Fatalf("receive created %d records", len(after)-len(before))
				}
			case "child_request_approve":
				if c.Input.PriorResponse == "" {
					if _, err = r.receive(request); err != nil {
						t.Fatalf("receive: %v", err)
					}
					r.invitations.writes = 0
				}
				response, err = r.approve(t, requestIDOf(t, request), caseApproval(c))
			case "child_request_refuse":
				if _, err = r.receive(request); err != nil {
					t.Fatalf("receive: %v", err)
				}
				err = awid.RefuseIDChildRequest(r.invitations, requestIDOf(t, request))
			case "child_request_list":
				for _, stored := range c.Input.StoredRequests {
					if _, err = r.receive(x.requests[stored].CanonicalUTF8); err != nil {
						t.Fatalf("receive: %v", err)
					}
				}
				listed, err := awid.IDChildRequests(r.invitations)
				if err != nil {
					t.Fatal(err)
				}
				ids := []string{}
				for _, l := range listed {
					ids = append(ids, l.RequestID)
				}
				if strings.Join(ids, ",") != strings.Join(c.Expected.RequestIDs, ",") {
					t.Fatalf("listed %v want %v", ids, c.Expected.RequestIDs)
				}
				exported, err := json.Marshal(listed)
				if err != nil {
					t.Fatal(err)
				}
				// No private recipient, child key or request bytes leave the issuer's records.
				for _, secret := range []string{r.invitation(t, requestInvitationID(x, c.Input.StoredRequests[0])).Recipient, x.v.Keys["bob"].DIDKey, x.requests["human-issue"].Signed["signature"].(string)} {
					if secret == "" {
						t.Fatal("empty secret to look for")
					}
					if strings.Contains(string(exported), secret) {
						t.Fatalf("list exports %q:\n%s", secret, exported)
					}
				}
				return
			default:
				t.Fatalf("unhandled action %s", c.Action)
			}
			if c.Expected.ParentSignatures != nil && r.calls != *c.Expected.ParentSignatures {
				t.Fatalf("signer calls=%d want %d", r.calls, *c.Expected.ParentSignatures)
			}
			if c.Expected.Writes != nil && r.invitations.writes+r.issuance.writes != *c.Expected.Writes {
				t.Fatalf("writes=%d want %d", r.invitations.writes+r.issuance.writes, *c.Expected.Writes)
			}
			inv := r.invitation(t, c.Input.InvitationID)
			if c.Expected.RequestState != "" && (inv.Request == nil || inv.Request.State != c.Expected.RequestState) {
				t.Fatalf("request state %+v want %s", inv.Request, c.Expected.RequestState)
			}
			if inv.Void != c.Expected.InvitationVoid {
				t.Fatalf("invitation void=%v want %v", inv.Void, c.Expected.InvitationVoid)
			}
			if c.Expected.PreviousIssuedBytesRetained && c.Input.PriorState == awid.IDRequestIssued && inv.Request.Response != x.responses["human-issued"].CanonicalUTF8 {
				t.Fatal("voiding dropped the issued response")
			}
			if c.Expected.IssuedCertificateIDVisible || c.Expected.InvitationVoidVisible {
				listed, err := awid.IDChildRequests(r.invitations)
				if err != nil || len(listed) != 1 {
					t.Fatalf("listed %v (%v)", listed, err)
				}
				if c.Expected.IssuedCertificateIDVisible && (listed[0].CertificateID == "" || listed[0].CertificateID != inv.Request.NewCertificateID) {
					t.Fatalf("listed certificate id %q want %q", listed[0].CertificateID, inv.Request.NewCertificateID)
				}
				if c.Expected.InvitationVoidVisible && !listed[0].InvitationVoid {
					t.Fatal("the list does not show the invitation void")
				}
			}
			if c.Expected.IssuedResponseRetrievable {
				calls := r.calls
				retried, err := r.approve(t, inv.Request.RequestID, awid.IDHumanApproval{})
				if err != nil || string(retried) != inv.Request.Response || r.calls != calls {
					t.Fatalf("retry after void: err=%v calls=%d", err, r.calls-calls)
				}
				if after := r.invitation(t, c.Input.InvitationID); !after.Void || after.Request.State != awid.IDRequestIssued {
					t.Fatalf("retry changed the record: void=%v state=%s", after.Void, after.Request.State)
				}
			}
			if c.Action == "child_request_refuse" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !c.Expected.Accepted {
				if got := awid.IDCertificateErrorCode(err); got != c.Expected.Reason || response != nil {
					t.Fatalf("reason=%q (%v) want %q", got, err, c.Expected.Reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.Expected.Response != "" && string(response) != x.responses[c.Expected.Response].CanonicalUTF8 {
				t.Fatalf("response differs from frozen %s:\n%s", c.Expected.Response, response)
			}
			if c.Expected.IssuanceRecordedBeforeOut && !r.issuance.has(responseChildID(t, string(response))) {
				t.Fatal("the issued certificate was not recorded before output")
			}
		})
	}
}

// An interactive, confirmed approval that passes the human gate.
var fullHumanApproval = awid.IDHumanApproval{Interactive: true, Confirmed: true}

// agentIssue is an issue invitation for an agent child, with the child's
// request signed by its own key.
func (x idChildExchange) agentIssue(t *testing.T, parent []string, child, kind string) (*issueRun, string) {
	t.Helper()
	now, err := time.Parse(time.RFC3339, "2026-10-26T00:02:00Z")
	if err != nil {
		t.Fatal(err)
	}
	issuer := x.issuerParent(parent[len(parent)-1])
	inv := &awid.IDInvitation{InvitationID: "10000000-0000-4000-8000-0000000000a1", Mode: "self_custodial", Parent: issuer, Domain: "example.com", Kind: kind, Recipient: "fixed privately", ExpiresAt: now.Add(time.Hour).UTC().Format("2006-01-02T15:04:05Z")}
	r := &issueRun{x: x, invitations: &invitationStore{records: map[string][]byte{}}, issuance: newIssuedStore(t, x.v), issuer: issuer, status: "normal", signer: parent[len(parent)-1], now: now}
	for _, ancestor := range parent {
		r.parentChain = append(r.parentChain, x.parentChain(t, "normal", x.v.Keys[ancestor].DIDAW)...)
	}
	if err := r.invitations.PutInvitation(inv); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"v": json.Number("1"), "type": "aweb.id-certificate-request", "request_id": "20000000-0000-4000-8000-0000000000a1", "operation": "issue",
		"id": x.v.Keys[child].DIDAW, "domain": "example.com", "parent": issuer, "kind": kind, "subject_key": x.v.Keys[child].DIDKey,
		"invitation_id": inv.InvitationID, "old_certificate": nil,
	}
	return r, signRequest(t, x.v, child, request)
}

// An agent child is issued over the exchange with the ordinary invitation,
// child proof and parent checks, and no human fingerprint ceremony; an agent
// parent never issues a human (contract §6, R1).
func TestIDChildIssueByChildKind(t *testing.T) {
	x := loadIDChildExchange(t)
	for _, tc := range []struct {
		name   string
		parent []string
		child  string
	}{
		{"human-issues-agent", []string{"alice"}, "bob_agent"},
		{"agent-issues-agent", []string{"alice", "global_agent"}, "child_of_global"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, request := x.agentIssue(t, tc.parent, tc.child, "agent")
			if _, err := r.receive(request); err != nil {
				t.Fatal(err)
			}
			response, err := r.approve(t, "20000000-0000-4000-8000-0000000000a1", awid.IDHumanApproval{})
			if err != nil {
				t.Fatal(err)
			}
			if r.calls != 1 || !r.issuance.has(responseChildID(t, string(response))) {
				t.Fatalf("calls=%d, recorded=%v", r.calls, r.issuance.has(responseChildID(t, string(response))))
			}
			parsed, err := awid.ParseIDCertificateResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			certificates := parsed["chain"].(map[string]any)["certificates"].([]any)
			if len(certificates) != len(r.parentChain)+1 {
				t.Fatalf("chain has %d certificates", len(certificates))
			}
			c := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
			if c["id"] != x.v.Keys[tc.child].DIDAW || c["kind"] != "agent" || c["issuer_key"] != x.v.Keys[tc.parent[len(tc.parent)-1]].DIDKey {
				t.Fatalf("issued %v", c)
			}
			if inv := r.invitation(t, "10000000-0000-4000-8000-0000000000a1"); inv.Request.State != awid.IDRequestIssued {
				t.Fatalf("request state %s", inv.Request.State)
			}
		})
	}

	t.Run("agent-cannot-issue-human", func(t *testing.T) {
		r, request := x.agentIssue(t, []string{"alice", "global_agent"}, "replacement_human", "human")
		if _, err := r.receive(request); err != nil {
			t.Fatal(err)
		}
		response, err := r.approve(t, "20000000-0000-4000-8000-0000000000a1", fullHumanApproval)
		if got := awid.IDCertificateErrorCode(err); got != "human_issuer_is_agent" || response != nil || r.calls != 0 {
			t.Fatalf("reason=%q (%v) calls=%d", got, err, r.calls)
		}
	})

	t.Run("human-child-still-needs-the-confirmation", func(t *testing.T) {
		r, request := x.agentIssue(t, []string{"alice"}, "replacement_human", "human")
		if _, err := r.receive(request); err != nil {
			t.Fatal(err)
		}
		response, err := r.approve(t, "20000000-0000-4000-8000-0000000000a1", awid.IDHumanApproval{})
		if got := awid.IDCertificateErrorCode(err); got != "human_approval_required" || response != nil || r.calls != 0 {
			t.Fatalf("reason=%q (%v) calls=%d", got, err, r.calls)
		}
	})
}

// Single-fault probes for issue rules the frozen cases don't isolate. Each
// starts from an accepted frozen exchange and changes one thing.
func TestIDChildIssueProbes(t *testing.T) {
	x := loadIDChildExchange(t)
	cases := loadIDChildIssueCases(t)
	human := cases["csr-human-exact-interactive-approval"]
	root := cases["csr-root-human-exact-interactive-approval"]
	humanRequest := x.requests["human-issue"].CanonicalUTF8
	humanID := requestIDOf(t, humanRequest)
	rootID := requestIDOf(t, x.requests["root-human-issue"].CanonicalUTF8)
	approved := fullHumanApproval

	// variant re-signs the human request with one field changed under a new request id.
	variant := func(t *testing.T, key string, base string, changes map[string]any) string {
		t.Helper()
		parsed, err := awid.ParseIDCertificateRequest([]byte(x.requests[base].CanonicalUTF8))
		if err != nil {
			t.Fatal(err)
		}
		request := map[string]any{}
		for k, v := range parsed["request"].(map[string]any) {
			request[k] = v
		}
		request["request_id"] = "20000000-0000-4000-8000-0000000000b1"
		for k, v := range changes {
			request[k] = v
		}
		return signRequest(t, x.v, key, request)
	}
	refused := func(t *testing.T, err error, reason string) {
		t.Helper()
		if got := awid.IDCertificateErrorCode(err); got != reason {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
	}

	for field, value := range map[string]any{
		"parent": x.issuerParent("bob"),
		"domain": "example.org",
		"kind":   "agent",
	} {
		t.Run("request "+field+" differs from the invitation", func(t *testing.T) {
			r := x.issueRun(t, human)
			_, err := r.receive(variant(t, "bob", "human-issue", map[string]any{field: value}))
			refused(t, err, "request_binding_mismatch")
			if r.invitations.writes != 0 || r.invitation(t, human.Input.InvitationID).Request != nil {
				t.Fatal("a mismatched request was bound")
			}
		})
	}

	t.Run("a request id bound to one invitation is refused for another", func(t *testing.T) {
		r := x.issueRun(t, human)
		if _, err := r.receive(humanRequest); err != nil {
			t.Fatal(err)
		}
		other := *r.invitation(t, human.Input.InvitationID)
		other.InvitationID, other.Request = "10000000-0000-4000-8000-0000000000c1", nil
		if err := r.invitations.PutInvitation(&other); err != nil {
			t.Fatal(err)
		}
		r.invitations.writes = 0
		_, err := r.receive(variant(t, "bob", "human-issue", map[string]any{"request_id": humanID, "invitation_id": other.InvitationID}))
		refused(t, err, "request_conflict")
		if r.invitations.writes != 0 || r.invitation(t, other.InvitationID).Request != nil {
			t.Fatal("a second invitation took a request id already bound")
		}
	})

	t.Run("a void invitation refuses every later request and approval", func(t *testing.T) {
		r := x.issueRun(t, human)
		if _, err := r.receive(humanRequest); err != nil {
			t.Fatal(err)
		}
		_, err := r.receive(x.requests["human-second-key"].CanonicalUTF8)
		refused(t, err, "invitation_conflict")
		r.invitations.writes = 0
		_, err = r.receive(x.requests["human-second-request-same-key"].CanonicalUTF8)
		refused(t, err, "invitation_conflict")
		if r.invitations.writes != 0 {
			t.Fatalf("writes=%d", r.invitations.writes)
		}
		response, err := r.approve(t, humanID, approved)
		refused(t, err, "invitation_conflict")
		if response != nil || r.calls != 0 {
			t.Fatal("a void invitation signed")
		}
	})

	for name, approval := range map[string]awid.IDHumanApproval{
		"--yes with an otherwise full approval": {Interactive: true, AutoApprove: true, Confirmed: true},
		"no confirmation":                       {Interactive: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := x.issueRun(t, human)
			if _, err := r.receive(humanRequest); err != nil {
				t.Fatal(err)
			}
			response, err := r.approve(t, humanID, approval)
			refused(t, err, "human_approval_required")
			if inv := r.invitation(t, human.Input.InvitationID); response != nil || r.calls != 0 || inv.Void || inv.Request.State != awid.IDRequestPending {
				t.Fatalf("calls=%d void=%v state=%s", r.calls, inv.Void, inv.Request.State)
			}
		})
	}

	t.Run("the parent chain must end in the parent", func(t *testing.T) {
		r := x.issueRun(t, human)
		if _, err := r.receive(humanRequest); err != nil {
			t.Fatal(err)
		}
		r.parentChain = x.parentChain(t, "normal", x.v.Keys["bob"].DIDAW)
		if response, err := r.approve(t, humanID, approved); err == nil || response != nil || r.calls != 0 {
			t.Fatalf("err=%v calls=%d", err, r.calls)
		}
	})

	t.Run("an issued request cannot be refused", func(t *testing.T) {
		r := x.issueRun(t, human)
		if _, err := r.receive(humanRequest); err != nil {
			t.Fatal(err)
		}
		if _, err := r.approve(t, humanID, approved); err != nil {
			t.Fatal(err)
		}
		if err := awid.RefuseIDChildRequest(r.invitations, humanID); err == nil {
			t.Fatal("refused an issued request")
		}
		if state := r.invitation(t, human.Input.InvitationID).Request.State; state != awid.IDRequestIssued {
			t.Fatalf("state=%s", state)
		}
	})

	t.Run("an invitation with no request is not listed", func(t *testing.T) {
		r := x.issueRun(t, human)
		listed, err := awid.IDChildRequests(r.invitations)
		if err != nil || len(listed) != 0 {
			t.Fatalf("listed %v (%v)", listed, err)
		}
	})

	rootRun := func(t *testing.T) *issueRun {
		t.Helper()
		r := x.issueRun(t, root)
		if _, err := r.receive(x.requests["root-human-issue"].CanonicalUTF8); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rootApproval := fullHumanApproval

	t.Run("a namespace parent presents no parent chain", func(t *testing.T) {
		r := rootRun(t)
		r.parentChain = x.parentChain(t, "normal", x.v.Keys["alice"].DIDAW)
		response, err := r.approve(t, rootID, rootApproval)
		refused(t, err, "request_binding_mismatch")
		if response != nil || r.calls != 0 {
			t.Fatal("signed with a parent chain under a namespace parent")
		}
	})

	stale := resignFixture{status: x.v.Statuses["normal"]}.evidence(61)
	for name, tc := range map[string]struct {
		evidence *awid.IDChainEvidence
		reason   string
	}{"no evidence": {nil, "evidence_unavailable"}, "evidence past the fresh bound": {stale, "status_expired"}} {
		t.Run("a namespace parent with "+name, func(t *testing.T) {
			r := rootRun(t)
			response, err := awid.ApproveIDChildRequest(r.invitations, r.issuance, rootID, rootApproval, nil, tc.evidence, vectorSigner(t, x.v, "root", &r.calls), r.now)
			refused(t, err, tc.reason)
			if response != nil || r.calls != 0 {
				t.Fatal("signed without fresh evidence")
			}
		})
	}

	t.Run("a namespace parent for another domain never binds", func(t *testing.T) {
		r := x.issueRun(t, root)
		other := map[string]any{"kind": "namespace", "id": "example.org"}
		inv := r.invitation(t, root.Input.InvitationID)
		inv.Parent = other
		if err := r.invitations.PutInvitation(inv); err != nil {
			t.Fatal(err)
		}
		r.issuer = other
		r.invitations.writes = 0
		_, err := r.receive(variant(t, "alice", "root-human-issue", map[string]any{"parent": other}))
		refused(t, err, "domain_mismatch")
		if r.invitations.writes != 0 {
			t.Fatal("a request for another namespace was bound")
		}
	})
}

// A new child's id is its own key's: the stable id of subject_key for did:aw,
// refused at receive before anything is bound; for did:key the request codec
// already refuses an id other than subject_key.
func TestIDChildIssueNewChildIDIsTheSubjectKeys(t *testing.T) {
	x := loadIDChildExchange(t)
	human := loadIDChildIssueCases(t)["csr-human-exact-interactive-approval"]
	parsed, err := awid.ParseIDCertificateRequest([]byte(x.requests["human-issue"].CanonicalUTF8))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		change map[string]any
		reason string
	}{
		"did:aw of another key":  {map[string]any{"id": x.v.Keys["other_human"].DIDAW}, "subject_mismatch"},
		"did:key of another key": {map[string]any{"id": x.v.Keys["other_human"].DIDKey, "kind": "agent"}, "invalid_shape"},
	} {
		t.Run(name, func(t *testing.T) {
			r := x.issueRun(t, human)
			request := map[string]any{}
			for k, v := range parsed["request"].(map[string]any) {
				request[k] = v
			}
			for k, v := range tc.change {
				request[k] = v
			}
			inv := r.invitation(t, human.Input.InvitationID)
			inv.Kind = request["kind"].(string)
			if err := r.invitations.PutInvitation(inv); err != nil {
				t.Fatal(err)
			}
			r.invitations.writes = 0
			_, err := r.receive(signRequest(t, x.v, "bob", request))
			if got := awid.IDCertificateErrorCode(err); got != tc.reason {
				t.Fatalf("reason=%q (%v) want %q", got, err, tc.reason)
			}
			if r.invitations.writes != 0 {
				t.Fatal("a request for another key's id was bound")
			}
		})
	}
}

// Security notes on H2a (7d9949f5): N81 refused and expired requests never
// sign; N83 a parent chain that does not verify against the evidence is
// never signed into a response that every retry would replay.
func TestIDChildIssueApproveRefusals(t *testing.T) {
	x := loadIDChildExchange(t)
	human := loadIDChildIssueCases(t)["csr-human-exact-interactive-approval"]
	request := x.requests["human-issue"].CanonicalUTF8
	requestID := requestIDOf(t, request)
	approved := fullHumanApproval
	pending := func(t *testing.T) *issueRun {
		t.Helper()
		r := x.issueRun(t, human)
		if _, err := r.receive(request); err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("N81a a refused request is never signed", func(t *testing.T) {
		r := pending(t)
		if err := awid.RefuseIDChildRequest(r.invitations, requestID); err != nil {
			t.Fatal(err)
		}
		response, err := r.approve(t, requestID, approved)
		if err == nil || response != nil || r.calls != 0 {
			t.Fatalf("err=%v calls=%d", err, r.calls)
		}
		if state := r.invitation(t, human.Input.InvitationID).Request.State; state != awid.IDRequestFailed {
			t.Fatalf("state=%s", state)
		}
	})

	t.Run("N81b approval at exactly expires_at refuses", func(t *testing.T) {
		r := pending(t)
		inv := r.invitation(t, human.Input.InvitationID)
		inv.ExpiresAt = r.now.UTC().Format("2006-01-02T15:04:05Z")
		if err := r.invitations.PutInvitation(inv); err != nil {
			t.Fatal(err)
		}
		response, err := r.approve(t, requestID, approved)
		if got := awid.IDCertificateErrorCode(err); got != "invitation_conflict" || response != nil || r.calls != 0 {
			t.Fatalf("reason=%q (%v) calls=%d", got, err, r.calls)
		}
	})

	tampered := func(t *testing.T) []any {
		t.Helper()
		chain := x.parentChain(t, "normal", x.v.Keys["alice"].DIDAW)
		signed := map[string]any{}
		for k, v := range chain[0].(map[string]any) {
			signed[k] = v
		}
		signature := []byte(signed["signature"].(string))
		signature[0] ^= 'A' ^ 'B'
		if signature[0] == signed["signature"].(string)[0] {
			t.Fatal("signature unchanged")
		}
		signed["signature"] = string(signature)
		return []any{signed}
	}
	for name, chain := range map[string]func(*testing.T) []any{
		"N83 a superseded revision of the parent":        func(t *testing.T) []any { return []any{x.v.Certificates["alice-readmitted"].Signed} },
		"N83 a parent certificate whose signature fails": tampered,
	} {
		t.Run(name, func(t *testing.T) {
			r := pending(t)
			r.parentChain = chain(t)
			response, err := r.approve(t, requestID, approved)
			if err == nil || response != nil || r.calls != 0 {
				t.Fatalf("err=%v calls=%d", err, r.calls)
			}
			if inv := r.invitation(t, human.Input.InvitationID); inv.Request.State != awid.IDRequestPending || inv.Request.Response != "" {
				t.Fatalf("state=%s", inv.Request.State)
			}
		})
	}
}
