package awid

// The parent side of the issue file exchange (docs/id-certificates.md §6).
// The parent fixes an invitation privately before any request exists; the
// first valid child request binds to it, and the parent signs only on
// approve. Callers hold the parent's transaction lock across receive,
// approve and refuse, and fetch status evidence before taking it.
import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// IDInvitation is a parent's private record of one child it intends to
// issue: the fixed recipient, domain, parent and kind, and the one request
// bound to it. A void invitation signs nothing more.
type IDInvitation struct {
	InvitationID string           `json:"invitation_id"`
	Mode         string           `json:"mode"`
	Parent       map[string]any   `json:"parent"`
	Domain       string           `json:"domain"`
	Kind         string           `json:"kind"`
	Recipient    string           `json:"recipient"`
	ExpiresAt    string           `json:"expires_at"`
	Void         bool             `json:"void,omitempty"`
	Request      *IDRequestRecord `json:"request,omitempty"`
}

const (
	IDInvitationSelfCustodial = "self_custodial"
	IDInvitationHostManaged   = "host_managed"
)

// IDInvitationStore persists a parent's invitations durably.
type IDInvitationStore interface {
	Invitation(invitationID string) (*IDInvitation, error)
	PutInvitation(invitation *IDInvitation) error
	Invitations() ([]*IDInvitation, error)
}

// IDHumanApproval is what the approving command observed while the human
// approved a kind=human child: Confirmed is an affirmative answer, at a
// terminal, that the shown fingerprint matches what the recipient told the
// approver over a separate trusted channel.
type IDHumanApproval struct {
	Interactive bool
	AgentRun    bool
	AutoApprove bool
	Confirmed   bool
}

// IDChildRequest is a listed request with the public fields of its
// invitation. The recipient, child key and request bytes stay private. A
// did:aw id is derived from the child key, so the key's fingerprint can be
// computed from it: human approval rests on the approver comparing it with
// what the recipient said, not on the fingerprint being secret. An issued
// request names its certificate, so the inviter of a void invitation can
// decide on revocation.
type IDChildRequest struct {
	RequestID      string         `json:"request_id"`
	Operation      string         `json:"operation"`
	InvitationID   string         `json:"invitation_id"`
	InvitationVoid bool           `json:"invitation_void"`
	State          string         `json:"state"`
	CertificateID  string         `json:"certificate_id,omitempty"`
	ID             string         `json:"id"`
	Domain         string         `json:"domain"`
	Parent         map[string]any `json:"parent"`
	Kind           string         `json:"kind"`
}

// ReceiveIDChildRequest verifies an issue request's shape and key proof and
// binds it, pending, to the issuer's own invitation it names. A
// byte-identical retry changes nothing; a request proving a different key
// voids the invitation.
func ReceiveIDChildRequest(store IDInvitationStore, issuer map[string]any, raw []byte) (*IDInvitation, error) {
	signed, err := ParseIDCertificateRequest(raw)
	if err != nil {
		return nil, err
	}
	r := signed["request"].(map[string]any)
	if r["operation"] != "issue" {
		return nil, idCertificateRefusal("invalid_shape")
	}
	if !idNewChildIDIsSubjectKeys(r["id"].(string), r["subject_key"].(string)) {
		return nil, idCertificateRefusal("subject_mismatch")
	}
	mismatch := idCertificateRefusal("request_binding_mismatch")
	inv, err := store.Invitation(r["invitation_id"].(string))
	if err != nil {
		return nil, err
	}
	if inv == nil || !reflect.DeepEqual(inv.Parent, issuer) {
		return nil, mismatch
	}
	if inv.Mode != IDInvitationSelfCustodial {
		return nil, idCertificateRefusal("invitation_mode_mismatch")
	}
	requestID := r["request_id"].(string)
	if inv.Request != nil && inv.Request.RequestID == requestID {
		if inv.Request.Request == string(raw) {
			return inv, nil
		}
		return nil, idCertificateRefusal("request_conflict")
	}
	if !reflect.DeepEqual(r["parent"], inv.Parent) || r["domain"] != inv.Domain || r["kind"] != inv.Kind {
		return nil, mismatch
	}
	// A request id names one request for the whole issuer, so approve and
	// refuse by request id are never ambiguous.
	all, err := store.Invitations()
	if err != nil {
		return nil, err
	}
	for _, other := range all {
		if other.InvitationID != inv.InvitationID && other.Request != nil && other.Request.RequestID == requestID {
			return nil, idCertificateRefusal("request_conflict")
		}
	}
	if inv.Void {
		return nil, idCertificateRefusal("invitation_conflict")
	}
	if inv.Request != nil {
		prior, err := ParseIDCertificateRequest([]byte(inv.Request.Request))
		if err != nil {
			return nil, err
		}
		if prior["request"].(map[string]any)["subject_key"] == r["subject_key"] {
			return nil, idCertificateRefusal("request_conflict")
		}
		// A released response cannot be unsent: voiding blocks further signing,
		// and an issued request stays issued with its response.
		inv.Void = true
		if inv.Request.State == IDRequestPending {
			inv.Request.State = IDRequestFailed
		}
		if err := store.PutInvitation(inv); err != nil {
			return nil, err
		}
		return nil, idCertificateRefusal("invitation_conflict")
	}
	inv.Request = &IDRequestRecord{RequestID: requestID, Request: string(raw), State: IDRequestPending}
	if err := store.PutInvitation(inv); err != nil {
		return nil, err
	}
	return inv, nil
}

// ApproveIDChildRequest signs the certificate for a pending issue request and
// returns its exact response. A kind=human child needs the human approval,
// whoever the parent; an agent child needs the invitation and key proof
// alone. The invitation records the response before the issuance log, and
// both before anything is returned, so a retry returns the same bytes
// without signing again. parentChain is an identity parent's own current
// chain, ending in the parent; a namespace parent has none.
func ApproveIDChildRequest(invitations IDInvitationStore, issuance IDIssuanceStore, requestID string, approval IDHumanApproval, parentChain []any, evidence *IDChainEvidence, sign IDCertificateSigner, now time.Time) ([]byte, error) {
	inv, err := idInvitationForRequest(invitations, requestID)
	if err != nil {
		return nil, err
	}
	switch {
	case inv.Request.State == IDRequestIssued:
		return idIssuedResponse(issuance, inv.Request, now)
	case inv.Void:
		return nil, idCertificateRefusal("invitation_conflict")
	case inv.Request.State == IDRequestFailed:
		return nil, fmt.Errorf("child request %s was refused", requestID)
	}
	expires, err := time.Parse(time.RFC3339, inv.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return nil, idCertificateRefusal("invitation_conflict")
	}
	signed, err := ParseIDCertificateRequest([]byte(inv.Request.Request))
	if err != nil {
		return nil, err
	}
	r := signed["request"].(map[string]any)
	current, err := idIssuingKey(inv.Parent, inv.Domain, inv.Kind, parentChain, evidence)
	if err != nil {
		return nil, err
	}
	if inv.Kind == "human" {
		if !idHumanApproved(approval) {
			return nil, idCertificateRefusal("human_approval_required")
		}
	}
	certificate := map[string]any{
		"v": 1, "type": "aweb.id-certificate",
		"id": r["id"], "domain": r["domain"], "parent": r["parent"], "kind": r["kind"],
		"issuer_key": current, "issued_at": idRecordTime(now),
	}
	var response []byte
	_, err = issueIDCertificate(certificate, current, sign, func(child map[string]any, id string) error {
		certificates := append(append([]any{}, parentChain...), child)
		encoded, err := EncodeIDCertificateResponse(requestID, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates})
		if err != nil {
			return err
		}
		inv.Request.State = IDRequestIssued
		inv.Request.Response = string(encoded)
		inv.Request.NewCertificateID = id
		if err := invitations.PutInvitation(inv); err != nil {
			return err
		}
		if err := recordIssued(issuance, now)(child, id); err != nil {
			return err
		}
		response = encoded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}

// idIssuingKey is the key parent signs a kind child in domain with now: an
// identity parent's current key once its chain verifies, or the namespace's
// open epoch key. An agent parent never issues a human (R1), and a parent
// whose chain is already at the maximum depth issues nothing: its child's
// chain could never verify.
func idIssuingKey(parent map[string]any, domain, childKind string, parentChain []any, evidence *IDChainEvidence) (string, error) {
	switch parent["kind"] {
	case "identity":
		parentID, _ := parent["id"].(string)
		_, current, kind, err := idSigningParent(parentID, evidence, domain)
		if err != nil {
			return "", err
		}
		if kind != "human" && childKind == "human" {
			return "", idCertificateRefusal("human_issuer_is_agent")
		}
		if !idChainEndsIn(parentChain, parentID) {
			return "", fmt.Errorf("the parent chain does not end in %s", parentID)
		}
		if len(parentChain) >= IDChainMaxDepth {
			return "", idCertificateRefusal("depth_exceeded")
		}
		if err := idParentChainVerified(parentChain, parentID, current, evidence, domain); err != nil {
			return "", err
		}
		return current, nil
	case "namespace":
		if parent["id"] != domain {
			return "", idCertificateRefusal("domain_mismatch")
		}
		if len(parentChain) != 0 {
			return "", idCertificateRefusal("request_binding_mismatch")
		}
		if evidence == nil {
			return "", idCertificateRefusal("evidence_unavailable")
		}
		if err := idEvidenceUsable(evidence); err != nil {
			return "", err
		}
		status, err := parseIDStatus(evidence, domain)
		if err != nil {
			return "", err
		}
		epochs := status.Namespace.Epochs
		return epochs[len(epochs)-1].DIDKey, nil
	}
	return "", idCertificateRefusal("invalid_shape")
}

// idHumanApproved holds only for an affirmative confirmation a human gave at
// a terminal, never for an agent run or an automatic approval. A declined
// confirmation leaves the request pending and the invitation live.
func idHumanApproved(approval IDHumanApproval) bool {
	return approval.Interactive && !approval.AgentRun && !approval.AutoApprove && approval.Confirmed
}

// idNewChildIDIsSubjectKeys checks that a new did:aw child's id is the
// stable id of its own subject_key; the request codec already holds a did:key
// child's id to subject_key. An existing child presented under a later key
// (§6: "for did:aw the receiver independently resolves and checks the current
// key and continuity") needs resolved evidence and belongs to re-parenting.
func idNewChildIDIsSubjectKeys(id, subjectKey string) bool {
	if !strings.HasPrefix(id, "did:aw:") {
		return true
	}
	key, err := ExtractPublicKey(subjectKey)
	return err == nil && id == ComputeStableID(key)
}

// idParentChainVerified checks the parent chain a response will carry
// against the same evidence the signing decision used. A response is
// recorded as final and replayed on every retry, so a stale or wrong chain
// must never be signed into one.
func idParentChainVerified(parentChain []any, parentID, current string, evidence *IDChainEvidence, domain string) error {
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": parentChain}
	verdict := VerifyIDChain(bundle, IDChainSubject{ID: parentID, DIDKey: current}, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return idCertificateRefusal(verdict.Reason)
	}
	return nil
}

func idChainEndsIn(chain []any, id string) bool {
	if len(chain) == 0 {
		return false
	}
	last, ok := chain[len(chain)-1].(map[string]any)
	if !ok {
		return false
	}
	certificate, ok := last["certificate"].(map[string]any)
	return ok && certificate["id"] == id
}

// RefuseIDChildRequest fails a pending issue request without signing.
func RefuseIDChildRequest(invitations IDInvitationStore, requestID string) error {
	inv, err := idInvitationForRequest(invitations, requestID)
	if err != nil {
		return err
	}
	switch inv.Request.State {
	case IDRequestIssued:
		return fmt.Errorf("child request %s was already issued", requestID)
	case IDRequestFailed:
		return nil
	}
	inv.Request.State = IDRequestFailed
	return invitations.PutInvitation(inv)
}

// IDChildRequests lists the requests bound to the issuer's invitations.
func IDChildRequests(invitations IDInvitationStore) ([]IDChildRequest, error) {
	all, err := invitations.Invitations()
	if err != nil {
		return nil, err
	}
	out := []IDChildRequest{}
	for _, inv := range all {
		if inv.Request == nil {
			continue
		}
		signed, err := ParseIDCertificateRequest([]byte(inv.Request.Request))
		if err != nil {
			return nil, err
		}
		r := signed["request"].(map[string]any)
		out = append(out, IDChildRequest{RequestID: inv.Request.RequestID, Operation: "issue", InvitationID: inv.InvitationID, InvitationVoid: inv.Void, State: inv.Request.State, CertificateID: inv.Request.NewCertificateID, ID: r["id"].(string), Domain: inv.Domain, Parent: inv.Parent, Kind: inv.Kind})
	}
	return out, nil
}

func idInvitationForRequest(invitations IDInvitationStore, requestID string) (*IDInvitation, error) {
	all, err := invitations.Invitations()
	if err != nil {
		return nil, err
	}
	for _, inv := range all {
		if inv.Request != nil && inv.Request.RequestID == requestID {
			return inv, nil
		}
	}
	return nil, fmt.Errorf("no child request %s", requestID)
}
