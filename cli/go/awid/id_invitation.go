package awid

// The parent side of the issue file exchange (docs/id-certificates.md §6).
// The parent fixes an invitation privately before any request exists; the
// first valid child request binds to it, and the parent signs only on
// approve. Callers hold the parent's transaction lock across receive,
// approve and refuse, and fetch status evidence before taking it.
import (
	"fmt"
	"reflect"
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
// approved a kind=human child. The fingerprint must be entered before the
// request's own fingerprint is shown.
type IDHumanApproval struct {
	Interactive                 bool
	AgentRun                    bool
	AutoApprove                 bool
	OutOfBandChannel            bool
	FingerprintShownBeforeEntry bool
	EnteredFingerprint          string
}

// IDChildRequest is a listed request with the public fields of its
// invitation. The recipient, child key and request bytes stay private.
type IDChildRequest struct {
	RequestID    string         `json:"request_id"`
	InvitationID string         `json:"invitation_id"`
	State        string         `json:"state"`
	ID           string         `json:"id"`
	Domain       string         `json:"domain"`
	Parent       map[string]any `json:"parent"`
	Kind         string         `json:"kind"`
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
		// A released response cannot be unsent; voiding blocks further signing.
		inv.Void = true
		inv.Request.State = IDRequestFailed
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
	current, err := idIssuingKey(inv, parentChain, evidence)
	if err != nil {
		return nil, err
	}
	if inv.Kind == "human" {
		if err := idHumanApproved(invitations, inv, approval, r["subject_key"].(string)); err != nil {
			return nil, err
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

// idIssuingKey is the key the invitation's parent signs with now: an
// identity parent's current key once its chain verifies, or the namespace's
// open epoch key. An agent parent never issues a human (R1).
func idIssuingKey(inv *IDInvitation, parentChain []any, evidence *IDChainEvidence) (string, error) {
	switch inv.Parent["kind"] {
	case "identity":
		parentID, _ := inv.Parent["id"].(string)
		_, current, kind, err := idSigningParent(parentID, evidence, inv.Domain)
		if err != nil {
			return "", err
		}
		if kind != "human" && inv.Kind == "human" {
			return "", idCertificateRefusal("human_issuer_is_agent")
		}
		if !idChainEndsIn(parentChain, parentID) {
			return "", fmt.Errorf("the parent chain does not end in %s", parentID)
		}
		return current, nil
	case "namespace":
		// The request codec refuses a namespace parent other than its domain.
		if len(parentChain) != 0 {
			return "", idCertificateRefusal("request_binding_mismatch")
		}
		if evidence == nil {
			return "", idCertificateRefusal("evidence_unavailable")
		}
		if err := idEvidenceUsable(evidence); err != nil {
			return "", err
		}
		status, err := parseIDStatus(evidence, inv.Domain)
		if err != nil {
			return "", err
		}
		epochs := status.Namespace.Epochs
		return epochs[len(epochs)-1].DIDKey, nil
	}
	return "", idCertificateRefusal("invalid_shape")
}

// idHumanApproved refuses unless the approving human typed, before seeing
// it, the fingerprint the recipient sent over a separate trusted channel. A
// typed fingerprint that differs voids the invitation.
func idHumanApproved(invitations IDInvitationStore, inv *IDInvitation, approval IDHumanApproval, subjectKey string) error {
	if !approval.Interactive || approval.AgentRun || approval.AutoApprove || !approval.OutOfBandChannel || approval.FingerprintShownBeforeEntry || approval.EnteredFingerprint == "" {
		return idCertificateRefusal("human_approval_required")
	}
	fingerprint, err := IDKeyFingerprint(subjectKey)
	if err != nil {
		return err
	}
	if approval.EnteredFingerprint == fingerprint {
		return nil
	}
	inv.Void = true
	inv.Request.State = IDRequestFailed
	if err := invitations.PutInvitation(inv); err != nil {
		return err
	}
	return idCertificateRefusal("recipient_key_mismatch")
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
		out = append(out, IDChildRequest{RequestID: inv.Request.RequestID, InvitationID: inv.InvitationID, State: inv.Request.State, ID: r["id"].(string), Domain: inv.Domain, Parent: inv.Parent, Kind: inv.Kind})
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
