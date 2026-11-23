package awid

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IDTreeCreationRequest is the optional ID-tree part of an existing signed
// hosted creation request. Native parents supply their already registered chain.
type IDTreeCreationRequest struct {
	InvitationID string         `json:"invitation_id,omitempty"`
	Mode         string         `json:"mode,omitempty"`
	V            int            `json:"v"`
	RequestID    string         `json:"request_id"`
	Domain       string         `json:"domain"`
	Parent       map[string]any `json:"parent"`
	IDChain      map[string]any `json:"id_chain,omitempty"`
}

// IDTreeCreationResponse is adjacent to the constructor's existing identity and
// membership fields. Missing or null fields are the legacy unknown response.
type IDTreeCreationResponse struct {
	FieldsPresent       bool                       `json:"-"`
	IDChain             ReceivedIDChain            `json:"id_chain"`
	RegistrationRequest *IDTreeRegistrationRequest `json:"registration_request"`
}

// IDTreeRegistrationRequest preserves both arguments, including explicit nulls.
// A non-nil object requests registration; nil means Cloud requests no write.
type IDTreeRegistrationRequest struct {
	ExpectedHead *string `json:"expected_head"`
	InvitationID *string `json:"invitation_id"`
}

// UnmarshalJSON requires both registration precondition fields to be present;
// an explicit null remains distinct from a missing field.
func (request *IDTreeRegistrationRequest) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["expected_head"]; !ok {
		return fmt.Errorf("registration_request is missing expected_head")
	}
	if _, ok := fields["invitation_id"]; !ok {
		return fmt.Errorf("registration_request is missing invitation_id")
	}
	type plain IDTreeRegistrationRequest
	return json.Unmarshal(raw, (*plain)(request))
}

// DecodeIDTreeCreationResponse keeps legacy omission separate from a response
// that explicitly advertises the new protocol, even when both values are null.
func DecodeIDTreeCreationResponse(raw []byte) (IDTreeCreationResponse, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return IDTreeCreationResponse{}, err
	}
	var response IDTreeCreationResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return response, err
	}
	_, chainPresent := fields["id_chain"]
	_, registrationPresent := fields["registration_request"]
	response.FieldsPresent = chainPresent || registrationPresent
	return response, nil
}

// IDCreationIntent fixes the child's name and scope when its creator asks a
// hosted operator to prepare an invitation. It contains no parent authority.
type IDCreationIntent struct {
	Name          string `json:"name"`
	IdentityScope string `json:"identity_scope"`
}

// IDCreationInvitation is public intent fixed by a checked person session
// before a setup key or invite can be redeemed. It selects authority; it is
// not a signature and cannot replace response-chain verification.
type IDCreationInvitation struct {
	ID            string         `json:"id"`
	Parent        map[string]any `json:"parent"`
	Domain        string         `json:"domain"`
	Name          string         `json:"name"`
	IdentityScope string         `json:"identity_scope"`
}

// DecodeIDCreationInvitation reads the optional creation_invitation sibling.
// Absence is legacy. An explicitly advertised but unusable invitation refuses.
func DecodeIDCreationInvitation(raw []byte) (*IDCreationInvitation, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	value, present := fields["creation_invitation"]
	if !present {
		return nil, nil
	}
	var inv IDCreationInvitation
	if err := json.Unmarshal(value, &inv); err != nil {
		return nil, err
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

// Validate checks the invitation shape and registered-person parent selector.
// It does not establish expiry, availability or the parent's current authority.
func (inv *IDCreationInvitation) Validate() error {
	if inv == nil || !idCertificateIsUUID(inv.ID) || !idCertificateDomain(inv.Domain) || inv.Name == "" || (inv.IdentityScope != "local" && inv.IdentityScope != "global") || len(inv.Parent) != 2 || inv.Parent["kind"] != "identity" || !idCertificateIDValid(inv.Parent["id"], false) {
		return fmt.Errorf("invalid creation invitation")
	}
	id, ok := inv.Parent["id"].(string)
	if !ok {
		return fmt.Errorf("invalid creation invitation")
	}
	if !strings.HasPrefix(id, "did:aw:") {
		return fmt.Errorf("creation invitation requires a registered person parent")
	}
	return nil
}
