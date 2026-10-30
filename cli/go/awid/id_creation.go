package awid

import (
	"encoding/json"
	"fmt"
)

// IDTreeCreationRequest is the optional ID-tree part of an existing signed
// hosted creation request. Native parents supply their already registered chain.
type IDTreeCreationRequest struct {
	Mode      string         `json:"mode,omitempty"`
	V         int            `json:"v"`
	RequestID string         `json:"request_id"`
	Domain    string         `json:"domain"`
	Parent    map[string]any `json:"parent"`
	IDChain   map[string]any `json:"id_chain,omitempty"`
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
