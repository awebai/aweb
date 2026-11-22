package awid

// IDCertificateRequestOperation names the two subject-proven exchange requests.
type IDCertificateRequestOperation string

const (
	IDCertificateRequestIssue  IDCertificateRequestOperation = "issue"
	IDCertificateRequestResign IDCertificateRequestOperation = "resign"
)

// IDCertificateRequestView owns a shape-checked, subject-signed request from
// docs/id-certificates.md §6. Proof of possession does not authorize issuance.
type IDCertificateRequestView struct {
	signed                            map[string]any
	requestID, id, domain, subjectKey string
	operation                         IDCertificateRequestOperation
	kind                              IDCertificateKind
	parent                            IDCertificateParent
	invitationID                      string
	oldCertificate                    *IDCertificateView
}

// DecodeIDCertificateRequest reuses the released parser's exact field and
// signature rules, then gives consumers checked fields without map assertions.
func DecodeIDCertificateRequest(raw []byte) (IDCertificateRequestView, error) {
	signed, err := ParseIDCertificateRequest(raw)
	if err != nil {
		return IDCertificateRequestView{}, err
	}
	fields, ok := signed["request"].(map[string]any)
	if !ok {
		return IDCertificateRequestView{}, idCertificateRefusal(IDRefusalInvalidShape)
	}
	requestID, requestOK := fields["request_id"].(string)
	id, idOK := fields["id"].(string)
	domain, domainOK := fields["domain"].(string)
	subject, subjectOK := fields["subject_key"].(string)
	operation, operationOK := fields["operation"].(string)
	kind, kindOK := fields["kind"].(string)
	parent, parentOK := fields["parent"].(map[string]any)
	if !requestOK || !idOK || !domainOK || !subjectOK || !operationOK || !kindOK || !parentOK {
		return IDCertificateRequestView{}, idCertificateRefusal(IDRefusalInvalidShape)
	}
	parentID, parentIDOK := parent["id"].(string)
	parentKind, parentKindOK := parent["kind"].(string)
	if !parentIDOK || !parentKindOK {
		return IDCertificateRequestView{}, idCertificateRefusal(IDRefusalInvalidShape)
	}
	var invitationID string
	var oldCertificate *IDCertificateView
	if IDCertificateRequestOperation(operation) == IDCertificateRequestIssue {
		var ok bool
		invitationID, ok = fields["invitation_id"].(string)
		if !ok {
			return IDCertificateRequestView{}, idCertificateRefusal(IDRefusalInvalidShape)
		}
	} else {
		old, ok := fields["old_certificate"].(map[string]any)
		if !ok {
			return IDCertificateRequestView{}, idCertificateRefusal(IDRefusalInvalidShape)
		}
		checked, err := checkedIDCertificateView(old)
		if err != nil {
			return IDCertificateRequestView{}, err
		}
		oldCertificate = &checked
	}
	return IDCertificateRequestView{invitationID: invitationID, oldCertificate: oldCertificate, signed: copyIDObject(signed), requestID: requestID, id: id, domain: domain, subjectKey: subject,
		operation: IDCertificateRequestOperation(operation), kind: IDCertificateKind(kind), parent: IDCertificateParent{id: parentID, kind: IDParentKind(parentKind)},
	}, nil
}

// RequestID identifies the exact pending exchange.
func (request IDCertificateRequestView) RequestID() string { return request.requestID }

// ID identifies the certificate's proposed subject.
func (request IDCertificateRequestView) ID() string { return request.id }

// Domain names the request's certificate namespace.
func (request IDCertificateRequestView) Domain() string { return request.domain }

// SubjectKey identifies the key that proved possession over these fields.
func (request IDCertificateRequestView) SubjectKey() string { return request.subjectKey }

// Operation distinguishes initial issue from a local certificate re-sign.
func (request IDCertificateRequestView) Operation() IDCertificateRequestOperation {
	return request.operation
}

// Kind identifies the proposed subject kind.
func (request IDCertificateRequestView) Kind() IDCertificateKind { return request.kind }

// Parent names the proposed immediate signer, without proving its authority.
func (request IDCertificateRequestView) Parent() IDCertificateParent { return request.parent }

// InvitationID identifies the issuer's saved invitation for an issue request.
// A re-sign request has no invitation and returns an empty string.
func (request IDCertificateRequestView) InvitationID() string { return request.invitationID }

// PreviousCertificate returns the checked certificate presented for re-signing.
// The presence result is false for an initial issue request.
func (request IDCertificateRequestView) PreviousCertificate() (IDCertificateView, bool) {
	if request.oldCertificate == nil {
		return IDCertificateView{}, false
	}
	return *request.oldCertificate, true
}

// CertificateFields returns an independent expected child binding for the
// released map-based signing and import APIs. It contains no authorization.
func (request IDCertificateRequestView) CertificateFields() map[string]any {
	return map[string]any{"id": request.id, "domain": request.domain, "parent": request.parent.Fields(), "kind": string(request.kind)}
}

// Signed supplies an independent envelope to the released map-based importer.
func (request IDCertificateRequestView) Signed() map[string]any { return copyIDObject(request.signed) }

// Fields supplies an independent parent object for existing request/output DTOs.
func (parent IDCertificateParent) Fields() map[string]any {
	return map[string]any{"kind": string(parent.kind), "id": parent.id}
}

// IDCertificateResponseView owns a checked response and its ordered chain. It
// provides artifact integrity; current authority is checked by CheckIDChain.
type IDCertificateResponseView struct {
	requestID string
	chain     IDChain
}

// DecodeIDCertificateResponse reuses the released response parser before
// creating the checked chain view. It never selects an actor or registry.
func DecodeIDCertificateResponse(raw []byte) (IDCertificateResponseView, error) {
	fields, err := ParseIDCertificateResponse(raw)
	if err != nil {
		return IDCertificateResponseView{}, err
	}
	requestID, idOK := fields["request_id"].(string)
	bundle, chainOK := fields["chain"].(map[string]any)
	if !idOK || !chainOK {
		return IDCertificateResponseView{}, idCertificateRefusal(IDRefusalInvalidShape)
	}
	chain, err := IDChainFromBundle(bundle)
	if err != nil {
		return IDCertificateResponseView{}, err
	}
	return IDCertificateResponseView{requestID: requestID, chain: chain}, nil
}

// RequestID is correlation with the recipient's retained signed request.
func (response IDCertificateResponseView) RequestID() string { return response.requestID }

// Chain returns immutable checked certificate views, without current authority.
func (response IDCertificateResponseView) Chain() IDChain { return response.chain }
