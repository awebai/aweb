package awid

import "encoding/json"

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
	return IDCertificateRequestView{signed: copyIDObject(signed), requestID: requestID, id: id, domain: domain, subjectKey: subject,
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

// Bundle supplies an independent chain for released map-based evidence,
// registration and installation APIs. No owned signed field is exposed.
func (chain IDChain) Bundle() map[string]any {
	if len(chain.certificates) == 0 {
		return nil
	}
	return map[string]any{"v": json.Number("1"), "type": "aweb.id-chain", "certificates": chain.SignedCertificates()}
}
