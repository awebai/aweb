package awid

// The parent and child sides of the re-sign file exchange
// (docs/id-certificates.md §6). Callers hold the parent identity's
// transaction lock across receive, approve and refuse, and fetch status
// evidence before taking it.
import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// ReceiveIDResignRequest verifies a re-sign request and attaches it, pending,
// to the issuance entry of the certificate it presents. Each issued
// certificate takes one re-sign; a byte-identical retry changes nothing.
func ReceiveIDResignRequest(store IDIssuanceStore, raw []byte) (*IDIssuanceEntry, error) {
	request, err := DecodeIDCertificateRequest(raw)
	if err != nil {
		return nil, err
	}
	if request.Operation() != IDCertificateRequestResign {
		return nil, idCertificateRefusal(IDRefusalInvalidShape)
	}
	old, exists := request.PreviousCertificate()
	if !exists {
		return nil, idCertificateRefusal(IDRefusalInvalidShape)
	}
	oldID, err := old.CertificateID()
	if err != nil {
		return nil, err
	}
	entry, err := store.Entry(oldID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, idCertificateRefusal(IDRefusalIssuanceNotRecorded)
	}
	requestID := request.RequestID()
	if other, err := store.EntryForRequest(requestID); err != nil {
		return nil, err
	} else if other != nil && other.CertificateID != oldID {
		return nil, idCertificateRefusal(IDRefusalRequestConflict)
	}
	if entry.Resign != nil {
		if entry.Resign.RequestID == requestID && entry.Resign.Request == string(raw) {
			return entry, nil
		}
		if entry.Resign.RequestID == requestID || entry.Resign.State != IDRequestFailed {
			return nil, idCertificateRefusal(IDRefusalRequestConflict)
		}
	}
	entry.Resign = &IDRequestRecord{RequestID: requestID, Request: string(raw), State: IDRequestPending}
	if err := store.Put(entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// ApproveIDResignRequest re-signs a pending request and returns its exact
// response. The old entry records the response before the new certificate's
// entry is written, and both before anything is returned, so a retry after a
// crash returns the same bytes without signing again. parentChain is the
// parent's own current chain, ending in the parent.
func ApproveIDResignRequest(store IDIssuanceStore, requestID, parentID string, parentChain []any, evidence *IDChainEvidence, domain string, sign IDCertificateSigner, now time.Time) ([]byte, error) {
	entry, err := idResignEntry(store, requestID)
	if err != nil {
		return nil, err
	}
	switch entry.Resign.State {
	case IDRequestIssued:
		return idIssuedResponse(store, entry.Resign, now)
	case IDRequestFailed:
		return nil, fmt.Errorf("re-sign request %s was refused", requestID)
	}
	request, err := DecodeIDCertificateRequest([]byte(entry.Resign.Request))
	if err != nil {
		return nil, err
	}
	if request.Domain() != domain {
		return nil, fmt.Errorf("this child belongs to %s but its parent is now in %s; its ancestry cannot refresh across domains; respawn under the adopted parent", request.Domain(), domain)
	}
	if len(parentChain) == 0 {
		return nil, fmt.Errorf("the parent's own chain is required")
	}
	last, ok := parentChain[len(parentChain)-1].(map[string]any)
	if ok {
		var certificate map[string]any
		certificate, ok = last["certificate"].(map[string]any)
		ok = ok && certificate["id"] == parentID
	}
	if !ok {
		return nil, fmt.Errorf("the parent chain does not end in %s", parentID)
	}
	_, err = idIssuingKey(map[string]any{"kind": "identity", "id": parentID}, domain, "agent", parentChain, evidence)
	if err != nil {
		return nil, err
	}
	previous, exists := request.PreviousCertificate()
	if !exists {
		return nil, idCertificateRefusal(IDRefusalInvalidShape)
	}
	req := IDResignRequest{Signed: previous.Signed(), Requested: request.CertificateFields(), SubjectKey: request.SubjectKey()}
	var response []byte
	_, err = resignIDCertificate(req, parentID, parentChain, evidence, domain, store, sign, now, func(child map[string]any, id string) error {
		certificates := append(append([]any{}, parentChain...), child)
		chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}
		encoded, err := EncodeIDCertificateResponse(requestID, chain)
		if err != nil {
			return err
		}
		entry.Resign.State = IDRequestIssued
		entry.Resign.Response = string(encoded)
		entry.Resign.NewCertificateID = id
		if err := store.Put(entry); err != nil {
			return err
		}
		if err := recordIssued(store, now)(child, id); err != nil {
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

// RefuseIDResignRequest fails a pending request without signing.
func RefuseIDResignRequest(store IDIssuanceStore, requestID string) error {
	entry, err := idResignEntry(store, requestID)
	if err != nil {
		return err
	}
	switch entry.Resign.State {
	case IDRequestIssued:
		return fmt.Errorf("re-sign request %s was already issued", requestID)
	case IDRequestFailed:
		return nil
	}
	entry.Resign.State = IDRequestFailed
	return store.Put(entry)
}

// IDResignResponse re-exports the stored response of an issued request, for
// a child that lost it.
func IDResignResponse(store IDIssuanceStore, requestID string) ([]byte, error) {
	entry, err := idResignEntry(store, requestID)
	if err != nil {
		return nil, err
	}
	if entry.Resign.State != IDRequestIssued {
		return nil, fmt.Errorf("re-sign request %s has no response (%s)", requestID, entry.Resign.State)
	}
	return []byte(entry.Resign.Response), nil
}

func idResignEntry(store IDIssuanceStore, requestID string) (*IDIssuanceEntry, error) {
	entry, err := store.EntryForRequest(requestID)
	if err != nil {
		return nil, err
	}
	if entry == nil || entry.Resign == nil {
		return nil, fmt.Errorf("no re-sign request %s", requestID)
	}
	return entry, nil
}

// idIssuedResponse returns an issued request's stored response, first
// recreating the new certificate's issuance entry from it if a crash lost
// that write.
func idIssuedResponse(store IDIssuanceStore, record *IDRequestRecord, now time.Time) ([]byte, error) {
	response := []byte(record.Response)
	existing, err := store.Entry(record.NewCertificateID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return response, nil
	}
	parsed, err := DecodeIDCertificateResponse(response)
	if err != nil {
		return nil, err
	}
	child := parsed.Chain().Leaf()
	id, err := child.CertificateID()
	if err != nil || id != record.NewCertificateID {
		return nil, fmt.Errorf("stored response does not carry certificate %s", record.NewCertificateID)
	}
	if err := recordIssued(store, now)(child.Signed(), id); err != nil {
		return nil, err
	}
	return response, nil
}

// IDCertificateImport is a verified response for an outstanding request. A
// did:aw child's certificate still needs its own registration before it
// carries any authority.
type IDCertificateImport struct {
	Chain               map[string]any
	Certificate         map[string]any
	RegistrationPending bool
}

// ImportIDCertificateResponse verifies a response against the child's
// outstanding request before anything is installed: the exact binding, the
// parent's current chain through the shared verifier, and the child
// certificate signed by the parent's current key. A namespace parent has no
// chain: its certificate must be signed by the namespace's open epoch key.
func ImportIDCertificateResponse(request map[string]any, raw []byte, evidence *IDChainEvidence, domain string) (*IDCertificateImport, error) {
	response, err := DecodeIDCertificateResponse(raw)
	if err != nil {
		return nil, err
	}
	mismatch := idCertificateRefusal(IDRefusalRequestBindingMismatch)
	r, ok := request["request"].(map[string]any)
	if !ok {
		return nil, idCertificateRefusal(IDRefusalInvalidShape)
	}
	if response.RequestID() != r["request_id"] {
		return nil, mismatch
	}
	return importIDCertificateChain(idCertificateChainImport{Expected: r, Chain: response.Chain(), Bundle: response.Chain().Bundle(), Evidence: evidence, Domain: domain})
}

// ImportIDCertificateChain applies the response import's existing binding and
// issuer checks to a creation response's public chain. expected contains the
// independently selected id, domain, parent and kind. This is pre-registration
// validation; a global leaf still needs registration and full verification.
func ImportIDCertificateChain(expected, chain map[string]any, evidence *IDChainEvidence, domain string) (*IDCertificateImport, error) {
	checked, err := IDChainFromBundle(chain)
	if err != nil {
		return nil, err
	}
	return importIDCertificateChain(idCertificateChainImport{Expected: expected, Chain: checked, Bundle: chain, Evidence: evidence, Domain: domain})
}

type idCertificateChainImport struct {
	Expected map[string]any
	Chain    IDChain
	Bundle   map[string]any
	Evidence *IDChainEvidence
	Domain   string
}

func importIDCertificateChain(input idCertificateChainImport) (*IDCertificateImport, error) {
	expected, chain, evidence, domain := input.Expected, input.Bundle, input.Evidence, input.Domain
	mismatch := idCertificateRefusal(IDRefusalRequestBindingMismatch)
	certificates := input.Chain.SignedCertificates()
	child := input.Chain.Leaf()
	c := child.Fields()
	for _, field := range []string{"id", "domain", "parent", "kind"} {
		if !reflect.DeepEqual(c[field], expected[field]) {
			return nil, mismatch
		}
	}
	parent := child.Parent().Fields()
	if parent["kind"] == "namespace" {
		// The root admits its first human directly: the chain is that one
		// certificate, signed by the namespace's open epoch key under fresh,
		// DNS-anchored namespace evidence.
		if len(certificates) != 1 {
			return nil, idCertificateRefusal(IDRefusalInvalidShape)
		}
		current, err := idIssuingKey(parent, domain, string(child.Kind()), nil, evidence)
		if err != nil {
			return nil, err
		}
		if c["issuer_key"] != current {
			return nil, idCertificateRefusal(IDRefusalStaleIssuerKey)
		}
		return &IDCertificateImport{Chain: chain, Certificate: child.Signed(), RegistrationPending: strings.HasPrefix(child.ID(), "did:aw:")}, nil
	}
	if parent["kind"] != "identity" || len(certificates) < 2 {
		return nil, idCertificateRefusal(IDRefusalInvalidShape)
	}
	if evidence == nil {
		return nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	current, err := idIssuingKey(parent, domain, string(child.Kind()), certificates[:len(certificates)-1], evidence)
	if err != nil {
		// Import preserves the chain verifier's refusal contract; the
		// signing helper names a revoked signing parent more specifically.
		if IDCertificateErrorCode(err) == "parent_revoked" {
			return nil, idCertificateRefusal(IDRefusalRevoked)
		}
		return nil, err
	}
	// Parsing verified the child's signature under its own issuer_key.
	if c["issuer_key"] != current {
		return nil, idCertificateRefusal(IDRefusalStaleIssuerKey)
	}
	return &IDCertificateImport{Chain: chain, Certificate: child.Signed(), RegistrationPending: strings.HasPrefix(child.ID(), "did:aw:")}, nil
}
