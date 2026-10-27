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
	signed, err := ParseIDCertificateRequest(raw)
	if err != nil {
		return nil, err
	}
	r := signed["request"].(map[string]any)
	if r["operation"] != "resign" {
		return nil, idCertificateRefusal("invalid_shape")
	}
	oldID, err := IDCertificateID(r["old_certificate"].(map[string]any)["certificate"].(map[string]any))
	if err != nil {
		return nil, err
	}
	entry, err := store.Entry(oldID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, idCertificateRefusal("issuance_not_recorded")
	}
	requestID := r["request_id"].(string)
	if other, err := store.EntryForRequest(requestID); err != nil {
		return nil, err
	} else if other != nil && other.CertificateID != oldID {
		return nil, idCertificateRefusal("request_conflict")
	}
	if entry.Resign != nil {
		if entry.Resign.RequestID == requestID && entry.Resign.Request == string(raw) {
			return entry, nil
		}
		if entry.Resign.RequestID == requestID || entry.Resign.State != IDResignFailed {
			return nil, idCertificateRefusal("request_conflict")
		}
	}
	entry.Resign = &IDResignRecord{RequestID: requestID, Request: string(raw), State: IDResignPending}
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
	case IDResignIssued:
		return idResignIssuedResponse(store, entry, now)
	case IDResignFailed:
		return nil, fmt.Errorf("re-sign request %s was refused", requestID)
	}
	signed, err := ParseIDCertificateRequest([]byte(entry.Resign.Request))
	if err != nil {
		return nil, err
	}
	r := signed["request"].(map[string]any)
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
	req := IDResignRequest{
		Signed:     r["old_certificate"].(map[string]any),
		Requested:  map[string]any{"id": r["id"], "domain": r["domain"], "parent": r["parent"], "kind": r["kind"]},
		SubjectKey: r["subject_key"].(string),
	}
	var response []byte
	_, err = resignIDCertificate(req, parentID, evidence, domain, store, sign, now, func(child map[string]any, id string) error {
		certificates := append(append([]any{}, parentChain...), child)
		chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}
		encoded, err := EncodeIDCertificateResponse(requestID, chain)
		if err != nil {
			return err
		}
		entry.Resign.State = IDResignIssued
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
	case IDResignIssued:
		return fmt.Errorf("re-sign request %s was already issued", requestID)
	case IDResignFailed:
		return nil
	}
	entry.Resign.State = IDResignFailed
	return store.Put(entry)
}

// IDResignResponse re-exports the stored response of an issued request, for
// a child that lost it.
func IDResignResponse(store IDIssuanceStore, requestID string) ([]byte, error) {
	entry, err := idResignEntry(store, requestID)
	if err != nil {
		return nil, err
	}
	if entry.Resign.State != IDResignIssued {
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

// idResignIssuedResponse returns the stored response, first recreating the
// new certificate's entry from it if a crash lost that write.
func idResignIssuedResponse(store IDIssuanceStore, entry *IDIssuanceEntry, now time.Time) ([]byte, error) {
	response := []byte(entry.Resign.Response)
	existing, err := store.Entry(entry.Resign.NewCertificateID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return response, nil
	}
	parsed, err := ParseIDCertificateResponse(response)
	if err != nil {
		return nil, err
	}
	certificates := parsed["chain"].(map[string]any)["certificates"].([]any)
	child := certificates[len(certificates)-1].(map[string]any)
	id, err := IDCertificateID(child["certificate"].(map[string]any))
	if err != nil || id != entry.Resign.NewCertificateID {
		return nil, fmt.Errorf("stored response does not carry certificate %s", entry.Resign.NewCertificateID)
	}
	if err := recordIssued(store, now)(child, id); err != nil {
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
// certificate signed by the parent's current key.
func ImportIDCertificateResponse(request map[string]any, raw []byte, evidence *IDChainEvidence, domain string) (*IDCertificateImport, error) {
	response, err := ParseIDCertificateResponse(raw)
	if err != nil {
		return nil, err
	}
	mismatch := idCertificateRefusal("request_binding_mismatch")
	r, ok := request["request"].(map[string]any)
	if !ok {
		return nil, idCertificateRefusal("invalid_shape")
	}
	if response["request_id"] != r["request_id"] {
		return nil, mismatch
	}
	chain := response["chain"].(map[string]any)
	certificates := chain["certificates"].([]any)
	child := certificates[len(certificates)-1].(map[string]any)
	c := child["certificate"].(map[string]any)
	for _, field := range []string{"id", "domain", "parent", "kind"} {
		if !reflect.DeepEqual(c[field], r[field]) {
			return nil, mismatch
		}
	}
	parent := c["parent"].(map[string]any)
	if parent["kind"] != "identity" || len(certificates) < 2 {
		return nil, idCertificateRefusal("invalid_shape")
	}
	parentID := parent["id"].(string)
	if evidence == nil {
		return nil, idCertificateRefusal("evidence_unavailable")
	}
	// The verdict below refuses evidence outside the cache bounds.
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return nil, err
	}
	current, err := status.currentKey(parentID)
	if err != nil {
		return nil, err
	}
	parentBundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates[:len(certificates)-1]}
	verdict := VerifyIDChain(parentBundle, IDChainSubject{ID: parentID, DIDKey: current}, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, idCertificateRefusal(verdict.Reason)
	}
	// Parsing verified the child's signature under its own issuer_key.
	if c["issuer_key"] != current {
		return nil, idCertificateRefusal("stale_issuer_key")
	}
	return &IDCertificateImport{Chain: chain, Certificate: child, RegistrationPending: strings.HasPrefix(c["id"].(string), "did:aw:")}, nil
}
