package awid

// Re-signing an unregistered local child after its parent rotated
// (docs/id-certificates.md §3, "Key rotation and re-sign"). The parent signs
// the same id/domain/parent/kind with its current key, only for a certificate
// its own signer issued.
import (
	"reflect"
	"strings"
	"time"
)

// IDResignRequest is what a child presents on contact: its old signed
// certificate, the binding it asks to have signed, and the did:key it proved.
type IDResignRequest struct {
	Signed     map[string]any
	Requested  map[string]any
	SubjectKey string
}

// ResignIDCertificate returns the re-signed certificate after recording it in
// the issuance store. Every refusal happens before the signer runs.
func ResignIDCertificate(req IDResignRequest, parentID string, evidence *IDChainEvidence, domain string, store IDIssuanceStore, sign IDCertificateSigner, now time.Time) (map[string]any, error) {
	return resignIDCertificate(req, parentID, nil, evidence, domain, store, sign, now, recordIssued(store, now))
}

func resignIDCertificate(req IDResignRequest, parentID string, parentChain []any, evidence *IDChainEvidence, domain string, store IDIssuanceStore, sign IDCertificateSigner, now time.Time, commit func(map[string]any, string) error) (map[string]any, error) {
	previous, err := checkedIDCertificateView(req.Signed)
	if err != nil {
		return nil, err
	}
	old := previous.Fields()
	if !idCertificateExactFields(req.Requested, "id", "domain", "parent", "kind") {
		return nil, idCertificateRefusal(IDRefusalResignBindingMismatch)
	}
	for field, value := range req.Requested {
		if !reflect.DeepEqual(old[field], value) {
			return nil, idCertificateRefusal(IDRefusalResignBindingMismatch)
		}
	}
	if !reflect.DeepEqual(old["parent"], map[string]any{"kind": "identity", "id": parentID}) {
		return nil, idCertificateRefusal(IDRefusalResignBindingMismatch)
	}
	var current string
	var keyInHistory func(string) bool
	if strings.HasPrefix(parentID, "did:key:") {
		current, err = idIssuingKey(map[string]any{"kind": "identity", "id": parentID}, domain, "agent", parentChain, evidence)
		keyInHistory = func(key string) bool { return key == parentID }
	} else {
		var parent *idStatusIdentity
		parent, current, _, err = idSigningParent(parentID, evidence, domain)
		keyInHistory = func(key string) bool { return parentKeyHistoryHas(parent, key) }
	}
	if err != nil {
		return nil, err
	}
	if req.SubjectKey == "" || req.SubjectKey != old["id"] {
		return nil, idCertificateRefusal(IDRefusalSubjectMismatch)
	}
	if !keyInHistory(previous.IssuerKey()) {
		return nil, idCertificateRefusal(IDRefusalInvalidSignature)
	}
	if err = VerifyIDCertificate(req.Signed, previous.IssuerKey()); err != nil {
		return nil, err
	}
	oldID, err := IDCertificateID(old)
	if err != nil {
		return nil, err
	}
	if err = idIssuanceRecordedByKey(store, oldID, keyInHistory); err != nil {
		return nil, err
	}

	certificate := map[string]any{}
	for field, value := range old {
		certificate[field] = value
	}
	certificate["issuer_key"] = current
	certificate["issued_at"] = idRecordTime(now)
	return issueIDCertificate(certificate, current, sign, commit)
}

// idSigningParent checks an identity parent about to sign a child: usable
// evidence, not revoked, and its whole current chain valid, as at AWID
// registration. It returns the parent's status row, current key and kind.
func idSigningParent(parentID string, evidence *IDChainEvidence, domain string) (*idStatusIdentity, string, string, error) {
	if evidence == nil {
		return nil, "", "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	if err := idEvidenceUsable(evidence); err != nil {
		return nil, "", "", err
	}
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return nil, "", "", err
	}
	parent, err := status.row(parentID)
	if err != nil {
		return nil, "", "", err
	}
	if parent.Revocation != nil {
		return nil, "", "", idCertificateRefusal(IDRefusalParentRevoked)
	}
	current, err := status.currentKey(parentID)
	if err != nil {
		return nil, "", "", err
	}
	verdict := VerifyIDChain(nil, IDChainSubject{ID: parentID, DIDKey: current}, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid || verdict.Kind == nil {
		return nil, "", "", idCertificateRefusal(IDRefusal(verdict.Reason))
	}
	return parent, current, *verdict.Kind, nil
}

func parentKeyHistoryHas(parent *idStatusIdentity, key string) bool {
	for _, k := range parent.KeyHistory {
		if k.Entry.NewDIDKey == key {
			return true
		}
	}
	return false
}
