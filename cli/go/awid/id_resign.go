package awid

// Re-signing an unregistered local child after its parent rotated
// (docs/id-certificates.md §3, "Key rotation and re-sign"). The parent signs
// the same id/domain/parent/kind with its current key, only for a certificate
// its own signer issued.
import (
	"encoding/base64"
	"reflect"
	"time"
)

// IDCertificateSigner signs exact bytes and returns the signing did:key with
// the raw 64-byte Ed25519 signature. No private key crosses this boundary.
type IDCertificateSigner func(payload []byte) (didKey string, signature []byte, err error)

// IDIssuanceLog is the parent signer's durable record of the certificates it
// issued. Entries survive rotation and are never seeded from a submission.
type IDIssuanceLog interface {
	Recorded(certificateID string) (bool, error)
	Record(certificateID string) error
}

// IDResignRequest is what a child presents on contact: its old signed
// certificate, the binding it asks to have signed, and the did:key it proved.
type IDResignRequest struct {
	Signed     map[string]any
	Requested  map[string]any
	SubjectKey string
}

// ResignIDCertificate returns the re-signed certificate after recording it in
// the issuance log. Every refusal happens before the signer runs.
func ResignIDCertificate(req IDResignRequest, parentID string, evidence *IDChainEvidence, domain string, log IDIssuanceLog, sign IDCertificateSigner, now time.Time) (map[string]any, error) {
	old, err := idCertificateShape(req.Signed)
	if err != nil {
		return nil, err
	}
	if !idCertificateExactFields(req.Requested, "id", "domain", "parent", "kind") {
		return nil, idCertificateRefusal("resign_binding_mismatch")
	}
	for field, value := range req.Requested {
		if !reflect.DeepEqual(old[field], value) {
			return nil, idCertificateRefusal("resign_binding_mismatch")
		}
	}
	if !reflect.DeepEqual(old["parent"], map[string]any{"kind": "identity", "id": parentID}) {
		return nil, idCertificateRefusal("resign_binding_mismatch")
	}
	if evidence == nil {
		return nil, idCertificateRefusal("evidence_unavailable")
	}
	if err = idEvidenceUsable(evidence); err != nil {
		return nil, err
	}
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return nil, err
	}
	parent, err := status.row(parentID)
	if err != nil {
		return nil, err
	}
	if parent.Revocation != nil {
		return nil, idCertificateRefusal("parent_revoked")
	}
	current, err := status.currentKey(parentID)
	if err != nil {
		return nil, err
	}
	// The parent's whole current chain must be valid, as at AWID registration.
	verdict := VerifyIDChain(nil, IDChainSubject{ID: parentID, DIDKey: current}, evidence, domain)
	if verdict.IdentityValid == nil || !*verdict.IdentityValid {
		return nil, idCertificateRefusal(verdict.Reason)
	}
	if req.SubjectKey == "" || req.SubjectKey != old["id"] {
		return nil, idCertificateRefusal("subject_mismatch")
	}
	if !parentKeyHistoryHas(parent, old["issuer_key"].(string)) {
		return nil, idCertificateRefusal("invalid_signature")
	}
	if err = VerifyIDCertificate(req.Signed, old["issuer_key"].(string)); err != nil {
		return nil, err
	}
	oldID, err := IDCertificateID(old)
	if err != nil {
		return nil, err
	}
	recorded, err := log.Recorded(oldID)
	if err != nil {
		return nil, err
	}
	if !recorded {
		return nil, idCertificateRefusal("issuance_not_recorded")
	}

	certificate := map[string]any{}
	for field, value := range old {
		certificate[field] = value
	}
	certificate["issuer_key"] = current
	certificate["issued_at"] = now.UTC().Format("2006-01-02T15:04:05Z")
	payload, err := IDCertificateSigningBytes(certificate)
	if err != nil {
		return nil, err
	}
	signer, signature, err := sign(payload)
	if err != nil {
		return nil, err
	}
	if signer != current {
		return nil, idCertificateRefusal("issuer_key_not_current")
	}
	signed := map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(signature)}
	if err = VerifyIDCertificate(signed, current); err != nil {
		return nil, err
	}
	id, err := IDCertificateID(certificate)
	if err != nil {
		return nil, err
	}
	if err = log.Record(id); err != nil {
		return nil, err
	}
	return signed, nil
}

func parentKeyHistoryHas(parent *idStatusIdentity, key string) bool {
	for _, k := range parent.KeyHistory {
		if k.Entry.NewDIDKey == key {
			return true
		}
	}
	return false
}
