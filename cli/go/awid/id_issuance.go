package awid

// The parent signer's durable issuance record (docs/id-certificates.md §3 and
// §6). Every certificate a signer releases goes through issueIDCertificate,
// which records it before returning, so a later re-sign can find it.
import (
	"crypto/ed25519"
	"encoding/base64"
	"time"
)

// IDCertificateSigner signs exact bytes and returns the signing did:key with
// the raw 64-byte Ed25519 signature. No private key crosses this boundary.
type IDCertificateSigner func(payload []byte) (didKey string, signature []byte, err error)

// KeySigner signs with key held in this process, such as the namespace
// controller key.
func KeySigner(key ed25519.PrivateKey) IDCertificateSigner {
	return func(payload []byte) (string, []byte, error) {
		return ComputeDIDKey(key.Public().(ed25519.PublicKey)), ed25519.Sign(key, payload), nil
	}
}

// IDIssuanceEntry records one certificate the signer issued. A re-sign
// request for that certificate attaches to its entry.
type IDIssuanceEntry struct {
	CertificateID string           `json:"certificate_id"`
	Signed        map[string]any   `json:"signed"`
	RecordedAt    string           `json:"recorded_at,omitempty"`
	Resign        *IDRequestRecord `json:"resign,omitempty"`
}

// IDRequestRecord is one child request exchange, the re-sign of an issued
// certificate or the issue under an invitation: pending, then issued with its
// exact response, or failed.
type IDRequestRecord struct {
	RequestID        string `json:"request_id"`
	Request          string `json:"request"`
	State            string `json:"state"`
	Response         string `json:"response,omitempty"`
	NewCertificateID string `json:"new_certificate_id,omitempty"`
}

const (
	IDRequestPending = "pending"
	IDRequestIssued  = "issued"
	IDRequestFailed  = "failed"
)

// IDIssuanceStore persists issuance entries durably. Callers hold the
// identity's transaction lock across a read-modify-write.
type IDIssuanceStore interface {
	Entry(certificateID string) (*IDIssuanceEntry, error)
	EntryForRequest(requestID string) (*IDIssuanceEntry, error)
	Put(entry *IDIssuanceEntry) error
}

// issueIDCertificate signs certificate with the current key, verifies the
// result, and hands it to commit, which must record it durably. Nothing is
// returned to the caller unless commit succeeded.
func issueIDCertificate(certificate map[string]any, current string, sign IDCertificateSigner, commit func(signed map[string]any, id string) error) (map[string]any, error) {
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
	if err = commit(signed, id); err != nil {
		return nil, err
	}
	return signed, nil
}

// recordIssued is the commit for a newly issued certificate.
func recordIssued(store IDIssuanceStore, now time.Time) func(map[string]any, string) error {
	return func(signed map[string]any, id string) error {
		return store.Put(&IDIssuanceEntry{CertificateID: id, Signed: signed, RecordedAt: idRecordTime(now)})
	}
}

func idRecordTime(now time.Time) string { return now.UTC().Format("2006-01-02T15:04:05Z") }

// idIssuanceRecorded is provenance: an entry exists under id, its stored
// certificate re-derives exactly that id, and it verifies under a key from
// the parent's own history. The entry's name and time prove nothing.
func idIssuanceRecorded(store IDIssuanceStore, parent *idStatusIdentity, id string) error {
	refused := idCertificateRefusal("issuance_not_recorded")
	entry, err := store.Entry(id)
	if err != nil {
		return err
	}
	if entry == nil {
		return refused
	}
	c, err := idCertificateShape(entry.Signed)
	if err != nil {
		return refused
	}
	if stored, err := IDCertificateID(c); err != nil || stored != id {
		return refused
	}
	issuer := c["issuer_key"].(string)
	if !parentKeyHistoryHas(parent, issuer) || VerifyIDCertificate(entry.Signed, issuer) != nil {
		return refused
	}
	return nil
}
