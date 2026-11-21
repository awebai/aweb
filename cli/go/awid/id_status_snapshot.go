package awid

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type idNamespaceContinuity string

const (
	idNamespaceReplaced idNamespaceContinuity = "replaced"
	idNamespaceRotated  idNamespaceContinuity = "rotated"
)

type idWitnessInterval struct {
	from  time.Time
	until *time.Time
}

type idNamespaceEpoch struct {
	Seq          int                   `json:"seq"`
	DIDKey       string                `json:"did_key"`
	RegisteredAt string                `json:"registered_at"`
	RetiredAt    *string               `json:"retired_at"`
	Continuity   idNamespaceContinuity `json:"continuity"`
	validity     idWitnessInterval
}
type idStatusKey struct {
	Entry        DidKeyEvidence `json:"entry"`
	RegisteredAt string         `json:"registered_at"`
}
type idStatusRevision struct {
	Signed       map[string]any `json:"signed"`
	RegisteredAt string         `json:"registered_at"`
	SupersededAt *string        `json:"superseded_at"`
	IssuerKeySeq int            `json:"issuer_key_seq"`
	certificate  IDCertificateView
	validity     idWitnessInterval
}
type idStatusRevocation struct {
	RevokedAt     string `json:"revoked_at"`
	EffectiveFrom string `json:"effective_from"`
	effectiveAt   time.Time
}
type idStatusIdentity struct {
	ID                   string              `json:"id"`
	CurrentCertificateID string              `json:"current_certificate_id"`
	CurrentKeySeq        int                 `json:"current_key_seq"`
	KeyHistory           []idStatusKey       `json:"key_history"`
	Certificates         []idStatusRevision  `json:"certificates"`
	Revocation           *idStatusRevocation `json:"revocation"`
}
type idStatusSnapshot struct {
	V          int    `json:"v"`
	Domain     string `json:"domain"`
	ObservedAt string `json:"observed_at"`
	Namespace  struct {
		Epochs     []idNamespaceEpoch `json:"epochs"`
		Delegation map[string]any     `json:"delegation,omitempty"`
	} `json:"namespace"`
	Identities []idStatusIdentity `json:"identities"`
	Missing    []string           `json:"missing"`
	now        time.Time
	cutoff     time.Time
	byID       map[string]*idStatusIdentity
	missing    map[string]bool
}

func idWitness(s string) (time.Time, error) {
	if len(s) != 27 || s[26] != 'Z' {
		return time.Time{}, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	t, e := time.Parse("2006-01-02T15:04:05.000000Z", s)
	if e != nil || t.Year() < 1 {
		return time.Time{}, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	return t, nil
}

func idStatusFields(v any, fields string) bool {
	m, ok := v.(map[string]any)
	return ok && idCertificateExactFields(m, strings.Fields(fields)...)
}
func idStatusRequired(s map[string]any) bool {
	if !idStatusFields(s, "v domain observed_at namespace identities missing") || (!idStatusFields(s["namespace"], "epochs") && !idStatusFields(s["namespace"], "epochs delegation")) {
		return false
	}
	namespace, ok := s["namespace"].(map[string]any)
	if !ok {
		return false
	}
	if delegation, present := namespace["delegation"]; present && !idStatusFields(delegation, "parent_domain parent_controller_key controller_key") {
		return false
	}
	epochs, ok := namespace["epochs"].([]any)
	if !ok {
		return false
	}
	for _, e := range epochs {
		if !idStatusFields(e, "seq did_key registered_at retired_at continuity") {
			return false
		}
	}
	rows, ok := s["identities"].([]any)
	if !ok {
		return false
	}
	if _, ok = s["missing"].([]any); !ok {
		return false
	}
	for _, r := range rows {
		if !idStatusFields(r, "id current_certificate_id current_key_seq key_history certificates revocation") {
			return false
		}
		row, ok := r.(map[string]any)
		if !ok {
			return false
		}
		ks, ok := row["key_history"].([]any)
		if !ok {
			return false
		}
		for _, k := range ks {
			key, ok := k.(map[string]any)
			if !ok || !idStatusFields(key, "entry registered_at") || !idStatusFields(key["entry"], "seq operation previous_did_key new_did_key prev_entry_hash entry_hash state_hash authorized_by signature timestamp") {
				return false
			}
		}
		cs, ok := row["certificates"].([]any)
		if !ok {
			return false
		}
		for _, c := range cs {
			if !idStatusFields(c, "signed registered_at superseded_at issuer_key_seq") {
				return false
			}
		}
		if row["revocation"] != nil && !idStatusFields(row["revocation"], "revoked_at effective_from") {
			return false
		}
	}
	return true
}

// idStatusReadError keeps the released refusal while identifying the failed
// snapshot rule for typed-verdict diagnostics. It contains no response payload.
type idStatusReadError struct{ rule string }

// Error returns the public evidence-unavailable refusal without snapshot data.
func (err *idStatusReadError) Error() string { return string(IDRefusalEvidenceUnavailable) }

// Unwrap preserves the public IDCertificateError for typed refusal accessors.
func (err *idStatusReadError) Unwrap() error {
	return idCertificateRefusal(IDRefusalEvidenceUnavailable)
}
func idStatusRefusal(rule string) error { return &idStatusReadError{rule: rule} }
func idStatusDiagnostic(err error) string {
	var refusal *idStatusReadError
	if errors.As(err, &refusal) {
		return refusal.rule
	}
	return ""
}

// parseIDStatus reads one complete snapshot before any chain can consume its
// facts (docs/id-certificates.md §4). Each check owns one group of invariants.
func parseIDStatus(evidence *IDChainEvidence, domain string) (*idStatusSnapshot, error) {
	raw, err := idCertificateCanonical(evidence.Status)
	if err != nil || len(raw) > 131072 || !idStatusRequired(evidence.Status) {
		return nil, idStatusRefusal("snapshot fields or encoding")
	}
	var snapshot idStatusSnapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, idStatusRefusal("snapshot field types")
	}
	if snapshot.V != 1 || snapshot.Domain != domain {
		return nil, idStatusRefusal("snapshot version or namespace")
	}
	snapshot.now, err = idWitness(snapshot.ObservedAt)
	if err != nil {
		return nil, idStatusRefusal("snapshot observation witness")
	}
	if err := snapshot.checkEpochs(); err != nil {
		return nil, err
	}
	if err := snapshot.checkNamespaceAuthority(evidence.NamespaceAuthority); err != nil {
		return nil, err
	}
	snapshot.byID = make(map[string]*idStatusIdentity)
	snapshot.missing = make(map[string]bool)
	for index := range snapshot.Identities {
		row := &snapshot.Identities[index]
		if err := snapshot.checkIdentityRow(row); err != nil {
			return nil, err
		}
		snapshot.byID[row.ID] = row
	}
	if err := snapshot.checkIssuerKeys(); err != nil {
		return nil, err
	}
	if err := snapshot.checkMissingIdentities(); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func (snapshot *idStatusSnapshot) checkEpochs() error {
	epochs := snapshot.Namespace.Epochs
	if len(epochs) == 0 || epochs[0].Continuity != idNamespaceReplaced {
		return idStatusRefusal("namespace initial epoch")
	}
	for index := range epochs {
		epoch := &epochs[index]
		start, err := idWitness(epoch.RegisteredAt)
		if err != nil || start.After(snapshot.now) {
			return idStatusRefusal("namespace epoch start")
		}
		if epoch.Seq != index+1 || !idCertificateIDValid(epoch.DIDKey, true) {
			return idStatusRefusal("namespace epoch sequence or key")
		}
		if epoch.Continuity != idNamespaceRotated && epoch.Continuity != idNamespaceReplaced {
			return idStatusRefusal("namespace continuity kind")
		}
		epoch.validity.from = start
		if epoch.RetiredAt != nil {
			end, err := idWitness(*epoch.RetiredAt)
			if err != nil || end.Before(start) || end.After(snapshot.now) {
				return idStatusRefusal("namespace epoch retirement")
			}
			epoch.validity.until = &end
		}
		if index > 0 {
			previous := epochs[index-1]
			if previous.validity.until == nil || previous.validity.until.After(start) {
				return idStatusRefusal("namespace epoch overlap")
			}
			if epoch.Continuity == idNamespaceRotated && *previous.RetiredAt != epoch.RegisteredAt {
				return idStatusRefusal("namespace rotation boundary")
			}
		}
		if epoch.Continuity == idNamespaceReplaced {
			snapshot.cutoff = start
		}
	}
	return nil
}

func (snapshot *idStatusSnapshot) checkNamespaceAuthority(authority map[string]any) error {
	last := snapshot.Namespace.Epochs[len(snapshot.Namespace.Epochs)-1]
	if last.RetiredAt != nil || !idStatusFields(authority, "domain dns_name inherited controller_key") || authority["domain"] != snapshot.Domain {
		return idStatusRefusal("current namespace epoch or authority fields")
	}
	dnsName, nameOK := authority["dns_name"].(string)
	controller, keyOK := authority["controller_key"].(string)
	inherited, inheritedOK := authority["inherited"].(bool)
	if !nameOK || !keyOK || !inheritedOK {
		return idStatusRefusal("namespace authority field types")
	}
	if err := verifyIDNamespaceAuthority(snapshot.Domain, DomainAuthority{DNSName: dnsName, ControllerDID: controller, Inherited: inherited}, last.DIDKey, snapshot.Namespace.Delegation); err != nil {
		return idStatusRefusal("current namespace authority")
	}
	return nil
}

func (snapshot *idStatusSnapshot) checkIdentityRow(row *idStatusIdentity) error {
	if !idCertificateIDValid(row.ID, false) || !strings.HasPrefix(row.ID, "did:aw:") || snapshot.byID[row.ID] != nil {
		return idStatusRefusal("registered identity or duplicate row")
	}
	if len(row.KeyHistory) == 0 || row.CurrentKeySeq != len(row.KeyHistory) || len(row.Certificates) == 0 {
		return idStatusRefusal("identity history or current sequence")
	}
	entries := make([]DidKeyEvidence, 0, len(row.KeyHistory))
	for _, key := range row.KeyHistory {
		if _, err := idWitness(key.RegisteredAt); err != nil {
			return idStatusRefusal("identity key registration witness")
		}
		if !idCertificateIDValid(key.Entry.NewDIDKey, true) || !idCertificateIDValid(key.Entry.AuthorizedBy, true) {
			return idStatusRefusal("identity history key")
		}
		entries = append(entries, key.Entry)
	}
	// Registry registration witnesses select issuer_key_seq; DID-log timestamps
	// establish continuity through the existing genesis-anchored verifier.
	if _, err := VerifyDidLogEntries(row.ID, entries, snapshot.now); err != nil {
		return idStatusRefusal("identity key continuity")
	}
	if err := snapshot.checkIdentityCertificates(row); err != nil {
		return err
	}
	if row.Revocation != nil {
		revokedAt, err := idWitness(row.Revocation.RevokedAt)
		if err != nil {
			return idStatusRefusal("identity revocation witness")
		}
		effectiveAt, err := idWitness(row.Revocation.EffectiveFrom)
		if err != nil || revokedAt.After(snapshot.now) || effectiveAt.After(revokedAt) {
			return idStatusRefusal("identity revocation boundary")
		}
		row.Revocation.effectiveAt = effectiveAt
	}
	return nil
}

func (snapshot *idStatusSnapshot) checkIdentityCertificates(row *idStatusIdentity) error {
	seen := make(map[string]bool)
	for index := range row.Certificates {
		revision := &row.Certificates[index]
		certificate, err := checkedIDCertificateView(revision.Signed)
		if err != nil {
			return idStatusRefusal("identity certificate shape")
		}
		if err := VerifyIDCertificate(revision.Signed, certificate.IssuerKey()); err != nil {
			return idStatusRefusal("identity certificate signature")
		}
		if certificate.ID() != row.ID || certificate.Domain() != snapshot.Domain || revision.IssuerKeySeq < 1 || int64(revision.IssuerKeySeq) > maxSafeInteger {
			return idStatusRefusal("identity certificate binding or issuer sequence")
		}
		revision.certificate = certificate
		digest, err := certificate.CertificateID()
		if err != nil || seen[digest] {
			return idStatusRefusal("identity certificate commitment or duplicate")
		}
		seen[digest] = true
		start, err := idWitness(revision.RegisteredAt)
		if err != nil || start.After(snapshot.now) {
			return idStatusRefusal("certificate registration witness")
		}
		revision.validity.from = start
		if revision.SupersededAt != nil {
			end, err := idWitness(*revision.SupersededAt)
			if err != nil || !end.After(start) || end.After(snapshot.now) {
				return idStatusRefusal("certificate supersession witness")
			}
			revision.validity.until = &end
		}
		if index > 0 {
			previous := row.Certificates[index-1]
			if previous.SupersededAt == nil || *previous.SupersededAt != revision.RegisteredAt {
				return idStatusRefusal("certificate revision boundary")
			}
		}
		if certificate.Parent().Kind() == IDParentKindNamespace {
			if revision.IssuerKeySeq > len(snapshot.Namespace.Epochs) {
				return idStatusRefusal("certificate namespace issuer sequence")
			}
			epoch := snapshot.Namespace.Epochs[revision.IssuerKeySeq-1]
			if start.Before(epoch.validity.from) || (epoch.validity.until != nil && !start.Before(*epoch.validity.until)) || certificate.IssuerKey() != epoch.DIDKey {
				return idStatusRefusal("certificate namespace issuer epoch")
			}
		}
	}
	current := row.Certificates[len(row.Certificates)-1]
	if current.SupersededAt != nil || !idCurrentCertificateMatches(current.certificate.Fields(), row.CurrentCertificateID) {
		return idStatusRefusal("identity current certificate head")
	}
	return nil
}

func (snapshot *idStatusSnapshot) checkIssuerKeys() error {
	for _, row := range snapshot.Identities {
		for _, revision := range row.Certificates {
			parent := revision.certificate.Parent()
			if parent.Kind() != IDParentKindIdentity {
				continue
			}
			if issuer := snapshot.byID[parent.ID()]; issuer != nil {
				if revision.IssuerKeySeq > len(issuer.KeyHistory) || revision.certificate.IssuerKey() != issuer.KeyHistory[revision.IssuerKeySeq-1].Entry.NewDIDKey {
					return idStatusRefusal("certificate parent issuer key")
				}
			}
		}
	}
	return nil
}

func (snapshot *idStatusSnapshot) checkMissingIdentities() error {
	for _, id := range snapshot.Missing {
		if !idCertificateIDValid(id, false) || !strings.HasPrefix(id, "did:aw:") || snapshot.byID[id] != nil || snapshot.missing[id] {
			return idStatusRefusal("missing identity binding or duplicate")
		}
		snapshot.missing[id] = true
	}
	return nil
}
func (s *idStatusSnapshot) row(id string) (*idStatusIdentity, error) {
	if s.missing[id] {
		return nil, idCertificateRefusal(IDRefusalUnregisteredIdentity)
	}
	r := s.byID[id]
	if r == nil {
		return nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	return r, nil
}
func (s *idStatusSnapshot) revision(id string, at time.Time) (*idStatusRevision, error) {
	row, err := s.row(id)
	if err != nil {
		return nil, err
	}
	for n := range row.Certificates {
		r := &row.Certificates[n]
		if !at.Before(r.validity.from) && (r.validity.until == nil || at.Before(*r.validity.until)) {
			return r, nil
		}
	}
	return nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
}
func (s *idStatusSnapshot) currentKey(id string) (string, error) {
	if strings.HasPrefix(id, "did:key:") {
		return id, nil
	}
	r, e := s.row(id)
	if e != nil {
		return "", e
	}
	return r.KeyHistory[len(r.KeyHistory)-1].Entry.NewDIDKey, nil
}
func (s *idStatusSnapshot) issuer(certificate IDCertificateView, r *idStatusRevision) (string, error) {
	parent := certificate.Parent()
	if parent.Kind() == IDParentKindNamespace {
		if r == nil {
			return s.Namespace.Epochs[len(s.Namespace.Epochs)-1].DIDKey, nil
		}
		if r.IssuerKeySeq > len(s.Namespace.Epochs) {
			return "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		return s.Namespace.Epochs[r.IssuerKeySeq-1].DIDKey, nil
	}
	id := parent.ID()
	if r != nil {
		if strings.HasPrefix(id, "did:key:") {
			return "", idCertificateRefusal(IDRefusalUnregisteredParent)
		}
		row, err := s.row(id)
		if err != nil {
			return "", err
		}
		if r.IssuerKeySeq > len(row.KeyHistory) {
			return "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		return row.KeyHistory[r.IssuerKeySeq-1].Entry.NewDIDKey, nil
	}
	return s.currentKey(id)
}
