package awid

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

type idNamespaceEpoch struct {
	Seq          int     `json:"seq"`
	DIDKey       string  `json:"did_key"`
	RegisteredAt string  `json:"registered_at"`
	RetiredAt    *string `json:"retired_at"`
	Continuity   string  `json:"continuity"`
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
}
type idStatusRevocation struct {
	RevokedAt     string `json:"revoked_at"`
	EffectiveFrom string `json:"effective_from"`
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
func idKnownTime(s string) time.Time { t, _ := idWitness(s); return t }
func idStatusFields(v any, fields string) bool {
	m, ok := v.(map[string]any)
	return ok && idCertificateExactFields(m, strings.Fields(fields)...)
}
func idStatusRequired(s map[string]any) bool {
	if !idStatusFields(s, "v domain observed_at namespace identities missing") || (!idStatusFields(s["namespace"], "epochs") && !idStatusFields(s["namespace"], "epochs delegation")) {
		return false
	}
	namespace := s["namespace"].(map[string]any)
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
		row := r.(map[string]any)
		ks, ok := row["key_history"].([]any)
		if !ok {
			return false
		}
		for _, k := range ks {
			if !idStatusFields(k, "entry registered_at") || !idStatusFields(k.(map[string]any)["entry"], "seq operation previous_did_key new_did_key prev_entry_hash entry_hash state_hash authorized_by signature timestamp") {
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
func parseIDStatus(e *IDChainEvidence, domain string) (*idStatusSnapshot, error) {
	bad := idCertificateRefusal(IDRefusalEvidenceUnavailable)
	raw, err := idCertificateCanonical(e.Status)
	if err != nil || len(raw) > 131072 || !idStatusRequired(e.Status) {
		return nil, bad
	}
	var s idStatusSnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.V != 1 || s.Domain != domain {
		return nil, bad
	}
	s.now, err = idWitness(s.ObservedAt)
	if err != nil {
		return nil, bad
	}
	epochs := s.Namespace.Epochs
	if len(epochs) == 0 || epochs[0].Continuity != "replaced" {
		return nil, bad
	}
	for n, epoch := range epochs {
		start, er := idWitness(epoch.RegisteredAt)
		if er != nil || start.After(s.now) || epoch.Seq != n+1 || !idCertificateIDValid(epoch.DIDKey, true) || (epoch.Continuity != "rotated" && epoch.Continuity != "replaced") {
			return nil, bad
		}
		if epoch.RetiredAt != nil {
			end, er := idWitness(*epoch.RetiredAt)
			if er != nil || end.Before(start) || end.After(s.now) {
				return nil, bad
			}
		}
		if n > 0 {
			prev := epochs[n-1]
			if prev.RetiredAt == nil || idKnownTime(*prev.RetiredAt).After(start) {
				return nil, bad
			}
			if epoch.Continuity == "rotated" && *prev.RetiredAt != epoch.RegisteredAt {
				return nil, bad
			}
		}
		if epoch.Continuity == "replaced" {
			s.cutoff = start
		}
	}
	last := epochs[len(epochs)-1]
	a := e.NamespaceAuthority
	if last.RetiredAt != nil || !idStatusFields(a, "domain dns_name inherited controller_key") || a["domain"] != domain {
		return nil, bad
	}
	dnsName, nameOK := a["dns_name"].(string)
	controller, keyOK := a["controller_key"].(string)
	inherited, inheritedOK := a["inherited"].(bool)
	if !nameOK || !keyOK || !inheritedOK || verifyIDNamespaceAuthority(domain, DomainAuthority{DNSName: dnsName, ControllerDID: controller, Inherited: inherited}, last.DIDKey, s.Namespace.Delegation) != nil {
		return nil, bad
	}
	s.byID = map[string]*idStatusIdentity{}
	s.missing = map[string]bool{}
	for n := range s.Identities {
		row := &s.Identities[n]
		if !idCertificateIDValid(row.ID, false) || !strings.HasPrefix(row.ID, "did:aw:") || s.byID[row.ID] != nil || len(row.KeyHistory) == 0 || row.CurrentKeySeq != len(row.KeyHistory) || len(row.Certificates) == 0 {
			return nil, bad
		}
		entries := []DidKeyEvidence{}
		for _, k := range row.KeyHistory {
			if _, er := idWitness(k.RegisteredAt); er != nil {
				return nil, bad
			}
			if !idCertificateIDValid(k.Entry.NewDIDKey, true) || !idCertificateIDValid(k.Entry.AuthorizedBy, true) {
				return nil, bad
			}
			entries = append(entries, k.Entry)
		}
		// Reuse the released genesis-anchored DID-log verifier; its old timestamps
		// are continuity only. The gate's witnessed issuer_key_seq selects the key.
		if _, er := VerifyDidLogEntries(row.ID, entries, s.now); er != nil {
			return nil, bad
		}
		seen := map[string]bool{}
		for i, rev := range row.Certificates {
			c, er := idCertificateShape(rev.Signed)
			if er != nil || VerifyIDCertificate(rev.Signed, c["issuer_key"].(string)) != nil || c["id"] != row.ID || c["domain"] != domain || rev.IssuerKeySeq < 1 || int64(rev.IssuerKeySeq) > maxSafeInteger {
				return nil, bad
			}
			digest, er := IDCertificateID(c)
			if er != nil || seen[digest] {
				return nil, bad
			}
			seen[digest] = true
			start, er := idWitness(rev.RegisteredAt)
			if er != nil || start.After(s.now) {
				return nil, bad
			}
			if rev.SupersededAt != nil {
				end, er := idWitness(*rev.SupersededAt)
				if er != nil || !end.After(start) || end.After(s.now) {
					return nil, bad
				}
			}
			if i > 0 {
				prev := row.Certificates[i-1]
				if prev.SupersededAt == nil || *prev.SupersededAt != rev.RegisteredAt {
					return nil, bad
				}
			}
			if c["parent"].(map[string]any)["kind"] == "namespace" {
				if rev.IssuerKeySeq > len(epochs) {
					return nil, bad
				}
				epoch := epochs[rev.IssuerKeySeq-1]
				if start.Before(idKnownTime(epoch.RegisteredAt)) || (epoch.RetiredAt != nil && !start.Before(idKnownTime(*epoch.RetiredAt))) || c["issuer_key"] != epoch.DIDKey {
					return nil, bad
				}
			}
		}
		current := row.Certificates[len(row.Certificates)-1]
		digest, _ := IDCertificateID(current.Signed["certificate"].(map[string]any))
		if current.SupersededAt != nil || row.CurrentCertificateID != digest {
			return nil, bad
		}
		if row.Revocation != nil {
			at, er := idWitness(row.Revocation.RevokedAt)
			effective, ee := idWitness(row.Revocation.EffectiveFrom)
			if er != nil || ee != nil || at.After(s.now) || effective.After(at) {
				return nil, bad
			}
		}
		s.byID[row.ID] = row
	}
	for _, row := range s.Identities {
		for _, rev := range row.Certificates {
			c := rev.Signed["certificate"].(map[string]any)
			parent := c["parent"].(map[string]any)
			if parent["kind"] == "identity" {
				if p := s.byID[parent["id"].(string)]; p != nil {
					if rev.IssuerKeySeq > len(p.KeyHistory) || c["issuer_key"] != p.KeyHistory[rev.IssuerKeySeq-1].Entry.NewDIDKey {
						return nil, bad
					}
				}
			}
		}
	}
	for _, id := range s.Missing {
		if !idCertificateIDValid(id, false) || !strings.HasPrefix(id, "did:aw:") || s.byID[id] != nil || s.missing[id] {
			return nil, bad
		}
		s.missing[id] = true
	}
	return &s, nil
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
		if !at.Before(idKnownTime(r.RegisteredAt)) && (r.SupersededAt == nil || at.Before(idKnownTime(*r.SupersededAt))) {
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
func (s *idStatusSnapshot) issuer(c map[string]any, r *idStatusRevision) (string, error) {
	p := c["parent"].(map[string]any)
	if p["kind"] == "namespace" {
		if r == nil {
			return s.Namespace.Epochs[len(s.Namespace.Epochs)-1].DIDKey, nil
		}
		if r.IssuerKeySeq > len(s.Namespace.Epochs) {
			return "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		return s.Namespace.Epochs[r.IssuerKeySeq-1].DIDKey, nil
	}
	id := p["id"].(string)
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
