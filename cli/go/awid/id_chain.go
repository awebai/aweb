package awid

// Pure ID-tree authority verification. Status/DNS facts come only from the
// production cached resolver or a locked AWID transaction, never the carrier.
import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"time"
)

// IDChainSubject binds a chain's subject to its authenticated current key and,
// when present, to the independently verified team-certificate identity.
type IDChainSubject struct {
	ID               string `json:"id"`
	DIDKey           string `json:"did_key"`
	TeamMemberDIDAW  string `json:"team_member_did_aw"`
	TeamMemberDIDKey string `json:"team_member_did_key"`
}

// IDChainEvidence carries caller-selected registry/DNS facts and their age.
// An assertion's carrier cannot supply its own trust or choose the namespace.
type IDChainEvidence struct {
	Status             map[string]any
	NamespaceAuthority map[string]any
	AgeSeconds         *float64
}

// IDChainResult is the released string-based verdict profile. CheckIDChain
// returns the typed equivalent; its Legacy adapter preserves these JSON fields.
type IDChainResult struct {
	Outcome       string  `json:"outcome"`
	HumanID       *string `json:"human_id"`
	IdentityValid *bool   `json:"identity_valid"`
	Kind          *string `json:"kind"`
	Reason        string  `json:"reason"`
}

func idChainFailure(reason IDRefusal) IDChainVerdict {
	result := IDChainVerdict{Outcome: IDChainOutcomeUnknown, Refusal: reason}
	switch reason {
	case IDRefusalStatusExpired, IDRefusalEvidenceUnavailable:
		result.Outcome = IDChainOutcomeUnavailable
	case IDRefusalLegacyNoChain, IDRefusalUnregisteredIdentity:
	default:
		valid := false
		result.IdentityValid = &valid
	}
	return result
}

// StatusCacheFreshness applies the 60-second current-evidence window; future,
// missing and non-finite ages are unavailable rather than clamped.
func StatusCacheFreshness(age *float64) IDStatusFreshness {
	if age == nil || math.IsNaN(*age) || math.IsInf(*age, 0) || *age < 0 {
		return IDStatusUnavailable
	}
	if *age <= 60 {
		return IDStatusFresh
	}
	return IDStatusUnavailable
}

// IDStatusCacheMode preserves the released string result of StatusCacheFreshness.
func IDStatusCacheMode(age *float64) string { return string(StatusCacheFreshness(age)) }

// idEvidenceUsable refuses evidence that is not fresh: status_expired once it
// is older than the fresh window, evidence_unavailable otherwise.
func idEvidenceUsable(evidence *IDChainEvidence) error {
	if StatusCacheFreshness(evidence.AgeSeconds) != IDStatusUnavailable {
		return nil
	}
	if evidence.AgeSeconds != nil && !math.IsInf(*evidence.AgeSeconds, 0) && *evidence.AgeSeconds > 60 {
		return idCertificateRefusal(IDRefusalStatusExpired)
	}
	return idCertificateRefusal(IDRefusalEvidenceUnavailable)
}

// IDRequestInput makes the authentication and human-ancestry policies explicit.
// A chain result cannot substitute for the request's original authentication.
type IDRequestInput struct {
	Verdict              IDChainVerdict
	Subject              IDChainSubject
	AuthenticationPassed bool
	HumanRequired        bool
}

// DecideIDRequest applies docs/id-certificates.md §4's request policy to the
// verified result. A local key may continue with unavailable advisory ancestry;
// it cannot satisfy a human-required operation without verified human evidence.
func DecideIDRequest(in IDRequestInput) IDRequestAction {
	if !in.AuthenticationPassed {
		return IDRequestRefuse
	}
	verdict := in.Verdict
	valid := verdict.IdentityValid != nil && *verdict.IdentityValid
	if in.HumanRequired {
		if valid && verdict.Outcome == IDChainOutcomeNearestHuman {
			return IDRequestContinue
		}
		return IDRequestRefuse
	}
	if valid || verdict.Refusal == IDRefusalLegacyNoChain || verdict.Refusal == IDRefusalUnregisteredIdentity {
		return IDRequestContinue
	}
	if strings.HasPrefix(in.Subject.ID, "did:key:") && (verdict.Refusal == IDRefusalStaleIssuerKey || verdict.Refusal == IDRefusalStatusExpired || verdict.Refusal == IDRefusalEvidenceUnavailable) {
		return IDRequestContinue
	}
	return IDRequestRefuse
}

// IDRequestDisposition preserves the released positional API. New callers use
// DecideIDRequest so authentication and human requirements are named inputs.
func IDRequestDisposition(result IDChainResult, subject IDChainSubject, originalAuthPassed, humanRequired bool) string {
	return string(DecideIDRequest(IDRequestInput{
		Verdict: IDChainVerdict{Outcome: IDChainOutcome(result.Outcome), IdentityValid: result.IdentityValid, Refusal: IDRefusal(result.Reason)},
		Subject: subject, AuthenticationPassed: originalAuthPassed, HumanRequired: humanRequired,
	}))
}

// IDStatusRequest selects the domain and registered identity IDs needed to
// verify this exact subject. A nil request means advisory chainless local identity.
func IDStatusRequest(bundle map[string]any, subject IDChainSubject, domain string) (map[string]any, error) {
	if bundle == nil {
		if strings.HasPrefix(subject.ID, "did:key:") {
			return nil, nil
		}
		if domain == "" {
			return nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		if !idCertificateDomain(domain) {
			return nil, idCertificateRefusal(IDRefusalInvalidDomain)
		}
		return map[string]any{"v": 1, "domain": domain, "ids": []string{subject.ID}}, nil
	}
	if raw, err := idCertificateCanonical(bundle); err != nil {
		return nil, err
	} else if len(raw) > IDChainMaxBytes {
		return nil, idCertificateRefusal(IDRefusalBundleTooLarge)
	}
	if err := idCertificateBundleShape(bundle); err != nil {
		return nil, err
	}
	certs := idChainCertificates(bundle)
	selected := certs[0]["certificate"].(map[string]any)["domain"].(string)
	if domain != "" && domain != selected {
		return nil, idCertificateRefusal(IDRefusalDomainMismatch)
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, s := range certs {
		id := s["certificate"].(map[string]any)["id"].(string)
		if strings.HasPrefix(id, "did:aw:") && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return map[string]any{"v": 1, "domain": selected, "ids": ids}, nil
}
func idChainCertificates(bundle map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, s := range bundle["certificates"].([]any) {
		out = append(out, s.(map[string]any))
	}
	return out
}
func idChainStructure(certs []map[string]any) error {
	by := map[string]map[string]any{}
	for _, s := range certs {
		c := s["certificate"].(map[string]any)
		id := c["id"].(string)
		if by[id] != nil {
			return idCertificateRefusal(IDRefusalDuplicateId)
		}
		by[id] = c
	}
	for id := range by {
		seen := map[string]bool{}
		for by[id] != nil {
			if seen[id] {
				return idCertificateRefusal(IDRefusalCycle)
			}
			seen[id] = true
			p := by[id]["parent"].(map[string]any)
			if p["kind"] == "namespace" {
				break
			}
			id = p["id"].(string)
		}
	}
	domain := certs[0]["certificate"].(map[string]any)["domain"]
	for n, s := range certs {
		c := s["certificate"].(map[string]any)
		p := c["parent"].(map[string]any)
		if c["domain"] != domain {
			return idCertificateRefusal(IDRefusalDomainMismatch)
		}
		if n == 0 {
			if p["kind"] != "namespace" || p["id"] != domain {
				return idCertificateRefusal(IDRefusalMissingParent)
			}
		} else {
			prev := certs[n-1]["certificate"].(map[string]any)
			if p["kind"] != "identity" || p["id"] != prev["id"] {
				return idCertificateRefusal(IDRefusalMissingParent)
			}
			if c["kind"] == "human" && prev["kind"] != "human" {
				return idCertificateRefusal(IDRefusalHumanIssuerIsAgent)
			}
		}
	}
	return nil
}

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
func verifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) (IDChainVerdict, error) {
	bad := func(code IDRefusal) (IDChainVerdict, error) { return IDChainVerdict{}, idCertificateRefusal(code) }
	plan, err := IDStatusRequest(bundle, subject, domain)
	if err != nil {
		return IDChainVerdict{}, err
	}
	if plan == nil {
		return bad(IDRefusalLegacyNoChain)
	}
	domain = plan["domain"].(string)
	var certs []map[string]any
	if bundle != nil {
		raw, er := idCertificateCanonical(bundle)
		if er != nil {
			return IDChainVerdict{}, er
		}
		if len(raw) > IDChainMaxBytes {
			return bad(IDRefusalBundleTooLarge)
		}
		certs = idChainCertificates(bundle)
		if err = idChainStructure(certs); err != nil {
			return IDChainVerdict{}, err
		}
		if certs[len(certs)-1]["certificate"].(map[string]any)["id"] != subject.ID {
			return bad(IDRefusalSubjectMismatch)
		}
	}
	if (subject.TeamMemberDIDKey != "" && subject.TeamMemberDIDKey != subject.DIDKey) || (subject.TeamMemberDIDAW != "" && subject.TeamMemberDIDAW != subject.ID) || (strings.HasPrefix(subject.ID, "did:key:") && subject.ID != subject.DIDKey) {
		return bad(IDRefusalSubjectMismatch)
	}
	if evidence == nil {
		return bad(IDRefusalEvidenceUnavailable)
	}
	if err = idEvidenceUsable(evidence); err != nil {
		return IDChainVerdict{}, err
	}
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return IDChainVerdict{}, err
	}
	if strings.HasPrefix(subject.ID, "did:aw:") {
		key, err := status.currentKey(subject.ID)
		if err != nil {
			return IDChainVerdict{}, err
		}
		if key != subject.DIDKey {
			return bad(IDRefusalSubjectMismatch)
		}
	}
	if certs == nil {
		id := subject.ID
		seen := map[string]bool{}
		for {
			if seen[id] {
				return bad(IDRefusalCycle)
			}
			if len(certs) >= IDChainMaxDepth {
				return bad(IDRefusalDepthExceeded)
			}
			seen[id] = true
			r, err := status.revision(id, status.now)
			if err != nil {
				return IDChainVerdict{}, err
			}
			certs = append([]map[string]any{r.Signed}, certs...)
			p := r.Signed["certificate"].(map[string]any)["parent"].(map[string]any)
			if p["kind"] == "namespace" {
				break
			}
			id = p["id"].(string)
		}
		if err = idChainStructure(certs); err != nil {
			return IDChainVerdict{}, err
		}
	}
	by := map[string]map[string]any{}
	for _, signed := range certs {
		c := signed["certificate"].(map[string]any)
		id := c["id"].(string)
		by[id] = signed
		if strings.HasPrefix(id, "did:aw:") {
			row, err := status.row(id)
			if err != nil {
				return IDChainVerdict{}, err
			}
			digest, _ := IDCertificateID(c)
			if row.CurrentCertificateID != digest {
				return bad(IDRefusalSupersededCertificate)
			}
		}
	}
	for _, signed := range certs {
		c := signed["certificate"].(map[string]any)
		var r *idStatusRevision
		if strings.HasPrefix(c["id"].(string), "did:aw:") {
			r, err = status.revision(c["id"].(string), status.now)
			if err != nil {
				return IDChainVerdict{}, err
			}
		}
		key, err := status.issuer(c, r)
		if err != nil {
			return IDChainVerdict{}, err
		}
		if key != c["issuer_key"] {
			return bad(IDRefusalStaleIssuerKey)
		}
		if err = VerifyIDCertificate(signed, key); err != nil {
			return IDChainVerdict{}, err
		}
	}
	var evaluate func(string, time.Time, map[string]bool) (string, error)
	evaluate = func(id string, at time.Time, path map[string]bool) (string, error) {
		if path[id] {
			return "", idCertificateRefusal(IDRefusalCycle)
		}
		if len(path) >= IDChainMaxDepth {
			return "", idCertificateRefusal(IDRefusalDepthExceeded)
		}
		path[id] = true
		defer delete(path, id)
		var r *idStatusRevision
		var signed map[string]any
		if strings.HasPrefix(id, "did:aw:") {
			var err error
			r, err = status.revision(id, at)
			if err != nil {
				return "", err
			}
			signed = r.Signed
			if idKnownTime(r.RegisteredAt).Before(status.cutoff) {
				return "", idCertificateRefusal(IDRefusalRootReplaced)
			}
			row, _ := status.row(id)
			if row.Revocation != nil && !idKnownTime(row.Revocation.EffectiveFrom).After(at) {
				return "", idCertificateRefusal(IDRefusalRevoked)
			}
		} else {
			signed = by[id]
		}
		if signed == nil {
			return "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		c := signed["certificate"].(map[string]any)
		if c["domain"] != domain {
			return "", idCertificateRefusal(IDRefusalDomainMismatch)
		}
		key, err := status.issuer(c, r)
		if err != nil {
			return "", err
		}
		if c["issuer_key"] != key {
			return "", idCertificateRefusal(IDRefusalStaleIssuerKey)
		}
		if err = VerifyIDCertificate(signed, key); err != nil {
			return "", err
		}
		p := c["parent"].(map[string]any)
		human := ""
		if p["kind"] == "identity" {
			parentID := p["id"].(string)
			parentAt := at
			if c["kind"] == "human" && r != nil {
				parentAt = idKnownTime(r.RegisteredAt)
			}
			var parent map[string]any
			if strings.HasPrefix(parentID, "did:aw:") {
				rev, err := status.revision(parentID, parentAt)
				if err != nil {
					return "", err
				}
				parent = rev.Signed
			} else {
				parent = by[parentID]
			}
			if parent == nil {
				return "", idCertificateRefusal(IDRefusalEvidenceUnavailable)
			}
			if c["kind"] == "human" && parent["certificate"].(map[string]any)["kind"] != "human" {
				return "", idCertificateRefusal(IDRefusalHumanIssuerIsAgent)
			}
			human, err = evaluate(parentID, parentAt, path)
			if err != nil {
				return "", err
			}
		}
		if c["kind"] == "human" {
			human = id
		}
		return human, nil
	}
	human, err := evaluate(subject.ID, status.now, map[string]bool{})
	if err != nil {
		return IDChainVerdict{}, err
	}
	valid := true
	kind := IDCertificateKind(certs[len(certs)-1]["certificate"].(map[string]any)["kind"].(string))
	r := IDChainVerdict{Outcome: IDChainOutcomeNoHuman, IdentityValid: &valid, Kind: &kind}
	if human != "" {
		r.Outcome = IDChainOutcomeNearestHuman
		r.HumanID = &human
	}
	return r, nil
}

// CheckIDChain verifies current identity and ancestry against caller-selected
// status/DNS evidence (docs/id-certificates.md §4). It performs no I/O and grants
// no authentication, membership or role. Refusal reasons are typed independently
// of Go error text; absent and unavailable evidence retain different outcomes.
func CheckIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) IDChainVerdict {
	result, err := verifyIDChain(bundle, subject, evidence, domain)
	if err != nil {
		code := IDRefusalCode(err)
		if code == "" {
			code = IDRefusalEvidenceUnavailable
		}
		return idChainFailure(code)
	}
	return result
}

// VerifyIDChain is the released string-based result adapter for CheckIDChain.
// It performs no I/O and grants no authentication, membership or role.
func VerifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) IDChainResult {
	return CheckIDChain(bundle, subject, evidence, domain).Legacy()
}
