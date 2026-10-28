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

type IDChainSubject struct {
	ID               string `json:"id"`
	DIDKey           string `json:"did_key"`
	TeamMemberDIDAW  string `json:"team_member_did_aw"`
	TeamMemberDIDKey string `json:"team_member_did_key"`
}
type IDChainEvidence struct {
	Status             map[string]any
	NamespaceAuthority map[string]any
	AgeSeconds         *float64
	RefreshFailed      bool
}
type IDChainResult struct {
	Outcome       string  `json:"outcome"`
	HumanID       *string `json:"human_id"`
	IdentityValid *bool   `json:"identity_valid"`
	Kind          *string `json:"kind"`
	Reason        string  `json:"reason"`
}

func idChainFailure(reason string) IDChainResult {
	r := IDChainResult{Outcome: "unknown", Reason: reason}
	switch reason {
	case "status_expired", "evidence_unavailable":
		r.Outcome = "unavailable"
	case "legacy_no_chain", "unregistered_identity":
	default:
		b := false
		r.IdentityValid = &b
	}
	return r
}
func IDStatusCacheMode(age *float64, refreshFailed bool) string {
	if age == nil || math.IsNaN(*age) || math.IsInf(*age, 0) || *age < 0 {
		return "unavailable"
	}
	if *age <= 60 {
		return "fresh"
	}
	if refreshFailed && *age <= 900 {
		return "outage_grace"
	}
	return "unavailable"
}
func IDRequestDisposition(r IDChainResult, subject IDChainSubject, originalAuthPassed, humanRequired bool) string {
	if !originalAuthPassed {
		return "refuse"
	}
	valid := r.IdentityValid != nil && *r.IdentityValid
	if humanRequired {
		if valid && r.Outcome == "nearest_human" {
			return "continue"
		}
		return "refuse"
	}
	if valid || r.Reason == "legacy_no_chain" || r.Reason == "unregistered_identity" {
		return "continue"
	}
	if strings.HasPrefix(subject.ID, "did:key:") && (r.Reason == "stale_issuer_key" || r.Reason == "status_expired" || r.Reason == "evidence_unavailable") {
		return "continue"
	}
	return "refuse"
}
func IDStatusRequest(bundle map[string]any, subject IDChainSubject, domain string) (map[string]any, error) {
	if bundle == nil {
		if strings.HasPrefix(subject.ID, "did:key:") {
			return nil, nil
		}
		if domain == "" {
			return nil, idCertificateRefusal("evidence_unavailable")
		}
		if !idCertificateDomain(domain) {
			return nil, idCertificateRefusal("invalid_domain")
		}
		return map[string]any{"v": 1, "domain": domain, "ids": []string{subject.ID}}, nil
	}
	if raw, err := idCertificateCanonical(bundle); err != nil {
		return nil, err
	} else if len(raw) > IDChainMaxBytes {
		return nil, idCertificateRefusal("bundle_too_large")
	}
	if err := idCertificateBundleShape(bundle); err != nil {
		return nil, err
	}
	certs := idChainCertificates(bundle)
	selected := certs[0]["certificate"].(map[string]any)["domain"].(string)
	if domain != "" && domain != selected {
		return nil, idCertificateRefusal("domain_mismatch")
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
			return idCertificateRefusal("duplicate_id")
		}
		by[id] = c
	}
	for id := range by {
		seen := map[string]bool{}
		for by[id] != nil {
			if seen[id] {
				return idCertificateRefusal("cycle")
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
			return idCertificateRefusal("domain_mismatch")
		}
		if n == 0 {
			if p["kind"] != "namespace" || p["id"] != domain {
				return idCertificateRefusal("missing_parent")
			}
		} else {
			prev := certs[n-1]["certificate"].(map[string]any)
			if p["kind"] != "identity" || p["id"] != prev["id"] {
				return idCertificateRefusal("missing_parent")
			}
			if c["kind"] == "human" && prev["kind"] != "human" {
				return idCertificateRefusal("human_issuer_is_agent")
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
		Epochs []idNamespaceEpoch `json:"epochs"`
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
		return time.Time{}, idCertificateRefusal("evidence_unavailable")
	}
	t, e := time.Parse("2006-01-02T15:04:05.000000Z", s)
	if e != nil || t.Year() < 1 {
		return time.Time{}, idCertificateRefusal("evidence_unavailable")
	}
	return t, nil
}
func idKnownTime(s string) time.Time { t, _ := idWitness(s); return t }
func idStatusFields(v any, fields string) bool {
	m, ok := v.(map[string]any)
	return ok && idCertificateExactFields(m, strings.Fields(fields)...)
}
func idStatusRequired(s map[string]any) bool {
	if !idStatusFields(s, "v domain observed_at namespace identities missing") || !idStatusFields(s["namespace"], "epochs") {
		return false
	}
	epochs, ok := s["namespace"].(map[string]any)["epochs"].([]any)
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
	bad := idCertificateRefusal("evidence_unavailable")
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
	if last.RetiredAt != nil || !idStatusFields(a, "domain dns_name inherited controller_key") || a["domain"] != domain || a["dns_name"] != "_awid."+domain || a["inherited"] != false || a["controller_key"] != last.DIDKey {
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
		return nil, idCertificateRefusal("unregistered_identity")
	}
	r := s.byID[id]
	if r == nil {
		return nil, idCertificateRefusal("evidence_unavailable")
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
	return nil, idCertificateRefusal("evidence_unavailable")
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
			return "", idCertificateRefusal("evidence_unavailable")
		}
		return s.Namespace.Epochs[r.IssuerKeySeq-1].DIDKey, nil
	}
	id := p["id"].(string)
	if r != nil {
		if strings.HasPrefix(id, "did:key:") {
			return "", idCertificateRefusal("unregistered_parent")
		}
		row, err := s.row(id)
		if err != nil {
			return "", err
		}
		if r.IssuerKeySeq > len(row.KeyHistory) {
			return "", idCertificateRefusal("evidence_unavailable")
		}
		return row.KeyHistory[r.IssuerKeySeq-1].Entry.NewDIDKey, nil
	}
	return s.currentKey(id)
}
func verifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) (IDChainResult, error) {
	bad := func(code string) (IDChainResult, error) { return IDChainResult{}, idCertificateRefusal(code) }
	plan, err := IDStatusRequest(bundle, subject, domain)
	if err != nil {
		return IDChainResult{}, err
	}
	if plan == nil {
		return bad("legacy_no_chain")
	}
	domain = plan["domain"].(string)
	var certs []map[string]any
	if bundle != nil {
		raw, er := idCertificateCanonical(bundle)
		if er != nil {
			return IDChainResult{}, er
		}
		if len(raw) > IDChainMaxBytes {
			return bad("bundle_too_large")
		}
		certs = idChainCertificates(bundle)
		if err = idChainStructure(certs); err != nil {
			return IDChainResult{}, err
		}
		if certs[len(certs)-1]["certificate"].(map[string]any)["id"] != subject.ID {
			return bad("subject_mismatch")
		}
	}
	if (subject.TeamMemberDIDKey != "" && subject.TeamMemberDIDKey != subject.DIDKey) || (subject.TeamMemberDIDAW != "" && subject.TeamMemberDIDAW != subject.ID) || (strings.HasPrefix(subject.ID, "did:key:") && subject.ID != subject.DIDKey) {
		return bad("subject_mismatch")
	}
	if evidence == nil {
		return bad("evidence_unavailable")
	}
	if IDStatusCacheMode(evidence.AgeSeconds, evidence.RefreshFailed) == "unavailable" {
		// Expired grace requires a failed refresh of last-known-good evidence.
		if evidence.RefreshFailed && evidence.AgeSeconds != nil && *evidence.AgeSeconds > 900 {
			return bad("status_expired")
		}
		return bad("evidence_unavailable")
	}
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return IDChainResult{}, err
	}
	if strings.HasPrefix(subject.ID, "did:aw:") {
		key, err := status.currentKey(subject.ID)
		if err != nil {
			return IDChainResult{}, err
		}
		if key != subject.DIDKey {
			return bad("subject_mismatch")
		}
	}
	if certs == nil {
		id := subject.ID
		seen := map[string]bool{}
		for {
			if seen[id] {
				return bad("cycle")
			}
			if len(certs) >= IDChainMaxDepth {
				return bad("depth_exceeded")
			}
			seen[id] = true
			r, err := status.revision(id, status.now)
			if err != nil {
				return IDChainResult{}, err
			}
			certs = append([]map[string]any{r.Signed}, certs...)
			p := r.Signed["certificate"].(map[string]any)["parent"].(map[string]any)
			if p["kind"] == "namespace" {
				break
			}
			id = p["id"].(string)
		}
		if err = idChainStructure(certs); err != nil {
			return IDChainResult{}, err
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
				return IDChainResult{}, err
			}
			digest, _ := IDCertificateID(c)
			if row.CurrentCertificateID != digest {
				return bad("superseded_certificate")
			}
		}
	}
	for _, signed := range certs {
		c := signed["certificate"].(map[string]any)
		var r *idStatusRevision
		if strings.HasPrefix(c["id"].(string), "did:aw:") {
			r, err = status.revision(c["id"].(string), status.now)
			if err != nil {
				return IDChainResult{}, err
			}
		}
		key, err := status.issuer(c, r)
		if err != nil {
			return IDChainResult{}, err
		}
		if key != c["issuer_key"] {
			return bad("stale_issuer_key")
		}
		if err = VerifyIDCertificate(signed, key); err != nil {
			return IDChainResult{}, err
		}
	}
	var evaluate func(string, time.Time, map[string]bool) (string, error)
	evaluate = func(id string, at time.Time, path map[string]bool) (string, error) {
		if path[id] {
			return "", idCertificateRefusal("cycle")
		}
		if len(path) >= IDChainMaxDepth {
			return "", idCertificateRefusal("depth_exceeded")
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
				return "", idCertificateRefusal("root_replaced")
			}
			row, _ := status.row(id)
			if row.Revocation != nil && !idKnownTime(row.Revocation.EffectiveFrom).After(at) {
				return "", idCertificateRefusal("revoked")
			}
		} else {
			signed = by[id]
		}
		if signed == nil {
			return "", idCertificateRefusal("evidence_unavailable")
		}
		c := signed["certificate"].(map[string]any)
		if c["domain"] != domain {
			return "", idCertificateRefusal("domain_mismatch")
		}
		key, err := status.issuer(c, r)
		if err != nil {
			return "", err
		}
		if c["issuer_key"] != key {
			return "", idCertificateRefusal("stale_issuer_key")
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
				return "", idCertificateRefusal("evidence_unavailable")
			}
			if c["kind"] == "human" && parent["certificate"].(map[string]any)["kind"] != "human" {
				return "", idCertificateRefusal("human_issuer_is_agent")
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
		return IDChainResult{}, err
	}
	valid := true
	kind := certs[len(certs)-1]["certificate"].(map[string]any)["kind"].(string)
	r := IDChainResult{Outcome: "no_human", IdentityValid: &valid, Kind: &kind, Reason: "verified"}
	if human != "" {
		r.Outcome = "nearest_human"
		r.HumanID = &human
	}
	return r, nil
}

// VerifyIDChain performs no I/O and grants no authentication, membership or role.
func VerifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) IDChainResult {
	r, err := verifyIDChain(bundle, subject, evidence, domain)
	if err != nil {
		code := IDCertificateErrorCode(err)
		if code == "" {
			code = "evidence_unavailable"
		}
		return idChainFailure(code)
	}
	return r
}
