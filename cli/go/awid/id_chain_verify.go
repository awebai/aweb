package awid

import (
	"strings"
	"time"
)

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
			if r.validity.from.Before(status.cutoff) {
				return "", idCertificateRefusal(IDRefusalRootReplaced)
			}
			row, _ := status.row(id)
			if row.Revocation != nil && !row.Revocation.effectiveAt.After(at) {
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
				parentAt = r.validity.from
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
