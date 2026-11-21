package awid

import (
	"strings"
	"time"
)

func verifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) (IDChainVerdict, error) {
	plan, err := planIDStatusRequest(bundle, subject, domain)
	if err != nil {
		return IDChainVerdict{}, err
	}
	if plan == nil {
		return IDChainVerdict{}, idCertificateRefusal(IDRefusalLegacyNoChain)
	}
	certificates := plan.certificates
	if bundle != nil {
		if err := idChainStructure(certificates); err != nil {
			return IDChainVerdict{}, err
		}
		if certificates[len(certificates)-1].ID() != subject.ID {
			return IDChainVerdict{}, idCertificateRefusal(IDRefusalSubjectMismatch)
		}
	}
	if err := checkIDSubjectBinding(subject); err != nil {
		return IDChainVerdict{}, err
	}
	if evidence == nil {
		return IDChainVerdict{}, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	if err := idEvidenceUsable(evidence); err != nil {
		return IDChainVerdict{}, err
	}
	status, err := parseIDStatus(evidence, plan.domain)
	if err != nil {
		return IDChainVerdict{}, err
	}
	if strings.HasPrefix(subject.ID, "did:aw:") {
		key, err := status.currentKey(subject.ID)
		if err != nil {
			return IDChainVerdict{}, err
		}
		if key != subject.DIDKey {
			return IDChainVerdict{}, idCertificateRefusal(IDRefusalSubjectMismatch)
		}
	}
	if certificates == nil {
		certificates, err = status.chainForSubject(subject.ID)
		if err != nil {
			return IDChainVerdict{}, err
		}
	}
	byID, err := checkCurrentIDChain(status, certificates)
	if err != nil {
		return IDChainVerdict{}, err
	}
	evaluator := idChainEvaluation{status: status, domain: plan.domain, byID: byID}
	human, err := evaluator.nearestHumanAt(subject.ID, status.now, make(map[string]bool))
	if err != nil {
		return IDChainVerdict{}, err
	}
	valid := true
	kind := certificates[len(certificates)-1].Kind()
	result := IDChainVerdict{Outcome: IDChainOutcomeNoHuman, IdentityValid: &valid, Kind: &kind}
	if human != "" {
		result.Outcome = IDChainOutcomeNearestHuman
		result.HumanID = &human
	}
	return result, nil
}

func checkIDSubjectBinding(subject IDChainSubject) error {
	if subject.TeamMemberDIDKey != "" && subject.TeamMemberDIDKey != subject.DIDKey {
		return idCertificateRefusal(IDRefusalSubjectMismatch)
	}
	if subject.TeamMemberDIDAW != "" && subject.TeamMemberDIDAW != subject.ID {
		return idCertificateRefusal(IDRefusalSubjectMismatch)
	}
	if strings.HasPrefix(subject.ID, "did:key:") && subject.ID != subject.DIDKey {
		return idCertificateRefusal(IDRefusalSubjectMismatch)
	}
	return nil
}

func (status *idStatusSnapshot) chainForSubject(id string) ([]IDCertificateView, error) {
	var certificates []IDCertificateView
	seen := make(map[string]bool)
	for {
		if seen[id] {
			return nil, idCertificateRefusal(IDRefusalCycle)
		}
		if len(certificates) >= IDChainMaxDepth {
			return nil, idCertificateRefusal(IDRefusalDepthExceeded)
		}
		seen[id] = true
		revision, err := status.revision(id, status.now)
		if err != nil {
			return nil, err
		}
		certificate := revision.certificate
		certificates = append([]IDCertificateView{certificate}, certificates...)
		if certificate.Parent().Kind() == IDParentKindNamespace {
			break
		}
		id = certificate.Parent().ID()
	}
	if err := idChainStructure(certificates); err != nil {
		return nil, err
	}
	return certificates, nil
}

func checkCurrentIDChain(status *idStatusSnapshot, certificates []IDCertificateView) (map[string]IDCertificateView, error) {
	byID := make(map[string]IDCertificateView)
	for _, certificate := range certificates {
		byID[certificate.ID()] = certificate
		if !strings.HasPrefix(certificate.ID(), "did:aw:") {
			continue
		}
		row, err := status.row(certificate.ID())
		if err != nil {
			return nil, err
		}
		if !idCurrentCertificateMatches(certificate.Fields(), row.CurrentCertificateID) {
			return nil, idCertificateRefusal(IDRefusalSupersededCertificate)
		}
	}
	for _, certificate := range certificates {
		var revision *idStatusRevision
		if strings.HasPrefix(certificate.ID(), "did:aw:") {
			var err error
			revision, err = status.revision(certificate.ID(), status.now)
			if err != nil {
				return nil, err
			}
		}
		issuer, err := status.issuer(certificate, revision)
		if err != nil {
			return nil, err
		}
		if issuer != certificate.IssuerKey() {
			return nil, idCertificateRefusal(IDRefusalStaleIssuerKey)
		}
		if err := VerifyIDCertificate(certificate.Signed(), issuer); err != nil {
			return nil, err
		}
	}
	return byID, nil
}

type idChainEvaluation struct {
	status *idStatusSnapshot
	domain string
	byID   map[string]IDCertificateView
}

// nearestHumanAt follows the historical parent at each registered human's
// witness while retaining current revocation and replacement checks (§4).
func (evaluation idChainEvaluation) nearestHumanAt(id string, at time.Time, path map[string]bool) (string, error) {
	if path[id] {
		return "", idCertificateRefusal(IDRefusalCycle)
	}
	if len(path) >= IDChainMaxDepth {
		return "", idCertificateRefusal(IDRefusalDepthExceeded)
	}
	path[id] = true
	defer delete(path, id)
	certificate, revision, err := evaluation.certificateAt(id, at)
	if err != nil {
		return "", err
	}
	if certificate.Domain() != evaluation.domain {
		return "", idCertificateRefusal(IDRefusalDomainMismatch)
	}
	issuer, err := evaluation.status.issuer(certificate, revision)
	if err != nil {
		return "", err
	}
	if certificate.IssuerKey() != issuer {
		return "", idCertificateRefusal(IDRefusalStaleIssuerKey)
	}
	if err := VerifyIDCertificate(certificate.Signed(), issuer); err != nil {
		return "", err
	}
	human := ""
	parent := certificate.Parent()
	if parent.Kind() == IDParentKindIdentity {
		parentAt := at
		if certificate.Kind() == IDCertificateKindHuman && revision != nil {
			parentAt = revision.validity.from
		}
		parentCertificate, err := evaluation.parentCertificateAt(parent.ID(), parentAt)
		if err != nil {
			return "", err
		}
		if certificate.Kind() == IDCertificateKindHuman && parentCertificate.Kind() != IDCertificateKindHuman {
			return "", idCertificateRefusal(IDRefusalHumanIssuerIsAgent)
		}
		human, err = evaluation.nearestHumanAt(parent.ID(), parentAt, path)
		if err != nil {
			return "", err
		}
	}
	if certificate.Kind() == IDCertificateKindHuman {
		human = id
	}
	return human, nil
}

func (evaluation idChainEvaluation) certificateAt(id string, at time.Time) (IDCertificateView, *idStatusRevision, error) {
	if !strings.HasPrefix(id, "did:aw:") {
		certificate, present := evaluation.byID[id]
		if !present {
			return IDCertificateView{}, nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
		}
		return certificate, nil, nil
	}
	revision, err := evaluation.status.revision(id, at)
	if err != nil {
		return IDCertificateView{}, nil, err
	}
	if revision.validity.from.Before(evaluation.status.cutoff) {
		return IDCertificateView{}, nil, idCertificateRefusal(IDRefusalRootReplaced)
	}
	row, err := evaluation.status.row(id)
	if err != nil {
		return IDCertificateView{}, nil, err
	}
	if row.Revocation != nil && !row.Revocation.effectiveAt.After(at) {
		return IDCertificateView{}, nil, idCertificateRefusal(IDRefusalRevoked)
	}
	return revision.certificate, revision, nil
}

func (evaluation idChainEvaluation) parentCertificateAt(id string, at time.Time) (IDCertificateView, error) {
	if strings.HasPrefix(id, "did:aw:") {
		revision, err := evaluation.status.revision(id, at)
		if err != nil {
			return IDCertificateView{}, err
		}
		return revision.certificate, nil
	}
	certificate, present := evaluation.byID[id]
	if !present {
		return IDCertificateView{}, idCertificateRefusal(IDRefusalEvidenceUnavailable)
	}
	return certificate, nil
}
