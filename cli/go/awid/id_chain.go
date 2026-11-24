package awid

// Pure ID-tree authority verification. Status/DNS facts come only from the
// production cached resolver or a locked AWID transaction, never the carrier.
import (
	"math"
	"strings"
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
	plan, err := planIDStatusRequest(bundle, subject, domain)
	if err != nil || plan == nil {
		return nil, err
	}
	return map[string]any{"v": 1, "domain": plan.domain, "ids": plan.ids}, nil
}

type idChainPlan struct {
	domain       string
	ids          []string
	certificates []IDCertificateView
}

func planIDStatusRequest(bundle map[string]any, subject IDChainSubject, domain string) (*idChainPlan, error) {
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
		return &idChainPlan{domain: domain, ids: []string{subject.ID}}, nil
	}
	chain, err := IDChainFromBundle(bundle)
	if err != nil {
		return nil, err
	}
	certificates := chain.Certificates()
	selected := certificates[0].Domain()
	if domain != "" && domain != selected {
		return nil, idCertificateRefusal(IDRefusalDomainMismatch)
	}
	ids := make([]string, 0)
	seen := make(map[string]bool)
	for _, certificate := range certificates {
		id := certificate.ID()
		if strings.HasPrefix(id, "did:aw:") && !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return &idChainPlan{domain: selected, ids: ids, certificates: certificates}, nil
}

func idChainStructure(certificates []IDCertificateView) error {
	byID := make(map[string]IDCertificateView)
	for _, certificate := range certificates {
		if _, exists := byID[certificate.ID()]; exists {
			return idCertificateRefusal(IDRefusalDuplicateId)
		}
		byID[certificate.ID()] = certificate
	}
	for id := range byID {
		seen := make(map[string]bool)
		certificate, exists := byID[id]
		for exists {
			if seen[id] {
				return idCertificateRefusal(IDRefusalCycle)
			}
			seen[id] = true
			parent := certificate.Parent()
			if parent.Kind() == IDParentKindNamespace {
				break
			}
			id = parent.ID()
			certificate, exists = byID[id]
		}
	}
	domain := certificates[0].Domain()
	for index, certificate := range certificates {
		parent := certificate.Parent()
		if certificate.Domain() != domain {
			return idCertificateRefusal(IDRefusalDomainMismatch)
		}
		if index == 0 {
			if parent.Kind() != IDParentKindNamespace || parent.ID() != domain {
				return idCertificateRefusal(IDRefusalMissingParent)
			}
			continue
		}
		previous := certificates[index-1]
		if parent.Kind() != IDParentKindIdentity || parent.ID() != previous.ID() {
			return idCertificateRefusal(IDRefusalMissingParent)
		}
		if certificate.Kind() == IDCertificateKindHuman && previous.Kind() != IDCertificateKindHuman {
			return idCertificateRefusal(IDRefusalHumanIssuerIsAgent)
		}
	}
	return nil
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
		failure := idChainFailure(code)
		failure.diagnostic = idStatusDiagnostic(err)
		return failure
	}
	return result
}

// VerifyIDChain is the released string-based result adapter for CheckIDChain.
// It performs no I/O and grants no authentication, membership or role.
func VerifyIDChain(bundle map[string]any, subject IDChainSubject, evidence *IDChainEvidence, domain string) IDChainResult {
	return CheckIDChain(bundle, subject, evidence, domain).Legacy()
}

// idCurrentCertificateMatches compares the public status commitment with the
// supplied certificate (docs/id-certificates.md, current certificate checks).
func idCurrentCertificateMatches(certificate map[string]any, expectedID string) bool {
	digest, err := IDCertificateID(certificate)
	if err != nil {
		return false
	}
	return digest == expectedID
}
