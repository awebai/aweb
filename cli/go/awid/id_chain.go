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
