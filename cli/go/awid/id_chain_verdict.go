package awid

import "encoding/json"

// IDChainVerdict is the typed result of current ID-chain verification. A valid
// identity with no HumanID is an agent without verified human ancestry. Nil
// IdentityValid means there was no definitive identity verdict, not validity.
// It grants neither authentication nor team membership.
type IDChainVerdict struct {
	Outcome       IDChainOutcome
	HumanID       *string
	IdentityValid *bool
	Kind          *IDCertificateKind
	Refusal       IDRefusal
}

// Legacy preserves the released IDChainResult fields and their exact JSON
// meanings. New callers can use CheckIDChain without changing the wire profile.
func (verdict IDChainVerdict) Legacy() IDChainResult {
	result := IDChainResult{
		Outcome: string(verdict.Outcome), HumanID: verdict.HumanID,
		IdentityValid: verdict.IdentityValid, Reason: string(verdict.Refusal),
	}
	if verdict.Kind != nil {
		kind := string(*verdict.Kind)
		result.Kind = &kind
	}
	if verdict.Refusal == "" && verdict.IdentityValid != nil && *verdict.IdentityValid {
		result.Reason = "verified"
	}
	return result
}

// MarshalJSON retains the released result profile, including nulls and reason.
func (verdict IDChainVerdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(verdict.Legacy())
}
