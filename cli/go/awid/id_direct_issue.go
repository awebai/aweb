package awid

// Immediate init and spawn (docs/id-certificates.md §6): the parent signs
// the child's certificate directly, with no request or invitation. The
// certificate, the parent checks and the record before output are those of
// the CSR exchange.
import "time"

// IDChild names the certificate a parent issues: the child's id, its
// domain, its parent and its kind.
type IDChild struct {
	ID     string
	Domain string
	Parent map[string]any
	Kind   string
}

// IssueIDChild signs child's certificate as its parent and returns the
// child's chain: parentChain followed by the new certificate. parentChain is
// an identity parent's own current chain, ending in the parent; a namespace
// parent has none. The issuance is recorded before the chain is returned.
func IssueIDChild(issuance IDIssuanceStore, child IDChild, parentChain []any, evidence *IDChainEvidence, sign IDCertificateSigner, now time.Time) (map[string]any, error) {
	current, err := idIssuingKey(child.Parent, child.Domain, child.Kind, parentChain, evidence)
	if err != nil {
		return nil, err
	}
	certificate := map[string]any{
		"v": 1, "type": "aweb.id-certificate",
		"id": child.ID, "domain": child.Domain, "parent": child.Parent, "kind": child.Kind,
		"issuer_key": current, "issued_at": idRecordTime(now),
	}
	signed, err := issueIDCertificate(certificate, current, sign, recordIssued(issuance, now))
	if err != nil {
		return nil, err
	}
	certificates := append(append([]any{}, parentChain...), signed)
	return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}, nil
}
