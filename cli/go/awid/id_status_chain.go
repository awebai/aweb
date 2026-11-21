package awid

import "fmt"

// RegisteredIDChain is the chain status names as id's current registration:
// id's current certificate, then each identity parent's current certificate,
// up to the one a namespace issued, root-most first. It reads status only; the
// caller verifies the chain against trusted evidence (VerifyIDChain) before
// relying on it, so a status answer is never authority by itself.
func RegisteredIDChain(status map[string]any, id string) (map[string]any, error) {
	rows, ok := status["identities"].([]any)
	if !ok {
		return nil, ErrMalformedIDStatus
	}
	byID := map[string]map[string]any{}
	for _, value := range rows {
		row, rowOK := value.(map[string]any)
		rowID, idOK := row["id"].(string)
		if !rowOK || !idOK || rowID == "" || byID[rowID] != nil {
			return nil, ErrMalformedIDStatus
		}
		byID[rowID] = row
	}
	var path []any
	for len(path) < IDChainMaxDepth {
		signed, err := currentIDCertificate(byID[id])
		if err != nil {
			return nil, fmt.Errorf("the registered chain of %s: %w", id, err)
		}
		path = append([]any{signed}, path...)
		fields, fieldsOK := signed["certificate"].(map[string]any)
		parent, parentOK := fields["parent"].(map[string]any)
		if !fieldsOK || !parentOK {
			return nil, ErrMalformedIDStatus
		}
		kind, kindOK := parent["kind"].(string)
		if !kindOK {
			return nil, ErrMalformedIDStatus
		}
		switch IDParentKind(kind) {
		case IDParentKindNamespace:
			return map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": path}, nil
		case IDParentKindIdentity:
			next, ok := parent["id"].(string)
			if !ok || next == "" {
				return nil, ErrMalformedIDStatus
			}
			id = next
		default:
			return nil, ErrMalformedIDStatus
		}
	}
	return nil, idCertificateRefusal(IDRefusalChainTooDeep)
}

// currentIDCertificate is the signed certificate among row's revisions whose
// ID is row's current certificate ID.
func currentIDCertificate(row map[string]any) (map[string]any, error) {
	if row == nil {
		return nil, idCertificateRefusal(IDRefusalUnregisteredIdentity)
	}
	current, _ := row["current_certificate_id"].(string)
	revisions, _ := row["certificates"].([]any)
	for _, value := range revisions {
		revision, _ := value.(map[string]any)
		signed, _ := revision["signed"].(map[string]any)
		certificate, _ := signed["certificate"].(map[string]any)
		if certificate == nil {
			return nil, ErrMalformedIDStatus
		}
		if head, err := IDCertificateID(certificate); err == nil && head == current {
			return signed, nil
		}
	}
	return nil, idCertificateRefusal(IDRefusalEvidenceUnavailable)
}

// RegisteredIDHead is id's current certificate ID as evidence states it, only
// once the evidence is fresh and the whole status verifies as domain's under
// its namespace authority, the same checks VerifyIDChain applies. Malformed,
// stale or unanchored evidence, or evidence that does not hold id, is an
// error, never a head.
func RegisteredIDHead(evidence *IDChainEvidence, domain, id string) (string, error) {
	if err := idEvidenceUsable(evidence); err != nil {
		return "", err
	}
	status, err := parseIDStatus(evidence, domain)
	if err != nil {
		return "", err
	}
	row, err := status.row(id)
	if err != nil {
		return "", err
	}
	return row.CurrentCertificateID, nil
}
