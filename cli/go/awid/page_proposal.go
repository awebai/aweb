package awid

import (
	"crypto/sha256"
	"encoding/hex"
)

// PageProposalPrefix domain-separates a page proposal digest
// (docs/page-format.md §5). It ends in one literal newline byte.
const PageProposalPrefix = "aweb.page-proposal/1\n"

// ProposalSHA256 is the digest a decision binds for one proposal record:
// "sha256:" and the hex SHA-256 of the prefix and the canonical JSON of
// {collection, record_id, value}, in StrictCanonicalJSON. Decode values with
// UseNumber, so numbers keep their exact form; a value without one canonical
// form is refused.
func ProposalSHA256(collection, recordID string, value any) (string, error) {
	canonical, err := StrictCanonicalJSON(map[string]any{
		"collection": collection,
		"record_id":  recordID,
		"value":      value,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte(PageProposalPrefix), canonical...))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
