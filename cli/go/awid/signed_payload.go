package awid

import (
	"encoding/json"
	"strings"
)

type signedEnvelopeMetadata struct {
	From           string `json:"from"`
	To             string `json:"to"`
	FromDID        string `json:"from_did"`
	ToDID          string `json:"to_did"`
	FromStableID   string `json:"from_stable_id"`
	ToStableID     string `json:"to_stable_id"`
	ConversationID string `json:"conversation_id"`
}

func parseSignedEnvelopeMetadata(payload string) (signedEnvelopeMetadata, bool) {
	if payload == "" {
		return signedEnvelopeMetadata{}, false
	}
	var meta signedEnvelopeMetadata
	if err := json.Unmarshal([]byte(payload), &meta); err != nil {
		return signedEnvelopeMetadata{}, false
	}
	return meta, true
}

// signedDisplayMatches checks the original response before signed metadata is
// projected over it. Missing legacy fields are not claims; present empty values
// are claims and must match. Null and non-string claims are invalid.
func signedDisplayMatches(payload string, fields map[string]string) bool {
	var signed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &signed); err != nil || signed == nil {
		return false
	}
	for name, displayed := range fields {
		raw, present := signed[name]
		if !present {
			continue
		}
		var value *string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			return false
		}
		if displayed == *value {
			continue
		}
		// A stable routing DID may project the same envelope's signed stable ID.
		// Unsigned metadata and resolver results never establish this equivalence.
		stableField := ""
		if name == "from_did" {
			stableField = "from_stable_id"
		}
		if name == "to_did" {
			stableField = "to_stable_id"
		}
		if stableField != "" && strings.HasPrefix(displayed, "did:aw:") && strings.HasPrefix(*value, "did:key:") {
			var stable string
			if json.Unmarshal(signed[stableField], &stable) == nil && stable == displayed {
				continue
			}
		}
		return false
	}
	return true
}
