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
		// Stored-route continuations deliberately sign the stable recipient
		// without resolving its current key. Only that signed recipient and
		// the same nonempty signed conversation may project an empty to_did.
		if name == "to_did" && *value == "" && strings.HasPrefix(displayed, "did:aw:") {
			var stable, conversation string
			if json.Unmarshal(signed["to_stable_id"], &stable) == nil && stable == displayed &&
				json.Unmarshal(signed["conversation_id"], &conversation) == nil && conversation != "" &&
				conversation == fields["conversation_id"] {
				continue
			}
		}
		return false
	}
	return true
}

// signedMailDisplayMatches permits the legacy empty recipient-key claim only
// for mail delivered to this reader. The authenticated read establishes the
// recipient; authenticated sender-visible reads also preserve the reader's own
// sent mail. Neither case makes that recipient DID a signed claim.
func (c *Client) signedMailDisplayMatches(payload string, fields map[string]string, authenticatedSenderRead bool) bool {
	recipient := fields["to_did"]
	readerIsRecipient := recipient != "" && (recipient == c.did || recipient == c.stableID)
	readerIsSender := false
	if authenticatedSenderRead {
		if meta, ok := parseSignedEnvelopeMetadata(payload); ok {
			readerIsSender = (c.did != "" && meta.FromDID == c.did) ||
				(c.stableID != "" && (meta.FromDID == c.stableID || meta.FromStableID == c.stableID))
		}
	}
	if readerIsRecipient || readerIsSender {
		var signed map[string]json.RawMessage
		if json.Unmarshal([]byte(payload), &signed) == nil {
			raw, present := signed["to_did"]
			_, stablePresent := signed["to_stable_id"]
			var value *string
			if present && !stablePresent && json.Unmarshal(raw, &value) == nil && value != nil && *value == "" {
				remaining := make(map[string]string, len(fields)-1)
				for name, display := range fields {
					if name != "to_did" {
						remaining[name] = display
					}
				}
				return signedDisplayMatches(payload, remaining)
			}
		}
	}
	return signedDisplayMatches(payload, fields)
}
