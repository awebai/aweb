package awid

import "encoding/json"

type signedEnvelopeMetadata struct {
	From         string `json:"from"`
	To           string `json:"to"`
	FromDID      string `json:"from_did"`
	ToDID        string `json:"to_did"`
	FromStableID string `json:"from_stable_id"`
	ToStableID   string `json:"to_stable_id"`
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
