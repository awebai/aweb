package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Decode only the response detail; HTTP status and operator wording stay with
// the calling service operation (docs/cli-integration-contract.md, Refusal codes).
func decodeTeamServiceRefusalDetail(body []byte) (string, error) {
	var response struct {
		Detail any `json:"detail"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("decode service refusal detail: %w", err)
	}
	if response.Detail == nil {
		return "", nil
	}
	encoded, err := json.Marshal(response.Detail)
	if err != nil {
		return "", fmt.Errorf("encode service refusal detail: %w", err)
	}
	return strings.TrimSpace(string(encoded)), nil
}
