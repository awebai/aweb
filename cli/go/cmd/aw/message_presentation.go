package main

import (
	"strings"

	"github.com/awebai/aw/awid"
)

// claimedSenderIdentifier allows only the existing identifier grammars in an
// autonomous notice. The sender label is a claim and carries no authority.
func claimedSenderIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if isValidWorkspaceAlias(value) {
		return value
	}
	if strings.HasPrefix(value, "did:key:") {
		if _, err := awid.ExtractPublicKey(value); err == nil {
			return value
		}
		return ""
	}
	if suffix, ok := strings.CutPrefix(value, "did:aw:"); ok {
		if _, err := awid.DecodeStableID(suffix); err == nil {
			return value
		}
		return ""
	}
	address, err := awid.CanonicalFederationAddress(value)
	if err != nil || !isValidWorkspaceAlias(awid.ParseNetworkAddress(address).Alias) {
		return ""
	}
	return address
}
