package identityutil

import (
	"strings"

	"github.com/awebai/aw/awid"
)

func HandleFromAddress(address string) string {
	return awid.HandleFromAddress(address)
}

func ValueMatchesSelf(value string, selfAlias string, selfDIDs ...string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, selfDID := range selfDIDs {
		selfDID = strings.TrimSpace(selfDID)
		if selfDID != "" && strings.EqualFold(value, selfDID) {
			return true
		}
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(value, selfAlias) {
		return true
	}
	if strings.EqualFold(value, "did:aw:"+selfAlias) {
		return true
	}
	return strings.EqualFold(HandleFromAddress(value), selfAlias)
}

func hasStrongSelfIdentity(selfAddress string, selfDIDs ...string) bool {
	if strings.TrimSpace(selfAddress) != "" {
		return true
	}
	for _, selfDID := range selfDIDs {
		if strings.TrimSpace(selfDID) != "" {
			return true
		}
	}
	return false
}

func MatchesSelf(alias, address, stableID, did, selfAlias, selfAddress string, selfDIDs ...string) bool {
	stableID = strings.TrimSpace(stableID)
	did = strings.TrimSpace(did)
	for _, selfDID := range selfDIDs {
		selfDID = strings.TrimSpace(selfDID)
		if selfDID != "" && (strings.EqualFold(stableID, selfDID) || strings.EqualFold(did, selfDID)) {
			return true
		}
	}
	if len(selfDIDs) > 0 && (stableID != "" || did != "") {
		return false
	}
	address = strings.TrimSpace(address)
	selfAddress = strings.TrimSpace(selfAddress)
	if selfAddress != "" && strings.EqualFold(address, selfAddress) {
		return true
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(HandleFromAddress(address), selfAlias) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(alias), selfAlias)
}

func MatchesSelfStrict(alias, address, stableID, did, selfAlias, selfAddress string, selfDIDs ...string) bool {
	address = strings.TrimSpace(address)
	stableID = strings.TrimSpace(stableID)
	did = strings.TrimSpace(did)
	selfAddress = strings.TrimSpace(selfAddress)
	if selfAddress != "" && strings.EqualFold(address, selfAddress) {
		return true
	}
	for _, selfDID := range selfDIDs {
		selfDID = strings.TrimSpace(selfDID)
		if selfDID != "" && (strings.EqualFold(stableID, selfDID) || strings.EqualFold(did, selfDID)) {
			return true
		}
	}
	if hasStrongSelfIdentity(selfAddress, selfDIDs...) && (address != "" || stableID != "" || did != "") {
		return false
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(HandleFromAddress(address), selfAlias) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(alias), selfAlias)
}
