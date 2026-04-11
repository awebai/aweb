package main

import "strings"

func uniqueIdentityDIDs(values ...string) []string {
	dids := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		duplicate := false
		for _, existing := range dids {
			if strings.EqualFold(existing, value) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			dids = append(dids, value)
		}
	}
	return dids
}

func identityValueMatchesSelf(value string, selfAlias string, selfDIDs ...string) bool {
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
	return strings.EqualFold(handleFromAddress(value), selfAlias)
}

func identityMatchesSelf(alias, address, stableID, did, selfAlias, selfAddress string, selfDIDs ...string) bool {
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
	selfAddress = strings.TrimSpace(selfAddress)
	address = strings.TrimSpace(address)
	if selfAddress != "" && strings.EqualFold(address, selfAddress) {
		return true
	}
	selfAlias = strings.TrimSpace(selfAlias)
	if selfAlias == "" {
		return false
	}
	if strings.EqualFold(handleFromAddress(address), selfAlias) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(alias), selfAlias)
}
