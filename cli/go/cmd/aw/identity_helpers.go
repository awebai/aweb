package main

import "strings"

type pendingIdentityRow struct {
	Alias    string
	Address  string
	DID      string
	StableID string
}

func newPendingIdentityRow(alias, address, did string) pendingIdentityRow {
	row := pendingIdentityRow{
		Alias:   strings.TrimSpace(alias),
		Address: strings.TrimSpace(address),
		DID:     strings.TrimSpace(did),
	}
	if strings.HasPrefix(row.DID, "did:aw:") {
		row.StableID = row.DID
	}
	return row
}

func pendingStableAlias(value string) string {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "did:aw:") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "did:aw:"))
}

func pendingIdentityRows(participants, addresses, dids []string) []pendingIdentityRow {
	count := len(participants)
	if len(addresses) > count {
		count = len(addresses)
	}
	if len(dids) > count {
		count = len(dids)
	}
	rows := make([]pendingIdentityRow, 0, count)
	for idx := 0; idx < count; idx++ {
		alias := ""
		if idx < len(participants) {
			alias = participants[idx]
		}
		address := ""
		if idx < len(addresses) {
			address = addresses[idx]
		}
		did := ""
		if idx < len(dids) {
			did = dids[idx]
		}
		rows = append(rows, newPendingIdentityRow(alias, address, did))
	}
	return rows
}

func (row pendingIdentityRow) label() string {
	if row.Address != "" {
		return row.Address
	}
	if row.StableID != "" {
		return row.StableID
	}
	if row.DID != "" {
		return row.DID
	}
	return row.Alias
}

func (row pendingIdentityRow) strength() int {
	if row.Address != "" {
		return 4
	}
	if row.StableID != "" {
		return 3
	}
	if row.DID != "" {
		return 2
	}
	if row.Alias != "" {
		return 1
	}
	return 0
}

func (row pendingIdentityRow) matchesAlias(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	return strings.EqualFold(row.Alias, value) ||
		strings.EqualFold(handleFromAddress(row.Address), value) ||
		strings.EqualFold(pendingStableAlias(row.DID), value)
}

func pendingIdentityByAliasSlices(participants, addresses, dids []string, alias string) (pendingIdentityRow, bool) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return pendingIdentityRow{}, false
	}
	matches := 0
	var matched pendingIdentityRow
	for _, row := range pendingIdentityRows(participants, addresses, dids) {
		if !row.matchesAlias(alias) {
			continue
		}
		matches++
		if matches > 1 {
			return pendingIdentityRow{}, false
		}
		matched = row
	}
	if matches == 0 {
		return pendingIdentityRow{}, false
	}
	return matched, true
}

func pendingDirectOpenTargetSlices(participants, addresses, dids []string) string {
	rows := pendingIdentityRows(participants, addresses, dids)
	if len(rows) != 1 {
		return ""
	}
	row := rows[0]
	if row.Address != "" {
		return row.Address
	}
	if row.DID != "" {
		return row.DID
	}
	return row.Alias
}

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
