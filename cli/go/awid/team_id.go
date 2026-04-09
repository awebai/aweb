package awid

import (
	"fmt"
	"strings"
)

// BuildTeamID returns the canonical colon-form team identifier "<name>:<domain>".
func BuildTeamID(domain, name string) string {
	domain = canonicalizeDomain(domain)
	name = strings.ToLower(strings.TrimSpace(name))
	if domain == "" || name == "" {
		return ""
	}
	return name + ":" + domain
}

// ParseTeamID parses the canonical colon-form team identifier "<name>:<domain>".
// It returns the normalized domain and lowercased team name.
func ParseTeamID(teamID string) (domain, name string, err error) {
	teamID = strings.TrimSpace(teamID)
	parts := strings.SplitN(teamID, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("invalid team_id %q (expected name:domain)", teamID)
	}
	name = strings.ToLower(strings.TrimSpace(parts[0]))
	domain = canonicalizeDomain(parts[1])
	if domain == "" || name == "" {
		return "", "", fmt.Errorf("invalid team_id %q (expected name:domain)", teamID)
	}
	return domain, name, nil
}
