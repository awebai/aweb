package appmanifest

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/awebai/aw/awid"
)

// CodeOwnerActsInvalid is every fault in a version 3 owner_acts member,
// shared through docs/vectors/owner-act-delivery-v1.json.
const CodeOwnerActsInvalid = "owner_acts_invalid"

const (
	maxOwnerActRoles         = 16
	maxOwnerActRoleNameBytes = 23
)

// ownerActRoleNamePattern is the designatable role grammar with a leading
// letter. With the 23-byte bound, it keeps a role name usable inside
// owner-act/1's token grammar.
var ownerActRoleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`)

// OwnerActs is a version 3 manifest's human origin and the roles that only a
// team owner act designates.
type OwnerActs struct {
	Origin string         `json:"origin"`
	Roles  []OwnerActRole `json:"roles"`
}

// OwnerActRole is one owner-designated role.
type OwnerActRole struct {
	Name          string   `json:"name"`
	Label         string   `json:"label"`
	Description   *string  `json:"description,omitempty"`
	Acts          []string `json:"acts"`
	NoticeContact bool     `json:"notice_contact"`
}

// parseOwnerActs decodes and checks the owner_acts member; absent declares
// no owner-designated role. Every fault is owner_acts_invalid.
func parseOwnerActs(raw json.RawMessage, appOrigin string) (*OwnerActs, error) {
	if raw == nil {
		return nil, nil
	}
	var ownerActs OwnerActs
	if err := decodeStrictObject(raw, &ownerActs, "owner_acts"); err != nil {
		return nil, codedf(CodeOwnerActsInvalid, "%v", err)
	}
	if !awid.ValidOwnerActAudience(ownerActs.Origin) {
		return nil, codedf(CodeOwnerActsInvalid, "owner_acts origin %q must be https with a lowercase host, an optional port and nothing after it", ownerActs.Origin)
	}
	// Cookies ignore ports, so a port does not separate the human origin
	// from the app's.
	if strings.EqualFold(originHostname(ownerActs.Origin), originHostname(appOrigin)) {
		return nil, codedf(CodeOwnerActsInvalid, "owner_acts origin %q shares the app origin's hostname", ownerActs.Origin)
	}
	if len(ownerActs.Roles) == 0 || len(ownerActs.Roles) > maxOwnerActRoles {
		return nil, codedf(CodeOwnerActsInvalid, "owner_acts must declare 1 to %d roles", maxOwnerActRoles)
	}
	names := map[string]bool{}
	for _, role := range ownerActs.Roles {
		if len(role.Name) > maxOwnerActRoleNameBytes || !ownerActRoleNamePattern.MatchString(role.Name) {
			return nil, codedf(CodeOwnerActsInvalid, "owner_acts role name %q must be a designatable role name of at most %d bytes beginning with a letter", role.Name, maxOwnerActRoleNameBytes)
		}
		if names[role.Name] {
			return nil, codedf(CodeOwnerActsInvalid, "duplicate owner_acts role name %q", role.Name)
		}
		names[role.Name] = true
		if !validRoleText(role.Label, maxRoleLabelRunes) {
			return nil, codedf(CodeOwnerActsInvalid, "owner_acts role %q label must be 1 to %d characters with no control or bidi character", role.Name, maxRoleLabelRunes)
		}
		if role.Description != nil && !validRoleText(*role.Description, maxRoleDescRunes) {
			return nil, codedf(CodeOwnerActsInvalid, "owner_acts role %q description must be 1 to %d characters with no control or bidi character", role.Name, maxRoleDescRunes)
		}
	}
	return &ownerActs, nil
}

func originHostname(origin string) string {
	parsed, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
