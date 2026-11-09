package appmanifest

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/awebai/aw/awid"
)

// CodeOwnerActsInvalid is every fault in a version 3 owner_acts member,
// as docs/app-manifest.md (Manifest version 3) names it.
const CodeOwnerActsInvalid = "owner_acts_invalid"

const (
	maxOwnerActRoles         = 16
	maxOwnerActRoleNameBytes = 64
)

// ownerActRoleNamePattern is the designatable role grammar with a leading
// letter. With the 64-byte bound, a role name fits owner-act/1's role.
var ownerActRoleNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`)

// OwnerActs is a version 3 manifest's human origin and the roles that only a
// team owner act designates.
type OwnerActs struct {
	Origin string         `json:"origin"`
	Roles  []OwnerActRole `json:"roles"`
}

// humanRoleActs are the acts an owner-designated role may declare, in
// ascending code point order.
var humanRoleActs = []string{"human-credential.replace", "human-role.designate", "human-role.revoke"}

// OwnerActRole is one owner-designated role, held by a human member of the
// team. NoticeContact is true when designate and replace name a notice
// contact.
type OwnerActRole struct {
	Name          string   `json:"name"`
	Label         string   `json:"label"`
	Description   *string  `json:"description,omitempty"`
	Acts          []string `json:"acts"`
	NoticeContact *bool    `json:"notice_contact"`
}

// parseOwnerActs decodes and checks the owner_acts member; absent declares
// no owner-designated role. Every fault is owner_acts_invalid.
func parseOwnerActs(raw json.RawMessage, appOrigin string) (*OwnerActs, error) {
	if raw == nil {
		return nil, nil
	}
	// Each level is decoded on its own, because the strict decoder matches
	// keys exactly only at the level it is given.
	var document struct {
		Origin string            `json:"origin"`
		Roles  []json.RawMessage `json:"roles"`
	}
	if err := decodeStrictObject(raw, &document, "owner_acts"); err != nil {
		return nil, codedf(CodeOwnerActsInvalid, "%v", err)
	}
	ownerActs := OwnerActs{Origin: document.Origin}
	for _, item := range document.Roles {
		var role OwnerActRole
		if err := decodeStrictObject(item, &role, "owner_acts.roles[]"); err != nil {
			return nil, codedf(CodeOwnerActsInvalid, "%v", err)
		}
		ownerActs.Roles = append(ownerActs.Roles, role)
	}
	if !awid.ValidOwnerActAudience(ownerActs.Origin) {
		return nil, codedf(CodeOwnerActsInvalid, "owner_acts origin %q must be https with a lowercase host, an optional port and nothing after it", ownerActs.Origin)
	}
	// Cookies ignore ports, so a port does not separate the human origin
	// from the app's.
	if strings.EqualFold(originHostname(ownerActs.Origin), originHostname(strings.TrimSpace(appOrigin))) {
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
		if !validHumanRoleActs(role.Acts) {
			return nil, codedf(CodeOwnerActsInvalid, "owner_acts role %q acts must be a nonempty set of %s, ascending with no repeat", role.Name, strings.Join(humanRoleActs, ", "))
		}
		if role.NoticeContact == nil {
			return nil, codedf(CodeOwnerActsInvalid, "owner_acts role %q must say whether it names a notice contact", role.Name)
		}
	}
	return &ownerActs, nil
}

// validHumanRoleActs reports whether acts is a nonempty subsequence of
// humanRoleActs: known acts, ascending by code point, no repeat.
func validHumanRoleActs(acts []string) bool {
	next := 0
	for _, act := range acts {
		for next < len(humanRoleActs) && humanRoleActs[next] != act {
			next++
		}
		if next == len(humanRoleActs) {
			return false
		}
		next++
	}
	return len(acts) > 0
}

// originHostname is the origin's hostname without a trailing DNS root dot,
// so a fully qualified name compares equal to its relative spelling.
func originHostname(origin string) string {
	parsed, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Hostname(), ".")
}
