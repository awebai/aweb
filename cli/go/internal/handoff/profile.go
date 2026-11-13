package handoff

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/mr-tron/base58"
)

// Profile is an operator-provisioned protected-service profile
// (docs/protected-service-profile.md): the public pins aw sends a protected
// operation to. Loading one grants no requester permission and no approval.
type Profile struct {
	ServiceID      string
	RequestOrigin  string
	HumanOrigin    string
	RPID           string
	RegistryOrigin string
	// NamespaceAuthorities pins each configured namespace's controller key,
	// by domain: the authority an ID chain in that namespace is verified from.
	NamespaceAuthorities map[string]string
	Bindings             []ProfileBinding
}

// ProfileBinding is one configured protected scope with its authority's
// public key and the policy it is approved under.
type ProfileBinding struct {
	// Scope is the exact protected context, as it decodes from the profile.
	Scope           map[string]any
	AuthorityKeyDID string
	PolicyVersion   int64
}

const maxProfileBytes = 65536

var (
	profileDomain  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	maxSafeInteger = int64(1<<53 - 1)
)

var errProfileInvalid = coded("profile_invalid", errors.New("the protected-service profile is not valid"))

// ParseProfile reads a profile strictly: one duplicate-free object with
// exactly its members, canonical origins, an HTTPS human origin whose host is
// rp_id, valid public keys and stable IDs, and bindings only for configured
// namespaces of this service, each authority with one key. Any other input
// refuses profile_invalid, naming nothing from it.
func ParseProfile(raw []byte) (*Profile, error) {
	if len(raw) > maxProfileBytes {
		return nil, errProfileInvalid
	}
	object, ok := decodeObject(raw)
	if !ok || !exactMembers(object, []string{"v", "service_id", "request_origin", "human_origin", "rp_id", "registry_origin", "namespace_authorities", "bindings"}) || !versionOne(object["v"]) {
		return nil, errProfileInvalid
	}
	profile := &Profile{}
	var okText bool
	if profile.ServiceID, okText = exactText(object["service_id"]); !okText {
		return nil, errProfileInvalid
	}
	for _, field := range []struct {
		name string
		into *string
	}{{"request_origin", &profile.RequestOrigin}, {"human_origin", &profile.HumanOrigin}, {"registry_origin", &profile.RegistryOrigin}} {
		origin, ok := canonicalOrigin(object[field.name])
		if !ok {
			return nil, errProfileInvalid
		}
		*field.into = origin
	}
	profile.RPID, _ = object["rp_id"].(string)
	human, _ := url.Parse(profile.HumanOrigin)
	if !profileDomain.MatchString(profile.RPID) || human.Scheme != "https" || human.Hostname() != profile.RPID {
		return nil, errProfileInvalid
	}
	namespaces, ok := namespaceAuthorities(object["namespace_authorities"])
	if !ok {
		return nil, errProfileInvalid
	}
	profile.NamespaceAuthorities = namespaces
	rows, _ := object["bindings"].([]any)
	if len(rows) == 0 {
		return nil, errProfileInvalid
	}
	seen := map[string]bool{}
	keys := map[string]string{}
	for _, row := range rows {
		binding, authority, stable, ok := profileBinding(row, profile.ServiceID, namespaces)
		if !ok || seen[stable] {
			return nil, errProfileInvalid
		}
		seen[stable] = true
		if known, ok := keys[authority]; ok && known != binding.AuthorityKeyDID {
			return nil, errProfileInvalid
		}
		keys[authority] = binding.AuthorityKeyDID
		profile.Bindings = append(profile.Bindings, binding)
	}
	return profile, nil
}

// BindingFor is the configured binding of exactly scope; it never picks a
// default human or generation.
func (p *Profile) BindingFor(scope map[string]any) (*ProfileBinding, error) {
	for i := range p.Bindings {
		if sameJSON(p.Bindings[i].Scope, scope) {
			return &p.Bindings[i], nil
		}
	}
	return nil, coded("profile_scope_refused", errors.New("the profile configures no binding for this scope"))
}

// teamDomain is the authority domain of team's controller bindings, when the
// profile binds that team's controller at all.
func (p *Profile) teamDomain(team string) (string, bool) {
	for _, binding := range p.Bindings {
		authority, _ := binding.Scope["authority"].(map[string]any)
		if authority["kind"] == "team_controller" && authority["id"] == team {
			domain, _ := authority["domain"].(string)
			return domain, true
		}
	}
	return "", false
}

func namespaceAuthorities(value any) (map[string]string, bool) {
	rows, _ := value.([]any)
	if len(rows) == 0 {
		return nil, false
	}
	controllers := map[string]string{}
	for _, row := range rows {
		object, _ := row.(map[string]any)
		domain, _ := object["domain"].(string)
		if _, seen := controllers[domain]; !exactMembers(object, []string{"domain", "controller_did"}) || !profileDomain.MatchString(domain) || !validDIDKey(object["controller_did"]) || seen {
			return nil, false
		}
		controllers[domain] = object["controller_did"].(string)
	}
	return controllers, true
}

func profileBinding(value any, serviceID string, namespaces map[string]string) (ProfileBinding, string, string, bool) {
	object, _ := value.(map[string]any)
	scope, _ := object["scope"].(map[string]any)
	policy, _ := object["policy"].(map[string]any)
	if !exactMembers(object, []string{"scope", "authority_key_did", "policy"}) || scope == nil || policy == nil || !validDIDKey(object["authority_key_did"]) {
		return ProfileBinding{}, "", "", false
	}
	if !exactMembers(policy, []string{"ref", "version"}) || policy["ref"] != "aweb.human-assurance/1" {
		return ProfileBinding{}, "", "", false
	}
	version, ok := positiveInteger(policy["version"])
	if !ok {
		return ProfileBinding{}, "", "", false
	}
	authority, _ := scope["authority"].(map[string]any)
	human, _ := scope["human"].(map[string]any)
	if !exactMembers(scope, []string{"v", "kind", "service_id", "authority", "human", "generation"}) || !versionOne(scope["v"]) || scope["kind"] != "protected_key" || scope["service_id"] != serviceID || authority == nil || human == nil {
		return ProfileBinding{}, "", "", false
	}
	if _, ok := positiveInteger(scope["generation"]); !ok {
		return ProfileBinding{}, "", "", false
	}
	kind, _ := authority["kind"].(string)
	id, _ := authority["id"].(string)
	domain, _ := authority["domain"].(string)
	humanID, _ := human["id"].(string)
	humanDomain, _ := human["domain"].(string)
	if !exactMembers(authority, []string{"kind", "id", "domain"}) || !exactMembers(human, []string{"id", "domain"}) || namespaces[domain] == "" || namespaces[humanDomain] == "" || !canonicalStableID(humanID) || !canonicalAuthority(kind, id, domain) {
		return ProfileBinding{}, "", "", false
	}
	authorityKey := kind + "\x00" + id + "\x00" + domain
	binding := ProfileBinding{Scope: scope, AuthorityKeyDID: object["authority_key_did"].(string), PolicyVersion: version}
	return binding, authorityKey, authorityKey + "\x00" + humanID + "\x00" + humanDomain, true
}

func canonicalAuthority(kind, id, domain string) bool {
	switch kind {
	case "human_identity":
		return canonicalStableID(id)
	case "namespace_controller":
		return id == domain
	case "team_controller":
		teamDomain, name, err := awid.ParseTeamID(id)
		return err == nil && teamDomain == domain && awid.BuildTeamID(teamDomain, name) == id
	}
	return false
}

// canonicalStableID: did:aw: and base58 that decodes to exactly 20 bytes and
// encodes back to itself.
func canonicalStableID(id string) bool {
	const prefix = "did:aw:"
	if len(id) <= len(prefix) || id[:len(prefix)] != prefix || len(id) > len(prefix)+32 {
		return false
	}
	decoded, err := base58.Decode(id[len(prefix):])
	return err == nil && len(decoded) == 20 && base58.Encode(decoded) == id[len(prefix):]
}

func validDIDKey(value any) bool {
	did, ok := value.(string)
	if !ok {
		return false
	}
	_, err := awid.ExtractPublicKey(did)
	return err == nil
}

func canonicalOrigin(value any) (string, bool) {
	text, ok := value.(string)
	if !ok {
		return "", false
	}
	origin, err := awid.CanonicalServerOrigin(text)
	return origin, err == nil && origin == text
}

func exactText(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok && text != "" && text == strings.TrimSpace(text)
}

// positiveInteger is a JSON integer in [1, 2^53-1], written as a plain integer.
func positiveInteger(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(number), 10, 64)
	return n, err == nil && strconv.FormatInt(n, 10) == string(number) && n >= 1 && n <= maxSafeInteger
}

func versionOne(value any) bool {
	n, ok := positiveInteger(value)
	return ok && n == 1
}
