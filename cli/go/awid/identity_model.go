package awid

import (
	"errors"
	"strings"
)

const (
	IdentityModeLocal  = "local"
	IdentityModeGlobal = "global"
)

// ErrInvalidIdentityScope is an unrecognized local/global identity scope.
var ErrInvalidIdentityScope = errors.New("identity scope must be local or global")

// ErrInvalidIdentityCustody is an unrecognized self/custodial identity custody.
var ErrInvalidIdentityCustody = errors.New("identity custody must be self or custodial")

// ParseIdentityScope normalizes a scope and returns its named value. It does not
// infer a scope from legacy certificate lifetime or supply a default.
func ParseIdentityScope(value string) (IdentityScope, error) {
	switch NormalizeIdentityScope(value) {
	case IdentityModeLocal:
		return IdentityScopeLocal, nil
	case IdentityModeGlobal:
		return IdentityScopeGlobal, nil
	default:
		return "", ErrInvalidIdentityScope
	}
}

// ParseIdentityCustody names identity-key custody independently of membership.
// Encryption-key assertions have their own hosted_custodial wire vocabulary.
func ParseIdentityCustody(value string) (IdentityCustody, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case CustodySelf:
		return IdentityCustodySelf, nil
	case CustodyCustodial:
		return IdentityCustodyHosted, nil
	default:
		return "", ErrInvalidIdentityCustody
	}
}

// NormalizeIdentityScope retains the released string normalizer; it does not
// validate the value or adapt a legacy lifetime.
func NormalizeIdentityScope(scope string) string {
	return strings.TrimSpace(strings.ToLower(scope))
}

// IdentityScopeFromLegacyLifetime is the explicit compatibility adapter for
// pre-v2 config and certificate decoders. Canonical code must not call it.
func IdentityScopeFromLegacyLifetime(lifetime string) string {
	switch strings.TrimSpace(strings.ToLower(lifetime)) {
	case "ephemeral":
		return IdentityModeLocal
	case "persistent":
		return IdentityModeGlobal
	default:
		return ""
	}
}

// IdentityHasPublicAddress reports whether the scope permits global addressing.
func IdentityHasPublicAddress(scope string) bool {
	parsed, err := ParseIdentityScope(scope)
	return err == nil && parsed == IdentityScopeGlobal
}

// RoutingHandle prefers the team-local member name over a global address.
func RoutingHandle(alias, address, scope string) string {
	if strings.TrimSpace(alias) != "" {
		return strings.TrimSpace(alias)
	}
	if !IdentityHasPublicAddress(scope) {
		return strings.TrimSpace(address)
	}
	return ""
}

// PublicAddress omits address text for a local identity.
func PublicAddress(address, scope string) string {
	if !IdentityHasPublicAddress(scope) {
		return ""
	}
	return strings.TrimSpace(address)
}

// DescribeIdentityScope returns the normalized declared scope for presentation.
func DescribeIdentityScope(scope string) string {
	return NormalizeIdentityScope(scope)
}

// IsSelfCustodial reports whether the identity's private key stays with its owner.
func IsSelfCustodial(custody string) bool {
	parsed, err := ParseIdentityCustody(custody)
	return err == nil && parsed == IdentityCustodySelf
}
