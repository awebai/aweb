package awid

import "strings"

const (
	IdentityModeLocal  = "local"
	IdentityModeGlobal = "global"
)

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

func IdentityHasPublicAddress(scope string) bool {
	return NormalizeIdentityScope(scope) == IdentityModeGlobal
}

func RoutingHandle(alias, address, scope string) string {
	if strings.TrimSpace(alias) != "" {
		return strings.TrimSpace(alias)
	}
	if !IdentityHasPublicAddress(scope) {
		return strings.TrimSpace(address)
	}
	return ""
}

func PublicAddress(address, scope string) string {
	if !IdentityHasPublicAddress(scope) {
		return ""
	}
	return strings.TrimSpace(address)
}

func DescribeIdentityScope(scope string) string {
	return NormalizeIdentityScope(scope)
}

func IsSelfCustodial(custody string) bool {
	return strings.TrimSpace(strings.ToLower(custody)) == CustodySelf
}
