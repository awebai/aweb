package awid

import "strings"

type IdentityClass string

const (
	IdentityClassEphemeral  IdentityClass = LifetimeEphemeral
	IdentityClassPersistent IdentityClass = LifetimePersistent
	IdentityModeLocal                     = "local"
	IdentityModeGlobal                    = "global"
)

func NormalizeLifetime(lifetime string) string {
	switch strings.TrimSpace(strings.ToLower(lifetime)) {
	case "", LifetimeEphemeral, IdentityModeLocal:
		return LifetimeEphemeral
	case LifetimePersistent, IdentityModeGlobal:
		return LifetimePersistent
	default:
		return strings.TrimSpace(strings.ToLower(lifetime))
	}
}

func NormalizeIdentityScope(scope string) string {
	switch strings.TrimSpace(strings.ToLower(scope)) {
	case "", LifetimeEphemeral, IdentityModeLocal:
		return IdentityModeLocal
	case LifetimePersistent, IdentityModeGlobal:
		return IdentityModeGlobal
	default:
		return strings.TrimSpace(strings.ToLower(scope))
	}
}

func LegacyLifetimeForIdentityScope(scope string) string {
	if NormalizeIdentityScope(scope) == IdentityModeGlobal {
		return LifetimePersistent
	}
	return LifetimeEphemeral
}

func IdentityClassFromLifetime(lifetime string) IdentityClass {
	switch NormalizeLifetime(lifetime) {
	case LifetimePersistent:
		return IdentityClassPersistent
	default:
		return IdentityClassEphemeral
	}
}

func IdentityHasPublicAddress(lifetime string) bool {
	return IdentityClassFromLifetime(lifetime) == IdentityClassPersistent
}

func RoutingHandle(alias, address, lifetime string) string {
	if strings.TrimSpace(alias) != "" {
		return strings.TrimSpace(alias)
	}
	if !IdentityHasPublicAddress(lifetime) {
		return strings.TrimSpace(address)
	}
	return ""
}

func PublicAddress(address, lifetime string) string {
	if !IdentityHasPublicAddress(lifetime) {
		return ""
	}
	return strings.TrimSpace(address)
}

func DescribeIdentityClass(lifetime string) string {
	switch IdentityClassFromLifetime(lifetime) {
	case IdentityClassPersistent:
		return IdentityModeGlobal
	default:
		return IdentityModeLocal
	}
}

func IsSelfCustodial(custody string) bool {
	return strings.TrimSpace(strings.ToLower(custody)) == CustodySelf
}
