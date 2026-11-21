package a2agw

import (
	"fmt"
	"strings"
)

type routeAuthPolicy struct {
	Mode         AuthMode
	StaticAPIKey string
	BearerToken  string
}

type runtimeRoute struct {
	Route
	Auth routeAuthPolicy
}

// parseRouteAuthPolicy is the sole interpretation of the released string input
// at the library configuration boundary (docs/a2a.md:933-935). Consumers use its
// named policy; external Go callers may still supply a runtime string variable.
func parseRouteAuthPolicy(route Route) (routeAuthPolicy, error) {
	policy := routeAuthPolicy{
		Mode:         AuthMode(strings.ToLower(strings.TrimSpace(route.Auth.Mode))),
		StaticAPIKey: route.Auth.StaticAPIKey,
		BearerToken:  route.Auth.BearerToken,
	}
	if policy.Mode == AuthModeUnspecified {
		policy.Mode = AuthModeNone
	}
	switch policy.Mode {
	case AuthModeNone:
	case AuthModeStaticAPIKey:
		if strings.TrimSpace(policy.StaticAPIKey) == "" && !route.Disabled {
			return routeAuthPolicy{}, fmt.Errorf("route %s: static_api_key mode requires Auth.StaticAPIKey. Configure the route's API key or disable the route, then retry.", route.RouteID)
		}
	case AuthModeBearer:
		if strings.TrimSpace(policy.BearerToken) == "" && !route.Disabled {
			return routeAuthPolicy{}, fmt.Errorf("route %s: bearer mode requires Auth.BearerToken. Configure the route's bearer token or disable the route, then retry.", route.RouteID)
		}
	default:
		return routeAuthPolicy{}, fmt.Errorf("route %s: unsupported auth mode %q. Set the route auth mode to none, static_api_key, or bearer, then retry.", route.RouteID, route.Auth.Mode)
	}
	return policy, nil
}
