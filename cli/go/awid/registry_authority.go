package awid

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"
)

// RegistryOperation identifies the routing contract, not network admission.
type RegistryOperation string

const (
	RegistryAdministrative RegistryOperation = "administrative"
	RegistryOutboundRead   RegistryOperation = "outbound_read"
)

type RegistryDiscoveryState string

const (
	RegistryDiscoveryPending           RegistryDiscoveryState = "not_requested"
	RegistryDiscoveryFound             RegistryDiscoveryState = "found"
	RegistryDiscoveryAbsent            RegistryDiscoveryState = "absent"
	RegistryDiscoveryTimeout           RegistryDiscoveryState = "timeout"
	RegistryDiscoveryTemporaryFailure  RegistryDiscoveryState = "temporary_failure"
	RegistryDiscoveryUnreachable       RegistryDiscoveryState = "unreachable"
	RegistryDiscoveryConnectionRefused RegistryDiscoveryState = "connection_refused"
	RegistryDiscoveryRefused           RegistryDiscoveryState = "refused"
	RegistryDiscoveryMalformed         RegistryDiscoveryState = "malformed"
	RegistryDiscoveryAmbiguous         RegistryDiscoveryState = "ambiguous"
)

type RegistrySelectionAction string

const (
	RegistryOriginSelected RegistrySelectionAction = "selected"
	RegistryLookupRequired RegistrySelectionAction = "discover"
)

type RegistryOriginSource string

const (
	RegistrySourceExplicit   RegistryOriginSource = "explicit"
	RegistrySourceTeam       RegistryOriginSource = "team"
	RegistrySourceConfigured RegistryOriginSource = "configured"
	RegistrySourceDiscovery  RegistryOriginSource = "discovery"
	RegistrySourceFallback   RegistryOriginSource = "fallback"
	RegistrySourceDefault    RegistryOriginSource = "default"
)

type RegistryAuthorityState string

const (
	RegistryAuthorityEstablished   RegistryAuthorityState = "established"
	RegistryAuthorityUnestablished RegistryAuthorityState = "unestablished"
)

type RegistryEnvironment string

const (
	RegistryProduction  RegistryEnvironment = "production"
	RegistryDevelopment RegistryEnvironment = "development"
)

type RegistryAbsence string

const (
	RegistryAuthoritativeAbsence RegistryAbsence = "absence"
	RegistryUnknownAbsence       RegistryAbsence = "unknown"
)

// RegistryTeamOrigin carries the exact selected membership, without granting
// administrative trust to its stored origin.
type RegistryTeamOrigin struct {
	TeamID string `json:"team_id"`
	Origin string `json:"origin"`
}

// RegistryDiscoveryObservation is already-parsed DNS evidence. The selector
// still validates the origin; transport failure is never a malformed record.
type RegistryDiscoveryObservation struct {
	State  RegistryDiscoveryState `json:"state"`
	Origin string                 `json:"origin,omitempty"`
}

// RegistryAuthorityMemo is the resolver's already-parsed domain-scoped routing
// snapshot. An empty controller means only a fallback route, never absence.
// It does not admit its origin through the private-network transport fence.
type RegistryAuthorityMemo struct {
	Domain     string `json:"domain"`
	Origin     string `json:"origin"`
	Controller string `json:"controller"`
}

type RegistryAuthorityInput struct {
	Environment      RegistryEnvironment          `json:"environment"`
	Operation        RegistryOperation            `json:"operation"`
	Domain           string                       `json:"domain"`
	TeamID           string                       `json:"team_id,omitempty"`
	IdentityDomain   string                       `json:"identity_domain,omitempty"`
	ConfiguredOrigin string                       `json:"configured_origin,omitempty"`
	ExplicitOrigin   string                       `json:"explicit_origin,omitempty"`
	Team             *RegistryTeamOrigin          `json:"team,omitempty"`
	Memo             *RegistryAuthorityMemo       `json:"memo,omitempty"`
	Discovery        RegistryDiscoveryObservation `json:"discovery"`
}

// RegistryAuthoritySelection describes routing evidence only. In particular,
// AuthorityEstablished does not admit private addresses or prove a signature.
// A fallback 404 remains unknown and must not populate an absence cache.
type RegistryAuthoritySelection struct {
	Action               RegistrySelectionAction `json:"action"`
	Origin               string                  `json:"origin"`
	Provenance           RegistryOriginSource    `json:"provenance"`
	AuthorityEstablished bool                    `json:"authority_established"`
	NotFound             RegistryAbsence         `json:"not_found"`
}

type RegistryAuthorityRefusalCode string

const (
	RegistryOperationInvalid     RegistryAuthorityRefusalCode = "registry_operation_invalid"
	RegistryTeamMismatch         RegistryAuthorityRefusalCode = "registry_team_mismatch"
	RegistryDiscoveryInvalid     RegistryAuthorityRefusalCode = "registry_discovery_invalid"
	RegistryDiscoveryUnavailable RegistryAuthorityRefusalCode = "registry_discovery_unavailable"
)

type RegistryAuthorityRefusal struct {
	Code   RegistryAuthorityRefusalCode
	Domain string
}

func (e *RegistryAuthorityRefusal) Error() string {
	switch e.Code {
	case RegistryOperationInvalid:
		return "The registry operation is invalid. Choose an administrative operation or an outbound address read."
	case RegistryTeamMismatch:
		return "The selected team's registry does not match the requested domain. Select the exact source team and retry."
	case RegistryDiscoveryUnavailable:
		return "The domain's registry could not be discovered and no fallback is configured. Check DNS availability or configure your identity's registry, then retry."
	default:
		return fmt.Sprintf("The registry's DNS evidence for %s is invalid or refused. Ask the domain operator to check %s and retry.", SanitizeErrorText(e.Domain), SanitizeErrorText(AWIDTXTName(e.Domain)))
	}
}

// SelectRegistryAuthority implements identity-messaging-contract.md:208-222.
// Administrative pins never ask DNS; foreign outbound reads alone may fall
// back on the listed transport failures. Call again with an observation when
// Action is RegistryLookupRequired. Origin admission remains registry_pin.go.
func SelectRegistryAuthority(in RegistryAuthorityInput) (RegistryAuthoritySelection, error) {
	if in.Operation != RegistryAdministrative && in.Operation != RegistryOutboundRead {
		return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryOperationInvalid}
	}
	domain := canonicalizeDomain(in.Domain)
	if origin := strings.TrimSpace(in.ExplicitOrigin); origin != "" {
		return selectedRegistry(origin, RegistrySourceExplicit, RegistryAuthorityEstablished)
	}
	configured := strings.TrimSpace(in.ConfiguredOrigin)
	if in.Operation == RegistryAdministrative {
		if in.Team != nil && strings.TrimSpace(in.Team.Origin) != "" {
			teamDomain, teamName, err := ParseTeamID(in.Team.TeamID)
			targetDomain, targetName, targetErr := ParseTeamID(in.TeamID)
			if err != nil || targetErr != nil || canonicalizeDomain(teamDomain) != domain || BuildTeamID(teamDomain, teamName) != BuildTeamID(targetDomain, targetName) {
				return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryTeamMismatch, Domain: domain}
			}
			return selectedRegistry(in.Team.Origin, RegistrySourceTeam, RegistryAuthorityEstablished)
		}
		if configured != "" {
			return selectedRegistry(configured, RegistrySourceConfigured, RegistryAuthorityEstablished)
		}
		return selectedRegistry(DefaultAWIDRegistryURL, RegistrySourceDefault, RegistryAuthorityEstablished)
	}
	if configured != "" && domain != "" && domain == canonicalizeDomain(in.IdentityDomain) {
		return selectedRegistry(configured, RegistrySourceConfigured, RegistryAuthorityEstablished)
	}
	if in.Memo != nil {
		if canonicalizeDomain(in.Memo.Domain) != domain || (in.Discovery.State != "" && in.Discovery.State != RegistryDiscoveryPending) {
			return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryDiscoveryInvalid, Domain: domain}
		}
		if strings.TrimSpace(in.Memo.Controller) != "" {
			return selectedRegistry(in.Memo.Origin, RegistrySourceDiscovery, RegistryAuthorityEstablished)
		}
		return selectedRegistry(in.Memo.Origin, RegistrySourceFallback, RegistryAuthorityUnestablished)
	}
	switch in.Discovery.State {
	case "", RegistryDiscoveryPending:
		return RegistryAuthoritySelection{Action: RegistryLookupRequired, NotFound: RegistryUnknownAbsence}, nil
	case RegistryDiscoveryFound:
		origin, err := discoveredRegistryOrigin(in.Discovery.Origin, in.Environment)
		if err != nil {
			return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryDiscoveryInvalid, Domain: domain}
		}
		return selectedRegistry(origin, RegistrySourceDiscovery, RegistryAuthorityEstablished)
	case RegistryDiscoveryAbsent:
		if configured != "" {
			return selectedRegistry(configured, RegistrySourceFallback, RegistryAuthorityUnestablished)
		}
		return selectedRegistry(DefaultAWIDRegistryURL, RegistrySourceFallback, RegistryAuthorityUnestablished)
	case RegistryDiscoveryTimeout, RegistryDiscoveryTemporaryFailure, RegistryDiscoveryUnreachable, RegistryDiscoveryConnectionRefused:
		if configured != "" {
			return selectedRegistry(configured, RegistrySourceFallback, RegistryAuthorityUnestablished)
		}
		return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryDiscoveryUnavailable, Domain: domain}
	case RegistryDiscoveryRefused, RegistryDiscoveryMalformed, RegistryDiscoveryAmbiguous:
		return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryDiscoveryInvalid, Domain: domain}
	default:
		return RegistryAuthoritySelection{}, &RegistryAuthorityRefusal{Code: RegistryDiscoveryInvalid, Domain: domain}
	}
}

func selectedRegistry(raw string, source RegistryOriginSource, authority RegistryAuthorityState) (RegistryAuthoritySelection, error) {
	origin, err := CanonicalRegistryServerOrigin(raw)
	if err != nil {
		return RegistryAuthoritySelection{}, err
	}
	absence := RegistryUnknownAbsence
	if authority == RegistryAuthorityEstablished {
		absence = RegistryAuthoritativeAbsence
	}
	return RegistryAuthoritySelection{Action: RegistryOriginSelected, Origin: origin, Provenance: source, AuthorityEstablished: authority == RegistryAuthorityEstablished, NotFound: absence}, nil
}

func discoveredRegistryOrigin(raw string, environment RegistryEnvironment) (string, error) {
	origin, err := CanonicalRegistryServerOrigin(raw)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if (parsed.Scheme != "https" && environment != RegistryDevelopment) || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", fmt.Errorf("discovered registry requires a public HTTPS host")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("discovered registry cannot be a literal IP address")
	}
	return origin, nil
}
