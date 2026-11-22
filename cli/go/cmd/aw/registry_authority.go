package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type registryAuthorityKind uint8

const (
	registryProcessSetting registryAuthorityKind = iota
	registryDomainRoute
	registryDNSAuthority
	registryIdentityRoute
	registryIdentityLookup
	registryInviteIssuerRoute
	registryTeamRoute
	registryWorkspaceTeamRoute
	registryDeliveryTeamRoute
	registryAddressClaimRoute
)

type registryAuthorityRequest struct {
	Kind             registryAuthorityKind
	Registry         *awid.RegistryClient
	DeliveryResolver *awid.RegistryResolver
	Override         string
	DefaultURL       string
	Domain           string
	TeamID           string
	Identity         *awconfig.ResolvedIdentity
	LookupDID        string
	WorkingDir       string
	IdentityHome     string
	AwebURL          string
	Authority        awid.DomainAuthority
	TXTResolver      awid.TXTResolver
	TeamDomain       string
	TeamRegistry     string
}

// resolveRegistryAuthority selects the origin for the subject of the operation.
// The selected origin carries no transport trust. The registry client's
// operator pins and public transport policy apply independently.
func resolveRegistryAuthority(ctx context.Context, req registryAuthorityRequest) (string, error) {
	override := strings.TrimSpace(req.Override)
	switch req.Kind {
	case registryProcessSetting:
		value := firstNonEmpty(override, os.Getenv("AWID_REGISTRY_URL"), req.DefaultURL)
		if strings.EqualFold(value, "local") {
			return "", errLocalRegistryURL
		}
		return value, nil
	case registryDomainRoute:
		return req.Registry.DiscoverRegistry(ctx, req.Domain)
	case registryDNSAuthority:
		named := strings.TrimSpace(req.Authority.RegistryURL)
		if override == "" {
			return named, nil
		}
		if named != "" && named != awid.DefaultAWIDRegistryURL && named != override {
			return "", usageError("--registry %s contradicts the registry %s that %s names", override, named, req.Authority.DNSName)
		}
		return override, nil
	case registryIdentityRoute, registryIdentityLookup, registryInviteIssuerRoute:
		return resolveIdentityRegistryAuthority(ctx, req)
	case registryDeliveryTeamRoute:
		membership, err := recordedRegistryMembership(req)
		if err != nil {
			return "", err
		}
		if legacyOrigin := legacyLocalMembershipRegistryOrigin(membership, req.WorkingDir, req.IdentityHome); legacyOrigin != "" {
			trustRecordedRegistryOrigin(req.DeliveryResolver, legacyOrigin, legacyOrigin)
			return awid.CanonicalRegistryServerOrigin(legacyOrigin)
		}
		if membership != nil && strings.TrimSpace(membership.RegistryURL) != "" {
			return awid.CanonicalRegistryServerOrigin(membership.RegistryURL)
		}
		return strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")), nil
	case registryTeamRoute, registryWorkspaceTeamRoute, registryAddressClaimRoute:
		if override != "" {
			return awid.CanonicalRegistryServerOrigin(override)
		}
		domain := awconfig.NormalizeDomain(req.Domain)
		meta, err := awconfig.LoadControllerMeta(domain)
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("load controller metadata for %s: %w", domain, err)
		}
		if meta != nil && strings.TrimSpace(meta.RegistryURL) != "" {
			if req.Registry != nil {
				trustRecordedRegistryOrigin(req.Registry.Resolver, meta.RegistryURL, controllerRegistryOperatorOrigin(domain, meta))
			}
			return awid.CanonicalRegistryServerOrigin(meta.RegistryURL)
		}
		if req.Kind == registryAddressClaimRoute {
			origin, err := req.Registry.DiscoverRegistry(ctx, domain)
			if err == nil && origin != "" {
				return origin, nil
			}
			if req.Identity != nil && strings.TrimSpace(req.Identity.RegistryURL) != "" {
				return awid.CanonicalRegistryServerOrigin(req.Identity.RegistryURL)
			}
			if err != nil {
				return "", fmt.Errorf("discover registry for %s: %w", domain, err)
			}
			return "", fmt.Errorf("registry URL for %s is empty", domain)
		}

		membership, err := recordedRegistryMembership(req)
		if err != nil {
			return "", err
		}
		if membership != nil && strings.TrimSpace(membership.RegistryURL) != "" {
			return awid.CanonicalRegistryServerOrigin(membership.RegistryURL)
		}
		identity, err := recordedRegistryIdentity(req)
		if err != nil {
			return "", err
		}
		if identity != nil {
			identityDomain, _, addressed := awconfig.CutIdentityAddress(identity.Address)
			// Workspace operations use the selected actor's recorded registry when
			// its exact team membership carries no registry of its own.
			usesMemberRegistry := membership != nil && (!addressed || req.Kind == registryWorkspaceTeamRoute)
			if (strings.EqualFold(identityDomain, domain) || usesMemberRegistry) && strings.TrimSpace(identity.RegistryURL) != "" {
				return awid.CanonicalRegistryServerOrigin(identity.RegistryURL)
			}
		}
		serviceURL := strings.TrimSpace(req.AwebURL)
		if serviceURL == "" && membership != nil {
			serviceURL = strings.TrimSpace(membership.AwebURL)
		}
		if serviceURL != "" {
			discovered, err := discoverOnboardingServiceURLs(serviceURL)
			if err != nil {
				return "", fmt.Errorf("discover registry for %s: %w", domain, err)
			}
			if strings.TrimSpace(discovered.RegistryURL) != "" {
				return awid.CanonicalRegistryServerOrigin(discovered.RegistryURL)
			}
		}
		configured, err := resolveRegistryURLSetting(registryURLSettingInput{})
		if err != nil {
			return "", err
		}
		if configured != "" {
			return awid.CanonicalRegistryServerOrigin(configured)
		}
		if req.Registry != nil {
			return req.Registry.DiscoverRegistry(ctx, domain)
		}
		if req.DefaultURL != "" {
			return req.DefaultURL, nil
		}
		if isAwebHostedNamespace(domain) {
			return awid.DefaultAWIDRegistryURL, nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("unknown registry authority selection")
	}
}

// Only the exact selected team can supply a membership pin.
func recordedRegistryMembership(req registryAuthorityRequest) (*awconfig.TeamMembership, error) {
	if req.TeamID == "" || (req.IdentityHome == "" && req.WorkingDir == "") {
		return nil, nil
	}
	state, _, err := loadTeamStateForInviteAt(req.WorkingDir, req.IdentityHome)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load team state: %w", err)
	}
	return state.Membership(req.TeamID), nil
}

func recordedRegistryIdentity(req registryAuthorityRequest) (*awconfig.WorktreeIdentity, error) {
	var identity *awconfig.WorktreeIdentity
	var err error
	switch {
	case req.IdentityHome != "":
		path, pathErr := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: req.IdentityHome}, "identity.yaml")
		if pathErr != nil {
			return nil, pathErr
		}
		identity, err = awconfig.LoadWorktreeIdentityFrom(path)
	case req.WorkingDir != "":
		identity, _, err = awconfig.LoadWorktreeIdentityFromDir(req.WorkingDir)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load worktree identity: %w", err)
	}
	return identity, nil
}

func resolveIdentityRegistryAuthority(ctx context.Context, req registryAuthorityRequest) (string, error) {
	identity := req.Identity
	if req.Kind == registryIdentityLookup && identity != nil && strings.TrimSpace(identity.StableID) != strings.TrimSpace(req.LookupDID) {
		identity = nil
	}
	if req.Kind == registryInviteIssuerRoute && identity != nil {
		if pin := firstNonEmpty(identity.RegistryURL, req.Override); pin != "" {
			return pin, nil
		}
		if req.Domain != "" && req.Domain == req.TeamDomain && strings.TrimSpace(req.TeamRegistry) != "" {
			authority, err := awid.DiscoverAuthoritativeRegistry(ctx, req.TXTResolver, req.Domain)
			if err != nil {
				return "", err
			}
			return resolveRegistryAuthority(ctx, registryAuthorityRequest{Kind: registryDNSAuthority, Authority: authority, Override: req.TeamRegistry})
		}
	}
	if strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")) != "" && req.Registry != nil {
		return req.Registry.DefaultRegistryURL, nil
	}
	if identity != nil {
		if pin := strings.TrimSpace(identity.RegistryURL); pin != "" {
			return pin, nil
		}
		if domain := identityRegistryDomain(req); domain != "" && req.Registry != nil {
			return req.Registry.DiscoverRegistry(ctx, domain)
		}
		if req.Kind != registryIdentityLookup && req.Registry != nil && strings.TrimSpace(identity.StableID) != "" {
			return "", fmt.Errorf("%w: global identity %s has no registry_url or address domain; cannot safely choose an AWID registry", errMissingIdentityRegistryContext, strings.TrimSpace(identity.StableID))
		}
	}
	if req.Registry != nil {
		return req.Registry.DefaultRegistryURL, nil
	}
	return "", nil
}

func identityRegistryDomain(req registryAuthorityRequest) string {
	if req.Kind == registryInviteIssuerRoute {
		return strings.TrimSpace(req.Domain)
	}
	return strings.TrimSpace(req.Identity.Domain)
}

func resolveTeamCommandRegistry(ctx context.Context, registry *awid.RegistryClient, workingDir, domain, teamID, override string) (string, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return "", err
	}
	origin, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryTeamRoute, Override: override, DefaultURL: registry.DefaultRegistryURL,
		Domain: domain, TeamID: teamID, WorkingDir: workingDir, IdentityHome: externalIdentityHomeRoot(home),
	})
	if err != nil {
		return "", err
	}
	trustControllerRegistryOrigin(registry.Resolver, domain, origin)
	return origin, nil
}
