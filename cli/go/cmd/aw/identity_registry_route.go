package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// identityRegistryScope binds home routing to the identity's own namespace.
// A signed chain can identify a namespace independent of the address alias.
type identityRegistryScope struct {
	identity *awconfig.ResolvedIdentity
	domain   string
}

func (s identityRegistryScope) applies(domain string) bool {
	return s.domain != "" && awconfig.NormalizeDomain(s.domain) == awconfig.NormalizeDomain(domain)
}

func selectedIdentityRegistryScope(wd string) (identityRegistryScope, error) {
	if wd == "" {
		return identityRegistryScope{}, nil
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return identityRegistryScope{}, err
	}
	if !home.External() {
		if _, err := os.Lstat(home.Root); errors.Is(err, os.ErrNotExist) {
			return identityRegistryScope{}, nil
		}
	}
	return identityRegistryScopeAt(wd, home.Root)
}

func identityRegistryScopeAt(wd, home string) (identityRegistryScope, error) {
	if home == "" {
		return identityRegistryScope{}, nil
	}
	identity, err := awconfig.ResolveIdentityFromHome(wd, home)
	if err != nil {
		return identityRegistryScope{}, err
	}
	installed, err := awconfig.LoadInstalledIDChain(filepath.Dir(identity.SigningKeyPath))
	if err != nil {
		return identityRegistryScope{}, err
	}
	if recordedPrivateIdentityRegistry(identity) == "" {
		return identityRegistryScope{}, nil
	}
	domain := identity.Domain
	if installed != nil {
		subject := awid.IDChainSubject{ID: identityID(identity), DIDKey: identity.DID}
		plan, err := awid.IDStatusRequest(installed.Bundle, subject, "")
		if err != nil {
			return identityRegistryScope{}, err
		}
		domain, _ = plan["domain"].(string)
	}
	return identityRegistryScope{identity: identity, domain: domain}, nil
}

// An explicit parent can supply the route for the just-issued chain. This
// permission is scoped to the parent home selected on this machine.
type inviteIdentityHomes struct {
	workingDir string
	recipient  string
	parent     string
}

func (homes inviteIdentityHomes) registryScope() (identityRegistryScope, error) {
	scope, err := identityRegistryScopeAt(homes.workingDir, homes.recipient)
	// A new recipient can have just a key and chain at this point.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return identityRegistryScope{}, err
	}
	if scope.identity != nil || homes.parent == "" {
		return scope, nil
	}
	parent := homes.parent
	if _, err := os.Stat(filepath.Join(parent, "signing.key")); errors.Is(err, os.ErrNotExist) {
		parent = filepath.Join(parent, ".aw")
	}
	scope, err = identityRegistryScopeAt(homes.workingDir, parent)
	// A legacy local parent can be represented by its team certificate.
	if errors.Is(err, os.ErrNotExist) {
		return identityRegistryScope{}, nil
	}
	return scope, err
}

type identityEvidenceRoute struct {
	domain    string
	origin    string
	authority awid.DomainAuthority
}

func resolveIdentityEvidenceRoute(ctx context.Context, registry *awid.RegistryClient, resolver awid.TXTResolver, kind registryAuthorityKind, scope identityRegistryScope, domain, override string) (identityEvidenceRoute, error) {
	dnsContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	authority, err := awid.DiscoverAuthoritativeRegistry(dnsContext, resolver, domain)
	if err != nil {
		return identityEvidenceRoute{}, fmt.Errorf("lookup %s: %w", awid.AWIDTXTName(domain), err)
	}
	var identity *awconfig.ResolvedIdentity
	if scope.applies(domain) {
		identity = scope.identity
	}
	origin, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: kind, Authority: authority, Identity: identity, Override: override,
	})
	if err != nil {
		return identityEvidenceRoute{}, err
	}
	if identity != nil {
		trustRecordedRegistryOrigin(registry.Resolver, identity.RegistryURL, identity.RegistryOperatorOrigin)
	}
	return identityEvidenceRoute{domain: awconfig.NormalizeDomain(domain), origin: origin, authority: authority}, nil
}

// Use the same DNS answer for controller validation and route selection.
func (route identityEvidenceRoute) status(registry *awid.RegistryClient) *awid.IDStatusClient {
	status := awid.NewIDStatusClient(registry, nil)
	checkDomain := func(domain string) error {
		if awconfig.NormalizeDomain(domain) != route.domain {
			return fmt.Errorf("registry for %s cannot answer for %s", route.domain, domain)
		}
		return nil
	}
	status.Route = func(_ context.Context, domain string) (string, error) { return route.origin, checkDomain(domain) }
	status.Authority = func(_ context.Context, domain string) (awid.DomainAuthority, error) {
		return route.authority, checkDomain(domain)
	}
	return status
}
