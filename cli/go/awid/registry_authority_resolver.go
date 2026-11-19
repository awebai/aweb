package awid

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// SelectRegistry resolves only when the selection owner asks for DNS. The
// result retains provenance and fallback404 semantics for supported callers;
// it supplies no administrative network admission or identity verification.
func (r *RegistryResolver) SelectRegistry(ctx context.Context, in RegistryAuthorityInput) (RegistryAuthoritySelection, error) {
	selection, _, err := r.selectRegistryWithAuthority(ctx, in)
	return selection, err
}

func (r *RegistryResolver) selectRegistryWithAuthority(ctx context.Context, in RegistryAuthorityInput) (RegistryAuthoritySelection, DomainAuthority, error) {
	selection, err := SelectRegistryAuthority(in)
	if err != nil || selection.Action != RegistryLookupRequired {
		return selection, DomainAuthority{RegistryURL: selection.Origin}, err
	}
	domain := canonicalizeDomain(in.Domain)
	authority, cached := r.loadRegistryCache(domain)
	var acquisitionErr error
	if cached {
		in.Memo = &RegistryAuthorityMemo{Domain: domain, Origin: authority.RegistryURL, Controller: authority.ControllerDID}
	} else {
		authority, acquisitionErr = DiscoverAuthoritativeRegistry(ctx, r.DNSResolver, domain)
		if acquisitionErr != nil {
			in.Discovery.State = registryDiscoveryFailure(acquisitionErr)
		} else if strings.TrimSpace(authority.ControllerDID) == "" {
			in.Discovery.State = RegistryDiscoveryAbsent
		} else {
			in.Discovery = RegistryDiscoveryObservation{State: RegistryDiscoveryFound, Origin: authority.RegistryURL}
		}
	}
	selection, err = SelectRegistryAuthority(in)
	if err != nil {
		if acquisitionErr != nil {
			return RegistryAuthoritySelection{}, DomainAuthority{}, fmt.Errorf("%w. %s", acquisitionErr, err)
		}
		return RegistryAuthoritySelection{}, DomainAuthority{}, err
	}
	authority.RegistryURL = selection.Origin
	if acquisitionErr == nil && !cached {
		// A fallback route has no controller and remains unknown404 evidence
		// when reused. Caching a route is not caching authoritative absence.
		r.storeRegistryCache(domain, authority, registryDiscoveryTTL)
	}
	return selection, authority, nil
}

func registryDiscoveryFailure(err error) RegistryDiscoveryState {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return RegistryDiscoveryMalformed
	}
	if dnsErr.IsTimeout {
		return RegistryDiscoveryTimeout
	}
	if dnsErr.IsTemporary {
		return RegistryDiscoveryTemporaryFailure
	}
	detail := strings.ToLower(strings.TrimSpace(dnsErr.Err))
	if strings.Contains(detail, "connection refused") {
		return RegistryDiscoveryConnectionRefused
	}
	if strings.Contains(detail, "network is unreachable") || strings.Contains(detail, "no route to host") {
		return RegistryDiscoveryUnreachable
	}
	return RegistryDiscoveryRefused
}

func registrySelectionEnvironment() RegistryEnvironment {
	if isExplicitDevelopmentEnvironment() {
		return RegistryDevelopment
	}
	return RegistryProduction
}
