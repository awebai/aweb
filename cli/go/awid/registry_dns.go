package awid

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const DefaultAWIDRegistryURL = "https://api.awid.ai"

type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type NetTXTResolver struct {
	Resolver *net.Resolver
}

func (r *NetTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return resolver.LookupTXT(ctx, name)
}

type DomainAuthority struct {
	ControllerDID string
	RegistryURL   string
	DNSName       string
	Inherited     bool
}

func DiscoverAuthoritativeRegistry(ctx context.Context, resolver TXTResolver, domain string) (DomainAuthority, error) {
	return lookupDomainAuthority(ctx, resolver, domain, true)
}

func VerifyExactDomainAuthority(ctx context.Context, resolver TXTResolver, domain string) (DomainAuthority, error) {
	return lookupDomainAuthority(ctx, resolver, domain, false)
}

func AWIDTXTName(domain string) string {
	return "_awid." + canonicalizeDomain(domain)
}

func lookupDomainAuthority(ctx context.Context, resolver TXTResolver, domain string, allowAncestors bool) (DomainAuthority, error) {
	if resolver == nil {
		resolver = &NetTXTResolver{}
	}
	candidates := candidateDomainsForLookup(domain, allowAncestors)
	if len(candidates) == 0 {
		return DomainAuthority{}, fmt.Errorf("invalid domain")
	}
	canonical := canonicalizeDomain(domain)
	for _, candidate := range candidates {
		qname := AWIDTXTName(candidate)
		records, err := resolver.LookupTXT(ctx, qname)
		if err != nil {
			if isTXTNotFound(err) {
				if allowAncestors {
					continue
				}
				return DomainAuthority{}, err
			}
			return DomainAuthority{}, err
		}
		awidRecords := make([]string, 0, len(records))
		for _, record := range records {
			record = strings.TrimSpace(record)
			if strings.HasPrefix(record, "awid=") {
				awidRecords = append(awidRecords, record)
			}
		}
		if len(awidRecords) == 0 {
			if allowAncestors {
				continue
			}
			return DomainAuthority{}, fmt.Errorf("no awid TXT record found at %s", qname)
		}
		if len(awidRecords) > 1 {
			return DomainAuthority{}, fmt.Errorf("multiple awid TXT records found at %s", qname)
		}
		authority, err := ParseAWIDTXTRecord(awidRecords[0], qname)
		if err != nil {
			return DomainAuthority{}, err
		}
		if candidate != canonical {
			authority.Inherited = true
		}
		return authority, nil
	}
	if allowAncestors {
		return DomainAuthority{
			RegistryURL: DefaultAWIDRegistryURL,
		}, nil
	}
	return DomainAuthority{}, fmt.Errorf("no TXT records found for %s", AWIDTXTName(domain))
}

func ParseAWIDTXTRecord(record, dnsName string) (DomainAuthority, error) {
	fields := make(map[string]string)
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, exists := fields[key]; exists {
			return DomainAuthority{}, fmt.Errorf("duplicate %s field in awid TXT record", key)
		}
		fields[key] = strings.TrimSpace(value)
	}

	if fields["awid"] != "v1" {
		return DomainAuthority{}, fmt.Errorf("unsupported awid version: %s", fields["awid"])
	}
	controller := strings.TrimSpace(fields["controller"])
	if controller == "" {
		return DomainAuthority{}, fmt.Errorf("missing controller field in awid TXT record")
	}
	if _, err := ExtractPublicKey(controller); err != nil {
		return DomainAuthority{}, fmt.Errorf("invalid controller DID: %s", controller)
	}

	registry := strings.TrimSpace(fields["registry"])
	if registry == "" {
		registry = DefaultAWIDRegistryURL
	} else {
		canonical, err := validateRegistryOrigin(registry)
		if err != nil {
			return DomainAuthority{}, fmt.Errorf("invalid registry origin in awid TXT record: %s", registry)
		}
		registry = canonical
	}

	return DomainAuthority{
		ControllerDID: controller,
		RegistryURL:   registry,
		DNSName:       dnsName,
	}, nil
}

func candidateDomainsForLookup(domain string, allowAncestors bool) []string {
	canonical := canonicalizeDomain(domain)
	if canonical == "" {
		return nil
	}
	if !allowAncestors {
		return []string{canonical}
	}
	labels := strings.Split(canonical, ".")
	boundary := registeredDomainBoundary(canonical)
	boundaryLabels := strings.Split(boundary, ".")
	maxIndex := len(labels) - len(boundaryLabels)
	if maxIndex < 0 {
		maxIndex = 0
	}
	out := make([]string, 0, maxIndex+1)
	for idx := 0; idx <= maxIndex; idx++ {
		out = append(out, strings.Join(labels[idx:], "."))
	}
	return out
}

func registeredDomainBoundary(domain string) string {
	boundary, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil || strings.TrimSpace(boundary) == "" {
		return canonicalizeDomain(domain)
	}
	return canonicalizeDomain(boundary)
}

func canonicalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func isTXTNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "nxdomain") || strings.Contains(msg, "no answer")
}

func validateRegistryOrigin(raw string) (string, error) {
	canonical, err := canonicalServerOrigin(raw)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(canonical)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("registry URL must include a host")
	}
	if parsed.Scheme != "https" && !isExplicitDevelopmentEnvironment() {
		return "", fmt.Errorf("registry URL must use https unless APP_ENV=development")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "", fmt.Errorf("registry URL must not target localhost")
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
			return "", fmt.Errorf("registry URL must not target a local or reserved IP address")
		}
		return "", fmt.Errorf("registry URL must not use a literal IP address")
	}
	return canonical, nil
}

func canonicalServerOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("server URL must be non-empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("server URL scheme must be http or https")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("server URL must not include userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("server URL must not include query or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("server URL must not include a path")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fmt.Errorf("server URL must include a host")
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	hostOut := host
	if strings.ContainsRune(host, ':') && !strings.HasPrefix(host, "[") {
		hostOut = "[" + host + "]"
	}
	if port != "" {
		hostOut += ":" + port
	}
	return scheme + "://" + hostOut, nil
}

func isExplicitDevelopmentEnvironment() bool {
	for _, name := range []string{"APP_ENV", "ENVIRONMENT"} {
		value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
		if value == "" {
			continue
		}
		return value == "dev" || value == "development" || value == "local"
	}
	return false
}
