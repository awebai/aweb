package awid

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Only the operator's explicit, live choices are reached with the caller's own
// HTTP client: the built-in default registry, AWID_REGISTRY_URL, and an origin
// the operator named on the current command line or in the running program's
// own configuration (TrustRegistryOrigin). Every other registry
// origin, whether stored in identity, team or controller files, carried by an
// invite, returned by service discovery or learned from an _awid TXT record,
// is reached only through the pinned client below, whatever client the caller
// injected. A private self-hosted registry is therefore named by
// AWID_REGISTRY_URL.

// registryHostLookup resolves a registry host name.
type registryHostLookup func(ctx context.Context, host string) ([]netip.Addr, error)

func systemRegistryHostLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newPinnedRegistryHTTPClient is the client for registry origins learned from
// DNS. Each connection resolves the host once and is refused unless every
// answer is a public address; it then dials only the checked addresses, in
// order, and TLS verifies the host name. Only https is spoken, and proxies
// from the environment are not used. allowNonPublicTest and tlsConfig exist
// for this package's tests.
func newPinnedRegistryHTTPClient(lookup registryHostLookup, allowNonPublicTest bool, tlsConfig *tls.Config) *http.Client {
	if lookup == nil {
		lookup = systemRegistryHostLookup
	}
	transport := NewAPITransport()
	transport.Proxy = nil
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		isolated := isolatedRegistryDevelopment(host)
		var values []string
		if _, err := netip.ParseAddr(host); err == nil {
			if !isolated {
				return nil, fmt.Errorf("a registry not named by AWID_REGISTRY_URL or the command line must be named by host, not address %s", host)
			}
			values = []string{host}
		} else {
			answers, err := lookup(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("resolve registry host %s: %w", host, err)
			}
			values = make([]string, len(answers))
			for i, answer := range answers {
				values[i] = answer.String()
			}
		}
		approved, err := validateFederationResolvedIPs(values, allowNonPublicTest || isolated)
		if err != nil {
			return nil, fmt.Errorf("registry host %s resolves to an address that is not public (%w); for a private self-hosted registry, name it with AWID_REGISTRY_URL", host, err)
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		var lastErr error
		for _, ip := range approved {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return &http.Client{Timeout: APITimeout(), Transport: httpsOnlyRoundTripper{transport}}
}

type httpsOnlyRoundTripper struct{ next http.RoundTripper }

func (h httpsOnlyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || (req.URL.Scheme != "https" && !isolatedRegistryDevelopment(req.URL.Hostname())) {
		return nil, errors.New("a registry not named by AWID_REGISTRY_URL or the command line must use https")
	}
	return h.next.RoundTrip(req)
}

// isolatedRegistryDevelopment is the federation contract's isolated-development
// mode applied to registry dials: APP_ENV=development and AWEB_FEDERATION_TEST
// both set, and an isolated host (a loopback literal, localhost, *.localhost,
// *.test, *.test.local or a single label). Only then may a registry not chosen
// by the operator be reached over http or at a non-public address.
func isolatedRegistryDevelopment(host string) bool {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "development") {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AWEB_FEDERATION_TEST"))) {
	case "1", "true", "yes", "on":
	default:
		return false
	}
	return isIsolatedFederationHost(host)
}

// registryOriginKey is the comparable form of a registry origin, or "" when
// raw is not a usable origin.
func registryOriginKey(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return scheme + "://[" + host + "]"
	}
	return scheme + "://" + host
}

// registryTrust is the set of registry origins the operator named on the
// current command line or in the program's own configuration
// (TrustRegistryOrigin).
type registryTrust struct {
	mu      sync.Mutex
	origins map[string]bool
}

func (t *registryTrust) trust(raw string) error {
	key := registryOriginKey(raw)
	if key == "" {
		return fmt.Errorf("invalid registry origin %q", raw)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.origins == nil {
		t.origins = map[string]bool{}
	}
	t.origins[key] = true
	return nil
}

func (t *registryTrust) trusted(raw string) bool {
	key := registryOriginKey(raw)
	if key == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.origins[key]
}

// TrustRegistryOrigin marks raw, a registry the operator named on the
// current command line or in the program's own configuration (the gateway's
// registry_url), as reachable with the resolver's own HTTP client.
// The built-in default and AWID_REGISTRY_URL are trusted without it. Never
// pass an origin that is stored or supplied by someone else (identity.yaml,
// teams.yaml, an invite, controller metadata, service discovery or DNS):
// those stay pinned to public addresses.
func (r *RegistryResolver) TrustRegistryOrigin(raw string) error {
	return r.trust.trust(raw)
}

func (r *RegistryResolver) originTrusted(raw string) bool {
	key := registryOriginKey(raw)
	if key == "" {
		return false
	}
	if key == registryOriginKey(DefaultAWIDRegistryURL) {
		return true
	}
	if env := strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL")); env != "" && key == registryOriginKey(env) {
		return true
	}
	return r.trust.trusted(raw)
}

// pinnedClient is the shared client for registry origins learned from DNS.
func (r *RegistryResolver) pinnedClient() *http.Client {
	r.pinnedMu.Lock()
	defer r.pinnedMu.Unlock()
	if r.pinnedHTTPClient == nil {
		r.pinnedHTTPClient = newPinnedRegistryHTTPClient(nil, false, nil)
	}
	return r.pinnedHTTPClient
}

// httpClientFor is the client a request to registryURL uses.
func (r *RegistryResolver) httpClientFor(registryURL string) *http.Client {
	if r.originTrusted(registryURL) {
		return r.HTTPClient
	}
	return r.pinnedClient()
}

// TrustRegistryOrigin marks raw, a registry the operator named on the
// current command line or in the program's own configuration, as reachable
// with the client's own HTTP client; see
// RegistryResolver.TrustRegistryOrigin.
func (c *RegistryClient) TrustRegistryOrigin(raw string) error {
	if c == nil || c.Resolver == nil {
		return fmt.Errorf("registry client has no resolver")
	}
	return c.Resolver.TrustRegistryOrigin(raw)
}

// httpClientFor is the client a request to registryURL uses: the caller's
// own for an origin the operator chose explicitly, the pinned client for any
// other. An empty registryURL means the client's default, judged the same way.
func (c *RegistryClient) httpClientFor(registryURL string) *http.Client {
	if strings.TrimSpace(registryURL) == "" {
		registryURL = c.defaultRegistryURL()
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = &RegistryResolver{}
	}
	if resolver.originTrusted(registryURL) {
		return c.httpClient()
	}
	if c.Resolver == nil {
		return newPinnedRegistryHTTPClient(nil, false, nil)
	}
	return c.Resolver.pinnedClient()
}

// inheritRegistryPolicy gives r the operator's trusted origins and the pinned
// client of from, for a resolver or client derived from another.
func (r *RegistryResolver) inheritRegistryPolicy(from *RegistryResolver) {
	if r == nil || from == nil || r == from {
		return
	}
	from.trust.mu.Lock()
	origins := make([]string, 0, len(from.trust.origins))
	for origin := range from.trust.origins {
		origins = append(origins, origin)
	}
	from.trust.mu.Unlock()
	for _, origin := range origins {
		_ = r.trust.trust(origin)
	}
	from.pinnedMu.Lock()
	pinned := from.pinnedHTTPClient
	from.pinnedMu.Unlock()
	r.pinnedMu.Lock()
	r.pinnedHTTPClient = pinned
	r.pinnedMu.Unlock()
}
