package awid

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type registryTXTLookup struct {
	records []string
	err     error
}

type registryTXTResolver struct {
	mu      sync.Mutex
	lookups map[string]registryTXTLookup
	calls   []string
}

func (r *registryTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, name)
	lookup, ok := r.lookups[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true}
	}
	return lookup.records, lookup.err
}

func (r *registryTXTResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func TestRegistryResolverIdentityRegistrySelection(t *testing.T) {
	controller := "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	const (
		homeRegistry    = "https://home.registry.test"
		foreignRegistry = "https://foreign.registry.test"
	)

	tests := []struct {
		name      string
		domain    string
		lookups   map[string]registryTXTLookup
		want      string
		wantErr   string
		wantCalls int
	}{
		{
			name:   "foreign record beats fallback",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {records: []string{"awid=v1; controller=" + controller + "; registry=" + foreignRegistry + ";"}},
			},
			want:      foreignRegistry,
			wantCalls: 1,
		},
		{
			name:      "foreign no record falls back",
			domain:    "foreign.example",
			lookups:   map[string]registryTXTLookup{},
			want:      homeRegistry,
			wantCalls: 1,
		},
		{
			name:   "foreign DNS timeout falls back",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {err: &net.DNSError{Err: "timeout", IsTimeout: true}},
			},
			want:      homeRegistry,
			wantCalls: 1,
		},
		{
			name:   "foreign DNS servfail falls back",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}},
			},
			want:      homeRegistry,
			wantCalls: 1,
		},
		{
			name:   "foreign DNS connection refused falls back",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {err: &net.DNSError{Err: "connection refused"}},
			},
			want:      homeRegistry,
			wantCalls: 1,
		},
		{
			name:   "foreign malformed DNS response fails closed",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {err: &net.DNSError{Err: "cannot unmarshal DNS message"}},
			},
			wantErr:   "cannot unmarshal DNS message",
			wantCalls: 1,
		},
		{
			name:   "foreign malformed record fails closed",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {records: []string{"awid=v2; controller=" + controller + "; registry=" + foreignRegistry + ";"}},
			},
			wantErr:   "unsupported awid version",
			wantCalls: 1,
		},
		{
			name:   "foreign multiple records fail closed",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {records: []string{
					"awid=v1; controller=" + controller + "; registry=https://one.registry.test;",
					"awid=v1; controller=" + controller + "; registry=https://two.registry.test;",
				}},
			},
			wantErr:   "multiple awid TXT records",
			wantCalls: 1,
		},
		{
			name:   "foreign invalid controller fails closed",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {records: []string{"awid=v1; controller=did:key:invalid; registry=" + foreignRegistry + ";"}},
			},
			wantErr:   "invalid controller DID",
			wantCalls: 1,
		},
		{
			name:   "foreign invalid registry fails closed",
			domain: "foreign.example",
			lookups: map[string]registryTXTLookup{
				"_awid.foreign.example": {records: []string{"awid=v1; controller=" + controller + "; registry=https://foreign.registry.test/path;"}},
			},
			wantErr:   "invalid registry origin",
			wantCalls: 1,
		},
		{
			name:   "own domain pin wins without DNS",
			domain: "home.example",
			lookups: map[string]registryTXTLookup{
				"_awid.home.example": {records: []string{"awid=v1; controller=" + controller + "; registry=" + foreignRegistry + ";"}},
			},
			want:      homeRegistry,
			wantCalls: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dns := &registryTXTResolver{lookups: test.lookups}
			resolver := NewRegistryResolver(nil, dns)
			if err := resolver.SetIdentityRegistryURL(homeRegistry, "home.example"); err != nil {
				t.Fatal(err)
			}

			authority, err := resolver.discoverAuthority(context.Background(), test.domain)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("err=%v, want containing %q", err, test.wantErr)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if authority.RegistryURL != test.want {
					t.Fatalf("RegistryURL=%q, want %q", authority.RegistryURL, test.want)
				}
			}
			if got := dns.callCount(); got != test.wantCalls {
				t.Fatalf("DNS calls=%d, want %d", got, test.wantCalls)
			}
		})
	}
}

func TestRegistryResolverWithoutFallbackKeepsPublicDefaultAndDNSFailure(t *testing.T) {
	t.Run("no record uses public default", func(t *testing.T) {
		dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{}}
		resolver := NewRegistryResolver(nil, dns)
		authority, err := resolver.discoverAuthority(context.Background(), "foreign.example")
		if err != nil {
			t.Fatal(err)
		}
		if authority.RegistryURL != DefaultAWIDRegistryURL {
			t.Fatalf("RegistryURL=%q, want %q", authority.RegistryURL, DefaultAWIDRegistryURL)
		}
	})

	t.Run("DNS failure remains an error", func(t *testing.T) {
		dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{
			"_awid.foreign.example": {err: &net.DNSError{Err: "timeout", IsTimeout: true}},
		}}
		resolver := NewRegistryResolver(nil, dns)
		if _, err := resolver.discoverAuthority(context.Background(), "foreign.example"); err == nil {
			t.Fatal("expected DNS failure without a configured fallback")
		}
	})
}

func TestRegistryResolverExplicitPinNeverConsultsDNS(t *testing.T) {
	dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{
		"_awid.foreign.example": {err: &net.DNSError{Err: "must not be called"}},
	}}
	resolver := NewRegistryResolver(nil, dns)
	if err := resolver.SetFallbackRegistryURL("https://home.registry.test"); err != nil {
		t.Fatal(err)
	}

	registryURL, err := resolver.DiscoverRegistry(context.Background(), "foreign.example")
	if err != nil {
		t.Fatal(err)
	}
	if registryURL != "https://home.registry.test" {
		t.Fatalf("registryURL=%q", registryURL)
	}
	if got := dns.callCount(); got != 0 {
		t.Fatalf("DNS calls=%d, want 0", got)
	}
}

func TestRegistryResolverUsesDifferentRegistriesForOwnAndForeignAddresses(t *testing.T) {
	homeServer, homeStableID, homeDID, homeHits := newAddressRegistryServer(t, "home.example", "alice")
	foreignServer, foreignStableID, foreignDID, foreignHits := newAddressRegistryServer(t, "foreign.example", "bob")

	homeOrigin := registryTestOrigin(t, "home.registry.test", homeServer.URL)
	foreignOrigin := registryTestOrigin(t, "foreign.registry.test", foreignServer.URL)
	dns := &registryTXTResolver{lookups: map[string]registryTXTLookup{
		"_awid.foreign.example": {records: []string{"awid=v1; controller=" + foreignDID + "; registry=" + foreignOrigin + ";"}},
	}}
	client := registryRoutingHTTPClient(t, map[string]string{
		"home.registry.test":    homeServer.URL,
		"foreign.registry.test": foreignServer.URL,
	})
	resolver := NewRegistryResolver(client, dns)
	if err := resolver.SetIdentityRegistryURL(homeOrigin, "home.example"); err != nil {
		t.Fatal(err)
	}

	home, err := resolver.Resolve(context.Background(), "home.example/alice")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := resolver.Resolve(context.Background(), "foreign.example/bob")
	if err != nil {
		t.Fatal(err)
	}
	if home.StableID != homeStableID || home.DID != homeDID || home.RegistryURL != homeOrigin {
		t.Fatalf("home resolution=%+v", home)
	}
	if foreign.StableID != foreignStableID || foreign.DID != foreignDID || foreign.RegistryURL != foreignOrigin {
		t.Fatalf("foreign resolution=%+v", foreign)
	}
	if homeHits.Load() != 2 {
		t.Fatalf("home registry hits=%d, want address+key", homeHits.Load())
	}
	if foreignHits.Load() != 2 {
		t.Fatalf("foreign registry hits=%d, want address+key", foreignHits.Load())
	}
}

func newAddressRegistryServer(t *testing.T, domain, name string) (*httptest.Server, string, string, *atomic.Int64) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	hits := &atomic.Int64{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/v1/namespaces/" + domain + "/addresses/" + name:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "address-" + name,
				"domain":          domain,
				"name":            name,
				"did_aw":          stableID,
				"current_did_key": did,
				"created_at":      "2026-08-25T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, stableID, did, hits
}

func registryTestOrigin(t *testing.T, host, serverURL string) string {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	return "https://" + net.JoinHostPort(host, port)
}

func registryRoutingHTTPClient(t *testing.T, routes map[string]string) *http.Client {
	t.Helper()
	addresses := make(map[string]string, len(routes))
	for host, rawURL := range routes {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		addresses[host] = parsed.Host
	}
	dialer := &net.Dialer{}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // Test-only TLS servers use generated certificates.
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		target, ok := addresses[host]
		if !ok {
			return nil, &net.DNSError{Err: "unexpected registry host", Name: host}
		}
		return dialer.DialContext(ctx, network, target)
	}
	client := &http.Client{Transport: transport}
	t.Cleanup(transport.CloseIdleConnections)
	return client
}
