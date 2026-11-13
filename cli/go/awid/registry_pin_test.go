package awid

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// recordingTransport counts the requests an injected client carries.
type recordingTransport struct {
	hosts []string
	base  http.RoundTripper
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.hosts = append(r.hosts, req.URL.Host)
	return r.base.RoundTrip(req)
}

func staticLookup(answers map[string][]string, calls *atomic.Int32) registryHostLookup {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		calls.Add(1)
		var out []netip.Addr
		for _, value := range answers[host] {
			out = append(out, netip.MustParseAddr(value))
		}
		return out, nil
	}
}

// A registry origin learned from DNS is dialled only after every answer for
// its host is checked: a private, loopback or metadata answer refuses the
// request before any connection, whatever client the caller injected.
func TestDNSSelectedRegistryRefusesNonPublicAnswersBeforeDialling(t *testing.T) {
	for _, answers := range [][]string{{"10.0.0.1"}, {"127.0.0.1"}, {"169.254.169.254"}, {"93.184.216.34", "10.0.0.1"}, {"64:ff9b::a00:1"}} {
		var lookups atomic.Int32
		injected := &recordingTransport{base: http.DefaultTransport}
		client := NewAWIDRegistryClient(&http.Client{Transport: injected}, nil)
		client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"registry.example.com": answers}, &lookups), false, nil)

		_, _, err := client.GetNamespaceAt(context.Background(), "https://registry.example.com", "example.com")
		if err == nil {
			t.Fatalf("%v: a non-public answer was dialled", answers)
		}
		if lookups.Load() == 0 {
			t.Fatalf("%v: the host was never resolved by the pinned dialler", answers)
		}
		if len(injected.hosts) != 0 {
			t.Fatalf("%v: a DNS-selected origin went through the injected client: %v", answers, injected.hosts)
		}
	}
}

// The pinned client dials only the checked address, and TLS still verifies
// the registry's host name, not the address.
func TestDNSSelectedRegistryDialsTheCheckedAddressWithTheHostName(t *testing.T) {
	var gotHost string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"domain":"example.com","controller_did":"did:key:z6Mk","verification_status":"verified"}`))
	}))
	defer server.Close()
	port := strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	var lookups atomic.Int32
	client := NewAWIDRegistryClient(nil, nil)
	// example.com is a name the httptest certificate covers; the test lookup
	// answers with the loopback the test server listens on.
	client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"example.com": {"127.0.0.1"}}, &lookups), true, &tls.Config{RootCAs: roots})
	origin := "https://example.com:" + port
	if _, _, err := client.GetNamespaceAt(context.Background(), origin, "example.com"); err != nil {
		t.Fatalf("the checked address must be dialled: %v", err)
	}
	if lookups.Load() != 1 || gotHost != "example.com:"+port {
		t.Fatalf("lookups=%d host=%q", lookups.Load(), gotHost)
	}

	// A certificate for another name is refused: the dial address does not
	// stand in for the host name.
	client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"registry.other.test": {"127.0.0.1"}}, &lookups), true, &tls.Config{RootCAs: roots})
	if _, _, err := client.GetNamespaceAt(context.Background(), "https://registry.other.test:"+port, "example.com"); err == nil {
		t.Fatal("TLS must verify the registry host name, not the dialled address")
	}
}

func TestDNSSelectedRegistryRefusesPlainHTTP(t *testing.T) {
	var lookups atomic.Int32
	client := NewAWIDRegistryClient(nil, nil)
	client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"registry.example.com": {"93.184.216.34"}}, &lookups), false, nil)
	_, _, err := client.GetNamespaceAt(context.Background(), "http://registry.example.com", "example.com")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("a DNS-selected registry must be https: %v", err)
	}
	if lookups.Load() != 0 {
		t.Fatal("plain http must be refused before any lookup")
	}
}

func jsonNamespaceServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"domain":"example.com","controller_did":"did:key:z6Mk","verification_status":"verified"}`))
	}))
	t.Cleanup(server.Close)
	return server
}

// Only the operator's explicit choices keep the injected client: the
// built-in default, AWID_REGISTRY_URL, and an origin the command line named
// (TrustRegistryOrigin). A fallback or default taken from stored state is not
// trusted by being configured on the client.
func TestOnlyExplicitOperatorChoicesUseTheInjectedClient(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AWID_REGISTRY_URL", "")
	var lookups atomic.Int32
	injected := &recordingTransport{base: http.DefaultTransport}
	client := NewAWIDRegistryClient(&http.Client{Transport: injected}, nil)
	client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(nil, &lookups), false, nil)

	stored := jsonNamespaceServer(t)
	if err := client.SetFallbackRegistryURL(stored.URL); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.GetNamespaceAt(context.Background(), "", "example.com"); err == nil {
		t.Fatal("a default taken from stored state must not be trusted")
	} else if !strings.Contains(err.Error(), "AWID_REGISTRY_URL") {
		t.Fatalf("the refusal must name AWID_REGISTRY_URL as the fix: %v", err)
	}

	flagged := jsonNamespaceServer(t)
	if err := client.TrustRegistryOrigin(flagged.URL + "/"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.GetNamespaceAt(context.Background(), flagged.URL, "example.com"); err != nil {
		t.Fatalf("an origin the command line named must use the injected client: %v", err)
	}

	env := jsonNamespaceServer(t)
	t.Setenv("AWID_REGISTRY_URL", env.URL)
	if _, _, err := client.GetNamespaceAt(context.Background(), env.URL, "example.com"); err != nil {
		t.Fatalf("AWID_REGISTRY_URL must use the injected client: %v", err)
	}
	if len(injected.hosts) != 2 || lookups.Load() != 0 {
		t.Fatalf("injected hosts=%v pinned lookups=%d", injected.hosts, lookups.Load())
	}
}

// The ID status route goes through the same choice.
func TestIDStatusRouteToAnUntrustedOriginIsPinned(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")
	var lookups atomic.Int32
	injected := &recordingTransport{base: http.DefaultTransport}
	registry := NewAWIDRegistryClient(&http.Client{Transport: injected}, nil)
	registry.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"registry.example.com": {"10.0.0.1"}}, &lookups), false, nil)
	if got := registry.httpClientFor("https://registry.example.com"); got != registry.Resolver.pinnedHTTPClient {
		t.Fatal("an untrusted origin must select the pinned client")
	}
	if got := registry.httpClientFor(DefaultAWIDRegistryURL); got == registry.Resolver.pinnedHTTPClient {
		t.Fatal("the built-in default must keep the caller's client")
	}
}

// The isolated-development mode of the federation contract also applies to
// the pinned registry client: with APP_ENV=development and
// AWEB_FEDERATION_TEST enabled, an isolated host (loopback, localhost, *.test,
// a single label) is reachable over http. Production refuses the same origin
// when either variable is missing, and no other host gains anything.
func TestPinnedRegistryAdmitsIsolatedHostsOnlyInIsolatedDevelopment(t *testing.T) {
	server := jsonNamespaceServer(t)
	get := func() error {
		client := NewAWIDRegistryClient(nil, nil)
		_, _, err := client.GetNamespaceAt(context.Background(), server.URL, "example.com")
		return err
	}
	t.Setenv("AWID_REGISTRY_URL", "")

	t.Setenv("APP_ENV", "development")
	t.Setenv("AWEB_FEDERATION_TEST", "1")
	if err := get(); err != nil {
		t.Fatalf("isolated development must reach a loopback registry: %v", err)
	}

	for name, env := range map[string][2]string{
		"no APP_ENV":            {"", "1"},
		"production":            {"production", "1"},
		"no federation test":    {"development", ""},
		"federation test false": {"development", "false"},
	} {
		t.Setenv("APP_ENV", env[0])
		t.Setenv("AWEB_FEDERATION_TEST", env[1])
		if err := get(); err == nil {
			t.Fatalf("%s: a loopback registry was reached outside isolated development", name)
		}
	}

	t.Setenv("APP_ENV", "development")
	t.Setenv("AWEB_FEDERATION_TEST", "1")
	var lookups atomic.Int32
	client := NewAWIDRegistryClient(nil, nil)
	client.Resolver.pinnedHTTPClient = newPinnedRegistryHTTPClient(staticLookup(map[string][]string{"registry.example.com": {"10.0.0.1"}}, &lookups), false, nil)
	if _, _, err := client.GetNamespaceAt(context.Background(), "http://registry.example.com", "example.com"); err == nil {
		t.Fatal("isolated development must not admit a non-isolated host")
	}
}
