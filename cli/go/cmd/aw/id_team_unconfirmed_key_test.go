package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// teamReadFaultProxy forwards to a real AWID registry. With failTeamRead set
// it answers the read of one team with 503, as when the registry is briefly
// unreachable; beforeCreate runs once, before the first create of that team
// is forwarded.
type teamReadFaultProxy struct {
	proxy        *httputil.ReverseProxy
	teamPath     string
	createPath   string
	failTeamRead atomic.Bool
	beforeCreate func()
	once         sync.Once
}

func (p *teamReadFaultProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet && req.URL.Path == p.teamPath && p.failTeamRead.Load() {
		http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
		return
	}
	if req.Method == http.MethodPost && req.URL.Path == p.createPath && p.beforeCreate != nil {
		p.once.Do(p.beforeCreate)
	}
	p.proxy.ServeHTTP(w, req)
}

func newTeamReadFaultProxy(t *testing.T, registryURL, domain, name string) (*teamReadFaultProxy, string) {
	t.Helper()
	target, err := url.Parse(registryURL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := &teamReadFaultProxy{
		proxy:      httputil.NewSingleHostReverseProxy(target),
		teamPath:   "/v1/namespaces/" + domain + "/teams/" + name,
		createPath: "/v1/namespaces/" + domain + "/teams",
	}
	server := newLocalHTTPServer(t, proxy)
	return proxy, server.URL
}

// registerTeamAt runs the team registration aw id team create runs, through
// registryURL, as the namespace controller controllerKey.
func registerTeamAt(t *testing.T, registryURL, domain, name string, controllerKey ed25519.PrivateKey) (*localTeamRegistration, error) {
	t.Helper()
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return ensureLocalTeamRegistered(ctx, registry, "", domain, name, "", controllerKey)
}

// directRegistry reaches the real registry without the fault proxy.
func directRegistry(t *testing.T, registryURL string) *awid.RegistryClient {
	t.Helper()
	return trustedClient(t, registryURL, http.DefaultTransport)
}

func assertNoTeamKeyFile(t *testing.T, domain, name string) {
	t.Helper()
	exists, err := awconfig.TeamKeyExists(domain, name)
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("a team key file is present")
	}
}

func setAsideKey(t *testing.T, domain, name string) ed25519.PrivateKey {
	t.Helper()
	key, _, err := awconfig.LoadUnconfirmedTeamKey(domain, name)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Another run on this machine registers the key this run created before this
// run's own create reaches the registry. This run's read then fails, so it
// cannot tell its key is the registered one: it sets the key aside instead of
// destroying it, refuses as unconfirmed while reads fail, and restores the key
// on the first run whose read answers. The team then works with that key.
func TestTeamCreateSetsAsideAKeyItCannotConfirmAndRestoresIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	const domain, name = "unconfirmed-race.example", "ops"
	proxy, proxyURL := newTeamReadFaultProxy(t, registryURL, domain, name)
	controllerKey := newKey(t)
	var registered string
	proxy.beforeCreate = func() {
		// The concurrent run: it loads the key this run saved and registers
		// it first, then the registry stops answering reads.
		key, err := awconfig.LoadTeamKey(domain, name)
		if err != nil {
			t.Errorf("load the saved key: %v", err)
			return
		}
		registered = didOf(key)
		if _, err := directRegistry(t, registryURL).CreateTeam(context.Background(), registryURL, domain, name, "", registered, controllerKey); err != nil {
			t.Errorf("concurrent registration: %v", err)
		}
		proxy.failTeamRead.Store(true)
	}

	_, err := registerTeamAt(t, proxyURL, domain, name, controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameUnconfirmed {
		t.Fatalf("first run: code=%q err=%v, want %q", code, err, codeTeamNameUnconfirmed)
	}
	aside := setAsideKey(t, domain, name)
	if aside == nil || didOf(aside) != registered {
		t.Fatal("the registered key was not set aside")
	}
	assertNoTeamKeyFile(t, domain, name)
	if _, err := awconfig.LoadTeamKey(domain, name); !errors.Is(err, awconfig.ErrTeamKeyUnconfirmed) {
		t.Fatalf("LoadTeamKey err=%v, want ErrTeamKeyUnconfirmed", err)
	}
	if code := errorCodeOf(func() error { _, err := awconfig.LoadTeamKey(domain, name); return err }()); code != codeTeamNameUnconfirmed {
		t.Fatalf("a command reading the team key gets code %q, want %q", code, codeTeamNameUnconfirmed)
	}

	// While reads fail, the set-aside key is left alone and no new key is made.
	_, err = registerTeamAt(t, proxyURL, domain, name, controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameUnconfirmed {
		t.Fatalf("run while reads fail: code=%q err=%v", code, err)
	}
	if again := setAsideKey(t, domain, name); again == nil || !again.Equal(aside) {
		t.Fatal("the set-aside key changed while reads failed")
	}
	assertNoTeamKeyFile(t, domain, name)

	proxy.failTeamRead.Store(false)
	result, err := registerTeamAt(t, proxyURL, domain, name, controllerKey)
	if err != nil {
		t.Fatalf("run once the registry answers: %v", err)
	}
	if result.TeamDIDKey != registered {
		t.Fatalf("team key=%s, the registry pins %s", result.TeamDIDKey, registered)
	}
	if setAsideKey(t, domain, name) != nil {
		t.Fatal("the set-aside key was not restored")
	}
	key, err := awconfig.LoadTeamKey(domain, name)
	if err != nil || !key.Equal(aside) {
		t.Fatalf("the team key is not the restored key: %v", err)
	}
	// The team works with that key: the registry answers its signed read.
	team, err := directRegistry(t, registryURL).GetTeam(context.Background(), registryURL, domain, name, key)
	if err != nil {
		t.Fatalf("signed read with the restored key: %v", err)
	}
	if team.TeamDIDKey != registered {
		t.Fatalf("registry team key=%s, want %s", team.TeamDIDKey, registered)
	}
}

// A key set aside while reads failed is removed by the first read that shows
// the registry pins another key, and the name is refused as taken.
func TestTeamCreateRemovesAnUnconfirmedKeyTheRegistryShowsIsNotTheTeams(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	const domain, name = "unconfirmed-elsewhere.example", "ops"
	proxy, proxyURL := newTeamReadFaultProxy(t, registryURL, domain, name)
	controllerKey := newKey(t)
	// The namespace is this controller's; the team is pinned to another key
	// and is public, so this run's read can tell.
	if _, err := registerTeamAt(t, registryURL, domain, "seed", controllerKey); err != nil {
		t.Fatalf("seed the namespace: %v", err)
	}
	other := newKey(t)
	registry := directRegistry(t, registryURL)
	if _, err := registry.CreateTeam(context.Background(), registryURL, domain, name, "", didOf(other), controllerKey); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.SetTeamVisibility(context.Background(), registryURL, domain, name, "public", other); err != nil {
		t.Fatal(err)
	}

	proxy.failTeamRead.Store(true)
	_, err := registerTeamAt(t, proxyURL, domain, name, controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameUnconfirmed {
		t.Fatalf("run while reads fail: code=%q err=%v", code, err)
	}
	if setAsideKey(t, domain, name) == nil {
		t.Fatal("the key this run created was not set aside")
	}

	proxy.failTeamRead.Store(false)
	_, err = registerTeamAt(t, proxyURL, domain, name, controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameTaken {
		t.Fatalf("run once the registry answers: code=%q err=%v, want %q", code, err, codeTeamNameTaken)
	}
	if setAsideKey(t, domain, name) != nil {
		t.Fatal("the unconfirmed key was kept for a team pinned to another key")
	}
	assertNoTeamKeyFile(t, domain, name)
	path, err := awconfig.UnconfirmedTeamKeyPath(domain, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("set-aside file still present: %v", err)
	}
}

// A read that answers at once and shows another key is a taken name, and the
// key this run created is deleted; a private team pinned to another key
// refuses this run's signed read, which is not absence: the run says it could
// not confirm and keeps its key aside.
func TestTeamCreateAgainstATeamPinnedToAnotherKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	const domain = "pinned-elsewhere.example"
	controllerKey := newKey(t)
	if _, err := registerTeamAt(t, registryURL, domain, "seed", controllerKey); err != nil {
		t.Fatalf("seed the namespace: %v", err)
	}
	registry := directRegistry(t, registryURL)
	other := newKey(t)
	for _, name := range []string{"public-team", "private-team"} {
		if _, err := registry.CreateTeam(context.Background(), registryURL, domain, name, "", didOf(other), controllerKey); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := registry.SetTeamVisibility(context.Background(), registryURL, domain, "public-team", "public", other); err != nil {
		t.Fatal(err)
	}

	_, err := registerTeamAt(t, registryURL, domain, "public-team", controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameTaken {
		t.Fatalf("public team: code=%q err=%v, want %q", code, err, codeTeamNameTaken)
	}
	assertNoTeamKeyFile(t, domain, "public-team")
	if setAsideKey(t, domain, "public-team") != nil {
		t.Fatal("a confirmed taken name left a set-aside key")
	}

	_, err = registerTeamAt(t, registryURL, domain, "private-team", controllerKey)
	if code := errorCodeOf(err); code != codeTeamNameUnconfirmed {
		t.Fatalf("private team: code=%q err=%v, want %q", code, err, codeTeamNameUnconfirmed)
	}
	assertNoTeamKeyFile(t, domain, "private-team")
	if setAsideKey(t, domain, "private-team") == nil {
		t.Fatal("the key this run created for the private team was not set aside")
	}
}
