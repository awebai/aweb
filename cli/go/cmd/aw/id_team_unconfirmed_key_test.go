package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// teamReadFaults carries requests to a real AWID registry. With failTeamRead
// set it answers the read of one team with 503, as when the registry is
// briefly unreachable; beforeCreate runs once, before the first create of
// that team is sent. Requests keep the registry's own URL, so the controller
// signatures they carry name the registry as their audience.
type teamReadFaults struct {
	teamPath     string
	createPath   string
	failTeamRead atomic.Bool
	beforeCreate func()
	once         sync.Once
}

func (f *teamReadFaults) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && req.URL.Path == f.teamPath && f.failTeamRead.Load() {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Status:     "503 Service Unavailable",
			Header:     http.Header{"Content-Type": []string{"text/plain"}},
			Body:       io.NopCloser(strings.NewReader("registry unavailable")),
			Request:    req,
		}, nil
	}
	if req.Method == http.MethodPost && req.URL.Path == f.createPath && f.beforeCreate != nil {
		f.once.Do(f.beforeCreate)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func newTeamReadFaults(domain, name string) *teamReadFaults {
	return &teamReadFaults{
		teamPath:   "/v1/namespaces/" + domain + "/teams/" + name,
		createPath: "/v1/namespaces/" + domain + "/teams",
	}
}

// registerTeamAt runs the team registration aw id team create runs, at
// registryURL over transport, as the namespace controller controllerKey.
func registerTeamAt(t *testing.T, registryURL string, transport http.RoundTripper, domain, name string, controllerKey ed25519.PrivateKey) (*localTeamRegistration, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return ensureLocalTeamRegistered(ctx, trustedClient(t, registryURL, transport), registryURL, domain, name, "", controllerKey)
}

// directRegistry reaches the real registry without faults.
func directRegistry(t *testing.T, registryURL string) *awid.RegistryClient {
	t.Helper()
	return trustedClient(t, registryURL, http.DefaultTransport)
}

func assertNoTeamKeyFile(t *testing.T, domain, name string) {
	t.Helper()
	path, err := awconfig.TeamKeyPath(domain, name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no active team key file at %s: %v", path, err)
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
	faults := newTeamReadFaults(domain, name)
	controllerKey := newKey(t)
	var registered string
	faults.beforeCreate = func() {
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
		faults.failTeamRead.Store(true)
	}

	_, err := registerTeamAt(t, registryURL, faults, domain, name, controllerKey)
	if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameUnconfirmed {
		t.Fatalf("first run: classification=%q err=%v, want %q", code, err, codeTeamNameUnconfirmed)
	}
	aside := setAsideKey(t, domain, name)
	if aside == nil || didOf(aside) != registered {
		t.Fatal("the registered key was not set aside")
	}
	assertNoTeamKeyFile(t, domain, name)
	if exists, err := awconfig.TeamKeyExists(domain, name); exists || !errors.Is(err, awconfig.ErrTeamKeyUnconfirmed) {
		t.Fatalf("TeamKeyExists = %v, %v; want false, ErrTeamKeyUnconfirmed", exists, err)
	}
	if _, err := awconfig.LoadTeamKey(domain, name); !errors.Is(err, awconfig.ErrTeamKeyUnconfirmed) {
		t.Fatalf("LoadTeamKey err=%v, want ErrTeamKeyUnconfirmed", err)
	}
	if code := errorCodeOf(func() error { _, err := awconfig.LoadTeamKey(domain, name); return err }()); code != codeTeamNameUnconfirmed {
		t.Fatalf("a command reading the team key gets code %q, want %q", code, codeTeamNameUnconfirmed)
	}

	// While reads fail, the set-aside key is left alone and no new key is made.
	_, err = registerTeamAt(t, registryURL, faults, domain, name, controllerKey)
	if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameUnconfirmed {
		t.Fatalf("run while reads fail: classification=%q err=%v", code, err)
	}
	if again := setAsideKey(t, domain, name); again == nil || !again.Equal(aside) {
		t.Fatal("the set-aside key changed while reads failed")
	}
	assertNoTeamKeyFile(t, domain, name)

	faults.failTeamRead.Store(false)
	result, err := registerTeamAt(t, registryURL, faults, domain, name, controllerKey)
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
// the registry pins another key, and the name is refused as taken. A public
// team shows its key; a private team refuses the read signed with the
// set-aside key, which it does only for a key that is not the team's.
func TestTeamCreateRemovesAnUnconfirmedKeyTheRegistryShowsIsNotTheTeams(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	const domain = "unconfirmed-elsewhere.example"
	controllerKey := newKey(t)
	if _, err := registerTeamAt(t, registryURL, http.DefaultTransport, domain, "seed", controllerKey); err != nil {
		t.Fatalf("seed the namespace: %v", err)
	}
	registry := directRegistry(t, registryURL)
	for _, visibility := range []string{"public", "private"} {
		t.Run(visibility, func(t *testing.T) {
			name := visibility + "-ops"
			faults := newTeamReadFaults(domain, name)
			other := newKey(t)
			if _, err := registry.CreateTeam(context.Background(), registryURL, domain, name, "", didOf(other), controllerKey); err != nil {
				t.Fatal(err)
			}
			if visibility == "public" {
				if _, err := registry.SetTeamVisibility(context.Background(), registryURL, domain, name, "public", other); err != nil {
					t.Fatal(err)
				}
			}

			faults.failTeamRead.Store(true)
			_, err := registerTeamAt(t, registryURL, faults, domain, name, controllerKey)
			if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameUnconfirmed {
				t.Fatalf("run while reads fail: classification=%q err=%v", code, err)
			}
			if setAsideKey(t, domain, name) == nil {
				t.Fatal("the key this run created was not set aside")
			}

			faults.failTeamRead.Store(false)
			_, err = registerTeamAt(t, registryURL, faults, domain, name, controllerKey)
			if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameTaken {
				t.Fatalf("run once the registry answers: classification=%q err=%v, want %q", code, err, codeTeamNameTaken)
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
		})
	}
}

// A team pinned to another key is a taken name, and the key this run created
// is deleted. A public team shows its key; a private team refuses the read
// this run signs with its own key, which it does only for a key that is
// neither the team's nor a member's, so that refusal shows the same.
func TestTeamCreateAgainstATeamPinnedToAnotherKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	const domain = "pinned-elsewhere.example"
	controllerKey := newKey(t)
	if _, err := registerTeamAt(t, registryURL, http.DefaultTransport, domain, "seed", controllerKey); err != nil {
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

	_, err := registerTeamAt(t, registryURL, http.DefaultTransport, domain, "public-team", controllerKey)
	if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameTaken {
		t.Fatalf("public team: classification=%q err=%v, want %q", code, err, codeTeamNameTaken)
	}
	assertNoTeamKeyFile(t, domain, "public-team")
	if setAsideKey(t, domain, "public-team") != nil {
		t.Fatal("a confirmed taken name left a set-aside key")
	}

	_, err = registerTeamAt(t, registryURL, http.DefaultTransport, domain, "private-team", controllerKey)
	if code := errorEnvelope(err, "").Error.Classification; code != codeTeamNameTaken {
		t.Fatalf("private team: classification=%q err=%v, want %q", code, err, codeTeamNameTaken)
	}
	assertNoTeamKeyFile(t, domain, "private-team")
	if setAsideKey(t, domain, "private-team") != nil {
		t.Fatal("a private team pinned to another key left a set-aside key")
	}
}
