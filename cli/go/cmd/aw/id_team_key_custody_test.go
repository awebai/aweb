package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// teamCreateRegistry is an AWID registry that holds one team. failFirstCreate
// makes it record the first create and then answer 500, as when the response
// is lost or the CLI dies after the registry accepted the team.
type teamCreateRegistry struct {
	t               *testing.T
	failFirstCreate bool
	onCreate        func(teamDIDKey string)

	mu       sync.Mutex
	creates  int
	teamDID  string
	existing bool
}

func (r *teamCreateRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var payload map[string]any
	if req.Method == http.MethodPost && req.URL.Path == "/v1/namespaces/acme.com/teams" {
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			r.t.Error(err)
			return
		}
		// The hook runs outside the lock so it can drive another run against
		// this registry while this create is in flight.
		if r.onCreate != nil {
			teamDID, _ := payload["team_did_key"].(string)
			r.onCreate(teamDID)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v1/namespaces/acme.com":
		http.NotFound(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/v1/namespaces":
		var payload map[string]any
		_ = json.NewDecoder(req.Body).Decode(&payload)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"domain": "acme.com", "controller_did": payload["controller_did"], "created_at": "2026-04-07T00:00:00Z",
		})
	case req.Method == http.MethodPost && req.URL.Path == "/v1/namespaces/acme.com/teams":
		r.creates++
		teamDID, _ := payload["team_did_key"].(string)
		if r.existing {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Team already exists"})
			return
		}
		r.existing, r.teamDID = true, teamDID
		if r.failFirstCreate && r.creates == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": "default:acme.com", "domain": "acme.com", "name": "default",
			"team_did_key": teamDID, "created_at": "2026-04-07T00:00:00Z",
		})
	case req.Method == http.MethodGet && req.URL.Path == "/v1/namespaces/acme.com/teams/default":
		if !r.existing {
			http.NotFound(w, req)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": "default:acme.com", "domain": "acme.com", "name": "default",
			"team_did_key": r.teamDID, "created_at": "2026-04-07T00:00:00Z",
		})
	default:
		r.t.Errorf("unexpected %s %s", req.Method, req.URL.Path)
	}
}

func registerDefaultTeam(t *testing.T, registryURL string) (*localTeamRegistration, error) {
	t.Helper()
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return ensureLocalTeamRegistered(ctx, registry, "", "acme.com", "default", "", controllerKey)
}

// The registry pins a team to its key. The key must already be in local
// custody when the registry is asked to pin it, or a crash in between leaves
// a team that no one can rotate or certify.
func TestTeamKeyIsSavedBeforeTheRegistryPinsIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var savedAtCreate string
	registry := &teamCreateRegistry{t: t, onCreate: func(string) {
		key, err := awconfig.LoadTeamKey("acme.com", "default")
		if err == nil {
			savedAtCreate = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		}
	}}
	server := newLocalHTTPServer(t, registry)

	result, err := registerDefaultTeam(t, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if savedAtCreate == "" {
		t.Fatal("the team key was not saved when the registry pinned it")
	}
	if savedAtCreate != result.TeamDIDKey || registry.teamDID != result.TeamDIDKey {
		t.Fatalf("saved=%s registered=%s result=%s", savedAtCreate, registry.teamDID, result.TeamDIDKey)
	}
}

// After the registry accepted a team but the CLI never saw the answer, the
// next run completes with the key the registry holds.
func TestTeamCreateInterruptedAfterTheRegistryAcceptedItCompletesOnRetry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	registry := &teamCreateRegistry{t: t, failFirstCreate: true}
	server := newLocalHTTPServer(t, registry)

	if _, err := registerDefaultTeam(t, server.URL); err == nil {
		t.Fatal("the interrupted create reported success")
	}
	result, err := registerDefaultTeam(t, server.URL)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if result.TeamDIDKey != registry.teamDID {
		t.Fatalf("retry key=%s, registry holds %s", result.TeamDIDKey, registry.teamDID)
	}
	saved, err := awconfig.LoadTeamKey("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	if awid.ComputeDIDKey(saved.Public().(ed25519.PublicKey)) != registry.teamDID {
		t.Fatal("the saved key is not the key the registry holds")
	}
}

// A team the registry already pins to another key is refused, and the run
// does not take that team's name for a key it does not hold.
func TestTeamCreateRefusesATeamPinnedToAnotherKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	registry := &teamCreateRegistry{t: t, existing: true, teamDID: awid.ComputeDIDKey(otherPub)}
	server := newLocalHTTPServer(t, registry)

	_, err = registerDefaultTeam(t, server.URL)
	if err == nil || !strings.Contains(err.Error(), "already pinned to "+registry.teamDID) {
		t.Fatalf("err=%v", err)
	}
	if reason := errorEnvelope(err, err.Error()).Error.Classification; reason != codeTeamNameTaken {
		t.Fatalf("classification=%q, want %q", reason, codeTeamNameTaken)
	}
	exists, err := awconfig.TeamKeyExists("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("a key file was left for a team pinned to another key")
	}
}

// A run that starts while another run is registering the team it saved a key
// for uses that saved key, and both runs register the one key on disk.
func TestTeamCreateDuringAnotherRegistrationUsesTheSavedKey(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	var started atomic.Bool
	var second *localTeamRegistration
	var secondErr error
	registry := &teamCreateRegistry{t: t}
	server := newLocalHTTPServer(t, registry)
	registry.onCreate = func(string) {
		// The first run has saved its key and is registering it. The second
		// run's own create comes through here too and must not start a third.
		if started.CompareAndSwap(false, true) {
			second, secondErr = registerDefaultTeam(t, server.URL)
		}
	}

	first, err := registerDefaultTeam(t, server.URL)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if secondErr != nil {
		t.Fatalf("second run: %v", secondErr)
	}
	saved, err := awconfig.LoadTeamKey("acme.com", "default")
	if err != nil {
		t.Fatal(err)
	}
	savedDID := awid.ComputeDIDKey(saved.Public().(ed25519.PublicKey))
	if savedDID != first.TeamDIDKey || second.TeamDIDKey != first.TeamDIDKey || registry.teamDID != first.TeamDIDKey {
		t.Fatalf("saved=%s first=%s second=%s registry=%s", savedDID, first.TeamDIDKey, second.TeamDIDKey, registry.teamDID)
	}
}

func TestOATSReleasedTeamRefusalEnvelopes(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	t.Setenv("HOME", dir)
	const domain, name = "acme.com", "default"
	if err := awconfig.SaveControllerKey(domain, newKey(t)); err != nil {
		t.Fatal(err)
	}
	foreignDID := didOf(newKey(t))
	registry := &teamCreateRegistry{t: t, existing: true, teamDID: foreignDID}

	for _, tc := range []struct {
		name, command, code, message, classification string
		status                                       int
	}{
		{"missing server", "show-server", "error", "no team server record is published for default:acme.com", "team_server_record_missing", 0},
		{"foreign pin", "create", "error", "team acme.com/default is already pinned to " + foreignDID, "team_name_taken", 0},
		{"private pin", "create", "http_error", "create team at registry: registry http 409: Team already exists", "team_name_taken", 409},
		{"unconfirmed pin", "create", "http_error", "create team at registry: registry http 409: Team already exists", "team_name_unconfirmed", 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case tc.command == "show-server":
					if req.Method != http.MethodGet || req.URL.Path != "/v1/namespaces/acme.com/teams/default/server" {
						t.Errorf("unexpected service record request: %s %s", req.Method, req.URL.Path)
					}
					http.NotFound(w, req)
				case tc.status == 409 && req.Method == http.MethodGet && req.URL.Path == "/v1/namespaces/acme.com/teams/default":
					if tc.classification == "team_name_unconfirmed" {
						http.Error(w, "registry temporarily unavailable", http.StatusServiceUnavailable)
					} else {
						http.Error(w, awid.RegistryCodeTeamPrivate, http.StatusForbidden)
					}
				default:
					registry.ServeHTTP(w, req)
				}
			}))
			nameFlag := "--name"
			if tc.command == "show-server" {
				nameFlag = "--team"
			}
			cmd := exec.Command(bin, "id", "team", tc.command, "--namespace", domain, nameFlag, name, "--registry", server.URL, "--json")
			cmd.Dir = dir
			cmd.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1", "AWID_SKIP_DNS_VERIFY=1")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			var envelope struct {
				Error struct {
					Code, Message, Classification string
					HTTPStatus                    int `json:"http_status"`
				}
			}
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || json.Unmarshal(out, &envelope) != nil {
				t.Fatalf("expected a JSON refusal and exit 1: %v\nstdout: %s\nstderr: %s", err, out, &stderr)
			}
			if envelope.Error.Code != tc.code || envelope.Error.Message != tc.message || envelope.Error.HTTPStatus != tc.status || envelope.Error.Classification != tc.classification {
				t.Fatalf("unexpected refusal: %s", out)
			}
			if strings.TrimSpace(stderr.String()) != tc.message {
				t.Fatalf("stderr lost the released first line: %s", &stderr)
			}
			assertNoTeamKeyFile(t, domain, name)
			if hasKey := setAsideKey(t, domain, name) != nil; hasKey != (tc.classification == "team_name_unconfirmed") {
				t.Fatalf("unconfirmed key retained=%t", hasKey)
			}
		})
	}
}
