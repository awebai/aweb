package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func resetCustodyClientGlobals(t *testing.T) {
	t.Helper()
	oldTeamFlag, oldServerFlag, oldLastClient := teamFlag, serverFlag, lastClient
	teamFlag, serverFlag, lastClient = "", "", nil
	t.Cleanup(func() { teamFlag, serverFlag, lastClient = oldTeamFlag, oldServerFlag, oldLastClient })
}

func custodyFixtureHome(t *testing.T) awconfig.IdentityHome {
	t.Helper()
	home := awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "resident"), Source: awconfig.IdentityHomeFlag}
	if err := os.MkdirAll(home.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

// custodyTestAwebHandler answers the API probe and the grant status readiness
// probe the way the aweb server does.
func custodyTestAwebHandler(requests *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"grant_not_found","contract":"identity-grant-status.v1"}`))
	})
}

func TestCustodyStartDoesNoNetworkIO(t *testing.T) {
	resetCustodyClientGlobals(t)
	var requests atomic.Int64
	server := httptest.NewServer(custodyTestAwebHandler(&requests))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)

	home := custodyFixtureHome(t)
	teamID, _ := custodyConstructorIdentityFixture(t, home, server.URL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("newCustodyService: %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("custody start made %d network requests, want none", got)
	}
	if svc.selectedTeam != teamID {
		t.Fatalf("custody start did not select the resident's team from configuration: %q", svc.selectedTeam)
	}
}

// A custody host started at boot, before the network is up: it starts, a
// request while the server is unreachable fails with a logged error, and once
// the server is reachable the next request succeeds, with no restart.
func TestCustodyRequestsReachServerOnceNetworkIsUp(t *testing.T) {
	resetCustodyClientGlobals(t)
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	awebURL := "http://" + addr
	t.Setenv("AWEB_URL", awebURL)

	home := custodyFixtureHome(t)
	teamID, _ := custodyConstructorIdentityFixture(t, home, awebURL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("custody must start while the server is unreachable: %v", err)
	}
	var logs bytes.Buffer
	svc.logOut = &logs

	down := svc.status(context.Background(), "running", nil)
	if down.Keys["signing_key_loaded"] != true {
		t.Fatalf("local signing key is not reported loaded: %#v", down.Keys)
	}
	if down.Client.Connected || down.Client.LastError != "client_initialization_failed" || down.Client.LastErrorAt == "" || !containsString(down.Errors, "client_initialization_failed") {
		t.Fatalf("unreachable server was not reported as the last error: client=%#v errors=%#v", down.Client, down.Errors)
	}
	if !strings.Contains(logs.String(), "client_initialization_failed") || !strings.Contains(logs.String(), addr) {
		t.Fatalf("failed request did not log its cause: %q", logs.String())
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("bring server up at %s: %v", addr, err)
	}
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(custodyTestAwebHandler(&requests))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()

	up := svc.status(context.Background(), "running", nil)
	if !up.Client.Connected || containsString(up.Errors, "client_initialization_failed") || containsString(up.Errors, "grant_status_unavailable") {
		t.Fatalf("request after the server came up did not succeed: client=%#v errors=%#v", up.Client, up.Errors)
	}
	if up.Freshness["last_checked_at"] == nil || len(up.Teams) != 1 || up.Teams[0]["team_id"] != teamID || up.Teams[0]["grant_status_endpoint_ready"] != true || up.Keys["signing_ready"] != true {
		t.Fatalf("custody is not ready after the server came up: freshness=%#v teams=%#v keys=%#v", up.Freshness, up.Teams, up.Keys)
	}
}

// A request that fails after the client exists is logged and reported too, and
// does not stop the next request from reaching the server.
func TestCustodyRequestFailureAfterConnectIsLoggedAndNotCached(t *testing.T) {
	resetCustodyClientGlobals(t)
	var requests atomic.Int64
	var failing atomic.Bool
	handler := custodyTestAwebHandler(&requests)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() && strings.Contains(r.URL.Path, "/identity-grants/") {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)

	home := custodyFixtureHome(t)
	custodyConstructorIdentityFixture(t, home, server.URL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("newCustodyService: %v", err)
	}
	var logs bytes.Buffer
	svc.logOut = &logs

	if first := svc.status(context.Background(), "running", nil); !first.Client.Connected || containsString(first.Errors, "grant_status_unavailable") {
		t.Fatalf("first status should connect and check the grant status endpoint: %#v", first)
	}
	failing.Store(true)
	failed := svc.status(context.Background(), "running", nil)
	if !containsString(failed.Errors, "grant_status_unavailable") || failed.Client.LastError != "grant_status_unavailable" || !strings.Contains(logs.String(), "grant_status_unavailable") {
		t.Fatalf("grant status failure was not logged and reported: client=%#v errors=%#v logs=%q", failed.Client, failed.Errors, logs.String())
	}
	failing.Store(false)
	recovered := svc.status(context.Background(), "running", nil)
	if containsString(recovered.Errors, "grant_status_unavailable") || recovered.Freshness["last_checked_at"] == nil {
		t.Fatalf("the next request after the failure did not reach the server: %#v", recovered)
	}
}
