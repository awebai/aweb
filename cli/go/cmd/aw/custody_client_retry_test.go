package main

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// custodyStartedBeforeServer serves custody for a resident whose aweb server
// is not listening yet, the shape of a custody host started at boot before the
// network is up. It returns the server address to bring up later.
type custodyStartedBeforeServer struct {
	svc    *custodyService
	addr   string
	teamID string
	errc   chan error
	cancel context.CancelFunc
}

func startCustodyBeforeServer(t *testing.T) *custodyStartedBeforeServer {
	t.Helper()
	oldTeamFlag, oldServerFlag, oldLastClient := teamFlag, serverFlag, lastClient
	teamFlag, serverFlag, lastClient = "", "", nil
	t.Cleanup(func() { teamFlag, serverFlag, lastClient = oldTeamFlag, oldServerFlag, oldLastClient })

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	awebURL := "http://" + addr
	t.Setenv("AWEB_URL", awebURL)

	home := awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "resident"), Source: awconfig.IdentityHomeFlag}
	if err := os.MkdirAll(home.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	teamID, _ := custodyConstructorIdentityFixture(t, home, awebURL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("newCustodyService: %v", err)
	}
	svc.clientRetryInitialDelay = 10 * time.Millisecond
	svc.clientRetryMaxDelay = 40 * time.Millisecond

	runID, err := awid.GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join("/tmp", "aw-custody-test-"+runID[:8])
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	svc.socketPath = filepath.Join(runDir, "custody.sock")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() { errc <- svc.serve(ctx) }()
	return &custodyStartedBeforeServer{svc: svc, addr: addr, teamID: teamID, errc: errc, cancel: cancel}
}

func (c *custodyStartedBeforeServer) waitFor(t *testing.T, what string, ok func(custodyStatusReport) bool) custodyStatusReport {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last custodyStatusReport
	for time.Now().Before(deadline) {
		select {
		case err := <-c.errc:
			t.Fatalf("custody service exited while waiting for %s: %v", what, err)
		default:
		}
		last = custodyStatusReport{}
		_ = custodyHTTP(context.Background(), c.svc.socketPath, http.MethodGet, "/status", nil, &last)
		if ok(last) {
			return last
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("custody never reached %s; last status: %#v", what, last)
	return last
}

func (c *custodyStartedBeforeServer) waitForRetries(t *testing.T) {
	t.Helper()
	unready := c.waitFor(t, "retrying an unreachable server", func(s custodyStatusReport) bool {
		return s.Client.Retries >= 2
	})
	if unready.Client.Ready || unready.Client.LastError != "client_initialization_failed" || !containsString(unready.Errors, "client_initialization_failed") {
		t.Fatalf("unreachable server was not reported as a failed client initialization: %#v", unready)
	}
}

// A custody host started at boot, before the network is up, must become ready
// once the server is reachable, without a restart: the process stays alive, so
// no supervisor would restart it.
func TestCustodyServeBecomesReadyWhenServerBecomesReachable(t *testing.T) {
	custody := startCustodyBeforeServer(t)
	custody.waitForRetries(t)
	addr, teamID := custody.addr, custody.teamID

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("bring server up at %s: %v", addr, err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents/heartbeat" || r.URL.Path == "/api/v1/agents/heartbeat" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"grant_not_found","contract":"identity-grant-status.v1"}`))
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()

	ready := custody.waitFor(t, "readiness after the server came up", func(s custodyStatusReport) bool {
		return s.Client.Ready
	})
	// The fixture has no encryption key, so encryption_key_unavailable stays.
	if containsString(ready.Errors, "client_initialization_failed") || containsString(ready.Errors, "grant_status_unavailable") || ready.Client.LastError != "" || ready.Client.Retries < 2 {
		t.Fatalf("ready custody still reports the start-up failure: %#v", ready)
	}
	if ready.Freshness["last_checked_at"] == nil || len(ready.Teams) != 1 || ready.Teams[0]["team_id"] != teamID || ready.Teams[0]["grant_status_endpoint_ready"] != true {
		t.Fatalf("custody became ready without the selected team's grant status: freshness=%#v teams=%#v", ready.Freshness, ready.Teams)
	}
	if ready.Keys["signing_ready"] != true {
		t.Fatalf("signing is not ready after client initialization: %#v", ready.Keys)
	}

	custody.cancel()
	if err := <-custody.errc; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

// Stopping custody while it is still retrying must not hang on the retry.
func TestCustodyServeStopsWhileRetryingClientInitialization(t *testing.T) {
	custody := startCustodyBeforeServer(t)
	custody.waitForRetries(t)
	custody.cancel()
	select {
	case err := <-custody.errc:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("custody did not stop while retrying client initialization")
	}
}

func TestCustodyClientRetryDelayDoublesUpToTheBound(t *testing.T) {
	svc := &custodyService{clientRetryInitialDelay: time.Second, clientRetryMaxDelay: 8 * time.Second}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 8 * time.Second, 8 * time.Second}
	for retry, delay := range want {
		if got := svc.clientRetryDelay(retry); got != delay {
			t.Fatalf("retry %d: delay=%v, want %v", retry, got, delay)
		}
	}
	if got := svc.clientRetryDelay(1000); got != 8*time.Second {
		t.Fatalf("a long outage overflowed the bound: %v", got)
	}
}

func TestCustodyStatusReportsReadyClientWithoutRetries(t *testing.T) {
	_, residentKey, _ := ed25519.GenerateKey(nil)
	_, sessionKey, _ := ed25519.GenerateKey(nil)
	svc := testCustodyService(t, residentKey, sessionKey)
	status := svc.status(context.Background(), "running", nil)
	if !status.Client.Ready || status.Client.LastError != "" || status.Client.Retries != 0 {
		t.Fatalf("client=%#v, want ready with no error and no retries", status.Client)
	}
}
