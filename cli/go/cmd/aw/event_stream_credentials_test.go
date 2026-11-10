package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
	awrun "github.com/awebai/aw/run"
	"github.com/awebai/aw/wake"
	"github.com/awebai/aw/wake/session"
)

// docs/event-stream-client-policy.md §4: before each retry of a refused
// stream the credentials are read again from where they are kept, so a grant
// renewed on disk is used without a restart. These tests change the grant on
// disk between two attempts.

const (
	expiredTestGrantID = "11111111-1111-4111-8111-111111111111"
	renewedTestGrantID = "22222222-2222-4222-8222-222222222222"
)

// grantStreamServer refuses the expired grant with 401 and serves the renewed
// one. It records the grant each stream request presented.
type grantStreamServer struct {
	*httptest.Server
	mu     sync.Mutex
	grants []string
}

func newGrantStreamServer(t *testing.T) *grantStreamServer {
	t.Helper()
	gs := &grantStreamServer{}
	gs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events/stream" {
			http.NotFound(w, r)
			return
		}
		grantID := r.Header.Get("X-AWEB-Grant-ID")
		gs.mu.Lock()
		gs.grants = append(gs.grants, grantID)
		gs.mu.Unlock()
		if grantID != renewedTestGrantID {
			http.Error(w, `{"detail":"grant not accepted"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: connected\ndata: {\"agent_id\":\"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\",\"team_id\":\"backend:acme.com\"}\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(gs.Close)
	return gs
}

func (gs *grantStreamServer) presented() []string {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	return append([]string(nil), gs.grants...)
}

// writeTestGrantHome writes a grant home the way a renewal does: a session
// key and the grant's state.
func writeTestGrantHome(t *testing.T, grantHome, grantID, awebURL string) {
	t.Helper()
	if err := os.MkdirAll(grantHome, 0o700); err != nil {
		t.Fatal(err)
	}
	_, sessionKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.GrantHomeSigningKeyPath(grantHome), sessionKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(grantHome), &awconfig.GrantHome{
		Version: awconfig.GrantHomeSchemaVersion,
		GrantID: grantID,
		TeamID:  "backend:acme.com",
		Subject: awconfig.GrantSubject{
			DIDAW:   "did:aw:alice",
			DIDKey:  "did:key:z6MkAliceRoot",
			Address: "acme.com/alice",
			Alias:   "alice",
		},
		Scopes:    []string{"events.read", "mail.read"},
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		AwebURL:   awebURL,
	}); err != nil {
		t.Fatal(err)
	}
}

// resolvedTempDir is a temporary directory with no symlink in its path, which
// an identity home requires and the platform's temporary directory may not be.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func isolateIdentityResolution(t *testing.T, root string) {
	t.Helper()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg"))
	t.Setenv("AWID_REGISTRY_URL", "")
	t.Setenv("AWEB_URL", "")
	t.Setenv("AWEB_IDENTITY_HOME", "")
	oldTeam, oldIdentityHomeFlag, oldActive := teamFlag, identityHomeFlag, activeIdentityHome
	teamFlag, identityHomeFlag, activeIdentityHome = "", "", awconfig.IdentityHome{}
	t.Cleanup(func() { teamFlag, identityHomeFlag, activeIdentityHome = oldTeam, oldIdentityHomeFlag, oldActive })
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// `aw run`: the client built at start holds the grant it read then. A refused
// stream's retry goes through runEventStreamReload, which reads the home again.
func TestRunEventStreamUsesAGrantRenewedOnDiskAfterARefusal(t *testing.T) {
	root := resolvedTempDir(t)
	isolateIdentityResolution(t, root)
	server := newGrantStreamServer(t)
	workingDir := filepath.Join(root, "work")
	if err := os.MkdirAll(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	grantHome := filepath.Join(root, "grant.aweb-identity")
	writeTestGrantHome(t, grantHome, expiredTestGrantID, server.URL)
	identityHomeFlag = grantHome

	client, _, err := runResolveClientForDir(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	clock := manualclock.New(time.Now())
	states := make(chan awrun.ConnectionState, 16)
	bus := awrun.NewEventBus(awrun.EventBusConfig{
		Stream:        awrun.NewEventStreamOpener(client.Client),
		Reload:        runEventStreamReload(workingDir),
		Now:           clock.Now,
		OnStateChange: func(state awrun.ConnectionState) { states <- state },
		Policy:        awrun.StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random},
	})
	ctx, cancel := context.WithCancel(context.Background())
	bus.Start(ctx)
	defer func() {
		cancel()
		bus.Stop()
	}()

	// First attempt: planned-close timer, then the wait after the refusal.
	if !clock.AwaitStarted(2, 1) {
		t.Fatal("the bus is not waiting to retry after the first refusal")
	}
	if bus.State() != awrun.ConnRefused {
		t.Fatalf("state=%s after the expired grant was refused", bus.State())
	}

	// The grant on disk is still the expired one: the retry presents it again.
	clock.Advance(time.Minute)
	if !clock.AwaitStarted(4, 1) {
		t.Fatal("the bus is not waiting to retry after the second refusal")
	}

	writeTestGrantHome(t, grantHome, renewedTestGrantID, server.URL)
	clock.Advance(2 * time.Minute)
	waitForCondition(t, "the stream to be accepted with the renewed grant", func() bool { return bus.State() == awrun.ConnStreaming })

	want := []string{expiredTestGrantID, expiredTestGrantID, renewedTestGrantID}
	if got := server.presented(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("grants presented %v, want %v", got, want)
	}
}

// The reload reads the grant from disk each time it is called; an opener
// keeps the grant it was built with.
func TestRunEventStreamReloadReadsTheGrantHomeOnEachCall(t *testing.T) {
	root := resolvedTempDir(t)
	isolateIdentityResolution(t, root)
	server := newGrantStreamServer(t)
	workingDir := filepath.Join(root, "work")
	if err := os.MkdirAll(workingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	grantHome := filepath.Join(root, "grant.aweb-identity")
	writeTestGrantHome(t, grantHome, expiredTestGrantID, server.URL)
	identityHomeFlag = grantHome

	reload := runEventStreamReload(workingDir)
	open := func(opener awrun.EventStreamOpener) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		source, err := opener(ctx, time.Now().Add(time.Minute))
		if err == nil {
			_ = source.Close()
		}
	}
	first, err := reload()
	if err != nil {
		t.Fatal(err)
	}
	open(first)
	writeTestGrantHome(t, grantHome, renewedTestGrantID, server.URL)
	open(first)
	second, err := reload()
	if err != nil {
		t.Fatal(err)
	}
	open(second)

	want := []string{expiredTestGrantID, expiredTestGrantID, renewedTestGrantID}
	if got := server.presented(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("grants presented %v, want %v", got, want)
	}

	// A home that cannot be read is an error, not a stream opened some other way.
	if err := os.Remove(awconfig.GrantHomeStatePath(grantHome)); err != nil {
		t.Fatal(err)
	}
	if opener, err := reload(); err == nil || opener != nil {
		t.Fatalf("reload with no grant on disk returned opener=%v err=%v", opener != nil, err)
	}
}

// The wake broker: OpenStream is wakeStreamOpener, which resolves the identity
// home from disk each time it is called, and the broker calls it again before
// each retry of a refused stream.
func TestWakeBrokerUsesAGrantRenewedOnDiskAfterARefusal(t *testing.T) {
	root := resolvedTempDir(t)
	isolateIdentityResolution(t, root)
	server := newGrantStreamServer(t)
	grantHome := filepath.Join(root, "grant.aweb-identity")
	writeTestGrantHome(t, grantHome, expiredTestGrantID, server.URL)
	instanceHome := filepath.Join(root, "instance")
	if err := os.MkdirAll(instanceHome, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := wake.NewStore(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	clock := manualclock.New(time.Now())
	broker, err := wake.NewBroker(wake.Config{
		Store:        store,
		Session:      session.NewFake(session.Inspection{Home: instanceHome, Backend: "herdr", Present: true, State: session.StateIdle, RawState: "idle"}),
		OpenStream:   wakeStreamOpener,
		StreamPolicy: awrun.StreamPolicyConfig{Now: clock.Now, Timer: clock.Timer, Rand: clock.Random},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := broker.Register(wake.Registration{Home: instanceHome, IdentityHome: grantHome, Delivery: wake.DeliverySession, Backend: "herdr", RegisteredAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- broker.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("broker did not stop")
		}
	}()
	stream := func() wake.StreamStatus {
		streams := broker.Status().Streams
		if len(streams) != 1 {
			t.Fatalf("streams=%+v, want one", streams)
		}
		return streams[0]
	}

	// First attempt: planned-close timer, then the wait after the refusal.
	if !clock.AwaitStarted(2, 1) {
		t.Fatal("the stream is not waiting to retry after the refusal")
	}
	refused := stream()
	if refused.Phase != string(wake.StreamRefused) || refused.Admitted || refused.Cause != "401" {
		t.Fatalf("stream %+v, want refused by 401 and not admitted", refused)
	}
	text := formatWakeStatus(broker.Status())
	wantLine := "  refused  " + grantHome + "  [refused by the server: 401; next try " + refused.NextAttemptAt.UTC().Format(time.RFC3339) + "]"
	if !strings.Contains(text, wantLine) {
		t.Fatalf("status text does not show the refusal as %q:\n%s", wantLine, text)
	}
	if strings.Contains(text, "over the stream bound") || strings.Contains(text, "stream_admitted=true") {
		t.Fatalf("status text shows a refused identity as over the bound or admitted:\n%s", text)
	}
	if !strings.Contains(text, "stream_admitted=false stream_phase=refused stream_cause=401 stream_next_try="+refused.NextAttemptAt.UTC().Format(time.RFC3339)) {
		t.Fatalf("status text does not show the receive identity as refused:\n%s", text)
	}

	writeTestGrantHome(t, grantHome, renewedTestGrantID, server.URL)
	clock.Advance(time.Minute)
	waitForCondition(t, "the stream to be accepted with the renewed grant", func() bool { return stream().Phase == string(wake.StreamLive) })
	if accepted := stream(); !accepted.Admitted || accepted.Cause != "" || !accepted.NextAttemptAt.IsZero() {
		t.Fatalf("stream %+v, want streaming and admitted", accepted)
	}
	want := []string{expiredTestGrantID, renewedTestGrantID}
	if got := server.presented(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("grants presented %v, want %v", got, want)
	}
	if text := formatWakeStatus(broker.Status()); !strings.Contains(text, "  streaming  "+grantHome) || strings.Contains(text, "refused") {
		t.Fatalf("status text after the stream was accepted:\n%s", text)
	}
}
