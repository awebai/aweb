package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// captureService is a custody service over a resident home whose client
// builds are recorded: each build reads teams.yaml from the capture it is
// given and gets a client for the next of its servers, which count requests.
type captureService struct {
	*custodyService
	home     string
	key      ed25519.PrivateKey
	builtOn  []string
	servers  []*httptest.Server
	requests []*atomic.Int64
	during   func()
}

var teamsOp = awconfig.CredentialOperation{Command: "test-writer", Intent: "teams"}

func newCaptureService(t *testing.T) *captureService {
	t.Helper()
	c := newUnstartedCaptureService(t)
	if err := c.bootstrapCredentials(); err != nil {
		t.Fatal(err)
	}
	return c
}

// newUnstartedCaptureService is a capture service over its own resident home
// that has not started.
func newUnstartedCaptureService(t *testing.T) *captureService {
	t.Helper()
	home := t.TempDir()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, "identity.yaml"), &awconfig.WorktreeIdentity{DID: did, Custody: awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal}); err != nil {
		t.Fatal(err)
	}
	writeTeams(t, home, "first")
	c := &captureService{home: home, key: key}
	for range 4 {
		var count atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			count.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(server.Close)
		c.servers, c.requests = append(c.servers, server), append(c.requests, &count)
	}
	c.custodyService = &custodyService{residentHome: home, logOut: io.Discard, identity: &awconfig.ResolvedIdentity{DID: did}}
	c.connectClient = func(_ context.Context, captured awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error) {
		teams, _ := os.ReadFile(filepath.Join(captured.Root, "teams.yaml"))
		c.builtOn = append(c.builtOn, string(teams))
		if c.during != nil {
			during := c.during
			c.during = nil
			during()
		}
		client, err := aweb.New(c.servers[len(c.builtOn)-1].URL)
		return &awconfig.Selection{TeamID: "engineering:example.com"}, client, err
	}
	t.Cleanup(func() {
		if c.readerLock != nil {
			_ = c.readerLock.Close()
		}
	})
	return c
}

// writeTeams writes a teams.yaml whose active team is named by alias.
func writeTeams(t *testing.T, home, alias string) {
	t.Helper()
	content := "active_team: engineering:example.com\nmemberships:\n  - team_id: engineering:example.com\n    alias: " + alias + "\n    cert_path: team-certs/engineering__example.com.pem\n"
	if err := os.WriteFile(filepath.Join(home, "teams.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// commitTeams changes teams.yaml as one supported update.
func commitTeams(t *testing.T, home, alias string) {
	t.Helper()
	op := awconfig.CredentialOperation{Command: "test-writer", Intent: alias}
	if err := awconfig.UpdateCredentials(home, op, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, home, alias)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (c *captureService) deps(t *testing.T) custodyClientDeps {
	t.Helper()
	return c.clientDeps(context.Background())
}

func TestCustodyKeepsItsSnapshotWhileTheCredentialsAreUnchanged(t *testing.T) {
	c := newCaptureService(t)
	first := c.deps(t).client
	if second := c.deps(t).client; first == nil || second != first || len(c.builtOn) != 1 {
		t.Fatalf("client %p then %p after %d builds", first, second, len(c.builtOn))
	}
}

// A published update is picked up by the next request; a request admitted
// before it keeps its own snapshot, closures included, to its end.
func TestCustodyServesTheNextRequestFromAPublishedUpdateAndKeepsAdmittedRequestsOnTheirs(t *testing.T) {
	c := newCaptureService(t)
	admitted := c.admit(context.Background())
	old := c.clientDeps(admitted)
	commitTeams(t, c.home, "second")
	next := c.deps(t)
	if next.client == nil || next.client == old.client || len(c.builtOn) != 2 {
		t.Fatalf("client after update %p (admitted %p) after %d builds", next.client, old.client, len(c.builtOn))
	}
	if c.clientDeps(admitted).client != old.client {
		t.Fatal("the admitted request's snapshot changed")
	}
	_, _ = old.readStoredMailReply(context.Background(), "message-1")
	_, _ = next.readStoredMailReply(context.Background(), "message-2")
	if c.requests[0].Load() != 1 || c.requests[1].Load() != 1 {
		t.Fatalf("old closure reached %d old and the new one %d new requests, want 1 and 1", c.requests[0].Load(), c.requests[1].Load())
	}
}

// A client is built from the capture admission read, never from the home as
// it is later; a change made meanwhile without publishing fails the next
// request closed. No capture is kept.
func TestCustodyBuildsFromItsCaptureAndRefusesAnUnpublishedChange(t *testing.T) {
	c := newCaptureService(t)
	commitTeams(t, c.home, "second")
	c.during = func() { writeTeams(t, c.home, "written by an older aw") }
	if deps := c.deps(t); deps.client == nil {
		t.Fatalf("no client: %s", c.lastError)
	}
	if built := c.builtOn[len(c.builtOn)-1]; !strings.Contains(built, "second") {
		t.Fatalf("built from %q, not the captured home", built)
	}
	if deps := c.deps(t); deps.client != nil || c.lastError != "credential_update_unpublished" {
		t.Fatalf("client %p, last error %q", deps.client, c.lastError)
	}
	if entries, _ := os.ReadDir(filepath.Join(c.home, custodyCaptureDir)); len(entries) != 0 {
		t.Fatalf("captures kept: %v", entries)
	}
}

func TestCustodyFailsClosedOnAnInterruptedUpdateUntilTheSameOperationCompletes(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no client before the update")
	}
	interrupted := errors.New("interrupted")
	_ = awconfig.UpdateCredentials(c.home, teamsOp, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, c.home, "half")
		return interrupted
	})
	deps := c.deps(t)
	if deps.client != nil || deps.grantStatus != nil || deps.resolveRecipient != nil || c.lastError != "credential_update_incomplete" {
		t.Fatalf("client %p, last error %q", deps.client, c.lastError)
	}
	if err := awconfig.UpdateCredentials(c.home, teamsOp, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, c.home, "whole")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client == nil {
		t.Fatalf("the completed update did not restore the client: %s", c.lastError)
	}
}

// A change without a published generation fails closed until a restart
// validates and adopts the home.
func TestCustodyRecoversAnUnpublishedChangeOnlyByARestart(t *testing.T) {
	c := newCaptureService(t)
	writeTeams(t, c.home, "written by an older aw")
	if deps := c.deps(t); deps.client != nil || c.lastError != "credential_update_unpublished" {
		t.Fatalf("client %p, last error %q", deps.client, c.lastError)
	}
	_ = c.readerLock.Close() // the first service stops
	restarted := &custodyService{residentHome: c.home, logOut: io.Discard, identity: c.identity, connectClient: c.connectClient}
	if err := restarted.bootstrapCredentials(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.readerLock.Close() })
	if deps := restarted.clientDeps(context.Background()); deps.client == nil {
		t.Fatalf("the restart did not adopt the home: %s", restarted.lastError)
	}
}

// Another signing key in the resident home latches identity_changed before
// anything else is checked, and restoring the key does not clear it.
func TestCustodyLatchesAChangedKeyUntilRestart(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no client before the change")
	}
	_, other, _ := awid.GenerateKeypair()
	if err := os.Remove(filepath.Join(c.home, "signing.key")); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(c.home, "signing.key"), other); err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client != nil || c.lastError != "identity_changed" {
		t.Fatalf("client %p, last error %q", deps.client, c.lastError)
	}
	_ = os.Remove(filepath.Join(c.home, "signing.key"))
	if err := awid.SaveSigningKey(filepath.Join(c.home, "signing.key"), c.key); err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client != nil || c.lastError != "identity_changed" {
		t.Fatalf("after restoring the key: client %p, last error %q", deps.client, c.lastError)
	}
}

// A request whose capture of generation N is admitted after N+1 was
// published is refused, and never replaces N+1's snapshot.
func TestCustodyNeverReplacesANewerSnapshotWithAnOlderCapture(t *testing.T) {
	c := newCaptureService(t)
	older, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	commitTeams(t, c.home, "second")
	newer := c.deps(t).client
	builds := len(c.builtOn)
	deps := c.admitCapture(context.Background(), older, nil)
	if deps.client != nil || len(c.builtOn) != builds || c.deps(t).client != newer {
		t.Fatalf("an older capture replaced the snapshot (client %p, newer %p, %d builds)", deps.client, newer, len(c.builtOn))
	}
}

// The real path: a custody service over a resident home whose certificate a
// supported update replaces sends the new certificate on its next requests,
// and a revoked grant stays refused across the reload.
func TestCustodyServesTheReplacedCertificateAndKeepsTheGrantRefused(t *testing.T) {
	resetCustodyClientGlobals(t)
	var mu sync.Mutex
	var sent []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header := r.Header.Get("X-AWID-Team-Certificate"); header != "" {
			if cert, err := awid.DecodeTeamCertificateHeader(header); err == nil {
				mu.Lock()
				sent = append(sent, cert.CertificateID)
				mu.Unlock()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/identity-grants/grant-1/status") {
			_, _ = w.Write([]byte(`{"grant_id":"grant-1","status":"revoked","effective_status":"revoked","expires_at":"2026-12-01T00:00:00Z","last_checked_at":"2026-11-13T00:00:00Z"}`))
			return
		}
		if strings.Contains(r.URL.Path, "heartbeat") {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"grant_not_found","contract":"identity-grant-status.v1"}`))
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	// Installing the replacement certificate publishes the identity's
	// encryption key; the test server stands in for the registry so the
	// publish never reaches DNS or the public registry.
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	home := custodyFixtureHome(t)
	teamID, didKey := custodyConstructorIdentityFixture(t, home, server.URL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatal(err)
	}
	first, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home.Root, teamID)
	if err != nil {
		t.Fatal(err)
	}
	lastSent := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(sent) == 0 {
			return ""
		}
		return sent[len(sent)-1]
	}
	grant := func() custodyGrantStatus {
		t.Helper()
		deps := svc.clientDeps(context.Background())
		if deps.grantStatus == nil {
			t.Fatalf("no client: %s", svc.lastError)
		}
		status, err := deps.grantStatus(context.Background(), "grant-1")
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := grant(); status.Active || lastSent() != first.CertificateID {
		t.Fatalf("before the update: grant %+v sent with %q, want %q", status, lastSent(), first.CertificateID)
	}
	_, teamKey, _ := awid.GenerateKeypair()
	replacement, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, MemberDIDAW: svc.identity.StableID,
		MemberAddress: first.MemberAddress, Alias: "alice", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commitTeamCertificate(t.TempDir(), home.Root, "fetch-cert", replacement, "", func() (string, error) { return "installed", nil }); err != nil {
		t.Fatal(err)
	}
	if status := grant(); status.Active || lastSent() != replacement.CertificateID {
		t.Fatalf("after the update: grant %+v sent with %q, want %q", status, lastSent(), replacement.CertificateID)
	}
}

// A service starting while a supported writer updates its resident home with
// no reader waits for the update, and serves only what it completed.
func TestCustodyStartingDuringAnUpdateWaitsForItToComplete(t *testing.T) {
	c := newUnstartedCaptureService(t)
	started := make(chan error, 1)
	op := awconfig.CredentialOperation{Command: "test-writer", Intent: "complete"}
	if err := awconfig.UpdateCredentials(c.home, op, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, c.home, "half")
		go func() { started <- c.bootstrapCredentials() }()
		select {
		case err := <-started:
			t.Fatalf("the service started on a half-written home: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
		writeTeams(t, c.home, "complete")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client == nil || !strings.Contains(c.builtOn[len(c.builtOn)-1], "complete") {
		t.Fatalf("client %p built on %v (%s)", deps.client, c.builtOn, c.lastError)
	}
}

// A service starting while an update that then crashes is writing never
// adopts the half-written home; it fails closed.
func TestCustodyStartingDuringAnUpdateThatCrashesFailsClosed(t *testing.T) {
	c := newUnstartedCaptureService(t)
	started := make(chan error, 1)
	op := awconfig.CredentialOperation{Command: "test-writer", Intent: "crashes"}
	_ = awconfig.UpdateCredentials(c.home, op, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, c.home, "half")
		go func() { started <- c.bootstrapCredentials() }()
		time.Sleep(100 * time.Millisecond)
		return errors.New("crashed")
	})
	if err := <-started; err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client != nil || c.lastError != "credential_update_incomplete" || len(c.builtOn) != 0 {
		t.Fatalf("client %p after %d builds, last error %q", deps.client, len(c.builtOn), c.lastError)
	}
	// The same operation completes it while the service serves; the next
	// request is served from it.
	if err := awconfig.UpdateCredentials(c.home, op, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		writeTeams(t, c.home, "recovered")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if deps := c.deps(t); deps.client == nil || !strings.Contains(c.builtOn[len(c.builtOn)-1], "recovered") {
		t.Fatalf("client %p built on %v (%s)", deps.client, c.builtOn, c.lastError)
	}
}

// An older capture is never built and served once a newer generation was
// published, even after the snapshot was dropped.
func TestCustodyNeverBuildsAnOlderCaptureAfterTheSnapshotWasDropped(t *testing.T) {
	c := newCaptureService(t)
	older, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	commitTeams(t, c.home, "second")
	if c.deps(t).client == nil {
		t.Fatal("generation 2 not served")
	}
	writeTeams(t, c.home, "written by an older aw")
	if c.deps(t).client != nil {
		t.Fatal("an unpublished change was served")
	}
	builds := len(c.builtOn)
	deps := c.admitCapture(context.Background(), older, nil)
	if deps.client != nil || len(c.builtOn) != builds {
		t.Fatalf("an older capture was built and served after a newer generation: client %p, %d builds", deps.client, len(c.builtOn)-builds)
	}
}

// A published generation that fails to build leaves no client: the service
// never serves a snapshot it has seen superseded.
func TestCustodyServesNoSupersededSnapshotWhenTheNewOneFailsToBuild(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no client before the update")
	}
	connect := c.connectClient
	c.connectClient = func(context.Context, awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error) {
		return nil, nil, errors.New("aweb unreachable")
	}
	commitTeams(t, c.home, "second")
	if deps := c.deps(t); deps.client != nil {
		t.Fatal("the superseded snapshot was served")
	}
	c.connectClient = connect
	if deps := c.deps(t); deps.client == nil {
		t.Fatalf("the next request did not build the new generation: %s", c.lastError)
	}
}

// A home whose update lock stays held is reported busy, not incomplete.
func TestCustodyReportsABusyHomeAsBusy(t *testing.T) {
	c := newCaptureService(t)
	op := awconfig.CredentialOperation{Command: "test-writer", Intent: "slow"}
	_ = awconfig.UpdateCredentials(c.home, op, func(func() error) error {
		if deps := c.deps(t); deps.client != nil || c.lastError != "credential_update_busy" {
			t.Errorf("client %p, last error %q", deps.client, c.lastError)
		}
		return nil
	})
}

// A build runs outside the service's lock; a refusal another request makes
// while it runs is never published over when it finishes.
func TestCustodyNeverPublishesABuildOverARefusalMadeWhileItRan(t *testing.T) {
	c := newCaptureService(t)
	commitTeams(t, c.home, "second")
	var during custodyClientDeps
	c.during = func() {
		writeTeams(t, c.home, "written by an older aw")
		during = c.deps(t)
	}
	built := c.deps(t)
	if during.client != nil || c.lastError != "credential_update_unpublished" {
		t.Fatalf("the request during the build was served: client %p, last error %q", during.client, c.lastError)
	}
	c.clientMu.Lock()
	published := c.client
	c.clientMu.Unlock()
	if built.client != nil || published != nil {
		t.Fatalf("the build published over the refusal: returned %p, published %p", built.client, published)
	}
}

// A capture root that is a symlink is refused before anything follows it:
// neither key bytes nor a mode change reach the directory it names.
func TestCustodyNeverFollowsACaptureRootSymlink(t *testing.T) {
	c := newCaptureService(t)
	outside := t.TempDir()
	if err := os.Chmod(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(c.home, custodyCaptureDir)
	_ = os.RemoveAll(root)
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	capture, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.writeCapture(capture.CredentialCapture); err == nil {
		t.Fatal("a capture was written through a symlinked root")
	}
	info, err := os.Stat(outside)
	entries, _ := os.ReadDir(outside)
	if err != nil || info.Mode().Perm() != 0o755 || len(entries) != 0 {
		t.Fatalf("the symlinked root's target was changed: %v %v %v", info.Mode().Perm(), entries, err)
	}
}

// A capture read before the home was observed unpublished, but admitted
// after that refusal, admits no client: refusals are ordered by when the
// capture read the home, not by when it was decided.
func TestCustodyAdmitsNoCaptureReadBeforeARefusal(t *testing.T) {
	c := newCaptureService(t)
	commitTeams(t, c.home, "second")
	if c.deps(t).client == nil {
		t.Fatal("generation 2 is not served")
	}
	earlier, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	writeTeams(t, c.home, "written by an older aw")
	if c.deps(t).client != nil {
		t.Fatal("an unpublished home was served")
	}
	builds := len(c.builtOn)
	if deps := c.admitCapture(context.Background(), earlier, nil); deps.client != nil || len(c.builtOn) != builds {
		t.Fatalf("a capture read before the unpublished refusal admitted a client (%d builds)", len(c.builtOn)-builds)
	}
}

// Refusals decided out of capture order keep the newest one: a capture read
// between two refusals admits no client after both are decided.
func TestCustodyKeepsTheNewestRefusalWhenRefusalsAreDecidedOutOfOrder(t *testing.T) {
	c := newCaptureService(t)
	commitTeams(t, c.home, "second")
	writeTeams(t, c.home, "changed by hand")
	first, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	writeTeams(t, c.home, "second")
	between, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if !between.State.Published() {
		t.Fatal("restoring the published bytes did not publish the home again")
	}
	writeTeams(t, c.home, "changed by hand")
	if c.deps(t).client != nil {
		t.Fatal("an unpublished home was served")
	}
	_ = c.admitCapture(context.Background(), first, nil)
	builds := len(c.builtOn)
	if deps := c.admitCapture(context.Background(), between, nil); deps.client != nil || len(c.builtOn) != builds {
		t.Fatalf("a capture read before the newest refusal admitted a client (%d builds)", len(c.builtOn)-builds)
	}
}
