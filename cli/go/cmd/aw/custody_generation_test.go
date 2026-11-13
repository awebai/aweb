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
	"sync/atomic"
	"testing"

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
	c.bootstrapCredentials()
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
	restarted := &custodyService{residentHome: c.home, logOut: io.Discard, identity: c.identity, connectClient: c.connectClient}
	restarted.bootstrapCredentials()
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

// A request admitted on generation N after N+1 was published is served by
// N+1's snapshot; it never replaces it.
func TestCustodyNeverReplacesANewerSnapshotWithAnOlderCapture(t *testing.T) {
	c := newCaptureService(t)
	older, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	commitTeams(t, c.home, "second")
	newer := c.deps(t).client
	builds := len(c.builtOn)
	c.clientMu.Lock()
	deps := c.admitCaptureLocked(context.Background(), older, nil)
	c.clientMu.Unlock()
	if deps.client != newer || len(c.builtOn) != builds || c.deps(t).client != newer {
		t.Fatalf("an older capture replaced the snapshot (client %p, newer %p, %d builds)", deps.client, newer, len(c.builtOn))
	}
}
