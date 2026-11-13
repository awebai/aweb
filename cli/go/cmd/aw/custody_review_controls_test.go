package main

// Controls security-fixes wrote reviewing acxy.18 at ee9143a72, kept as
// tests and adapted to the admission entry points that replaced them.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestSecurityReviewRebuildFailureRefusesNewRequest(t *testing.T) {
	c := newCaptureService(t)
	admitted := c.admit(context.Background())
	old := c.clientDeps(admitted).client
	if old == nil {
		t.Fatal("no original client")
	}
	commitTeams(t, c.home, "second")
	c.connectClient = func(context.Context, awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error) {
		return nil, nil, errors.New("the new generation cannot build")
	}
	got := c.deps(t)
	if c.clientDeps(admitted).client != old {
		t.Fatal("the already admitted request lost its old snapshot")
	}
	if got.client != nil || got.grantStatus != nil || got.resolveRecipient != nil {
		t.Fatalf("new request fell back to previous client %p (old=%p), last error=%q", got.client, old, c.lastError)
	}
}

func TestSecurityReviewOldFailureDoesNotDetachNewerSnapshot(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no original client")
	}
	writeTeams(t, c.home, "unpublished")
	older, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	writeTeams(t, c.home, "first")
	commitTeams(t, c.home, "newer")
	newest := c.deps(t).client
	if newest == nil {
		t.Fatal("no newer client")
	}
	generation := c.snapshotGeneration
	rejected := c.admitCapture(context.Background(), older, nil)
	c.clientMu.Lock()
	current := c.client
	currentGeneration := c.snapshotGeneration
	c.clientMu.Unlock()
	if rejected.client != nil {
		t.Fatal("the unpublished old request should refuse")
	}
	if current != newest || currentGeneration != generation {
		t.Fatalf("old failure detached newer snapshot: current=%p newest=%p, generation=%d want=%d", current, newest, currentGeneration, generation)
	}
}

func TestSecurityReviewAppSigningUsesAdmittedCertificate(t *testing.T) {
	resetCustodyClientGlobals(t)
	var observed string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if encoded := r.Header.Get("X-AWID-Team-Certificate"); encoded != "" {
			cert, err := awid.DecodeTeamCertificateHeader(encoded)
			if err == nil {
				observed = cert.CertificateID
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "heartbeat") {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"grant_not_found","contract":"identity-grant-status.v1"}`))
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	home := custodyFixtureHome(t)
	team, key := custodyConstructorIdentityFixture(t, home, server.URL, true)
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if svc.readerLock != nil {
			_ = svc.readerLock.Close()
		}
	})
	admitted := svc.admit(context.Background())
	old := svc.clientDeps(admitted)
	if old.client == nil {
		t.Fatalf("no original client: %s", svc.lastError)
	}
	first, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home.Root, team)
	if err != nil {
		t.Fatal(err)
	}
	_, controller, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	next, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: team, MemberDIDKey: key,
		MemberDIDAW: svc.identity.StableID, MemberAddress: first.MemberAddress, Alias: "alice", IdentityScope: awid.IdentityModeGlobal})
	if err != nil {
		t.Fatal(err)
	}
	err = awconfig.UpdateCredentials(home.Root, awconfig.CredentialOperation{Command: "review", Intent: "certificate"}, func(begin func() error) error {
		if err := begin(); err != nil {
			return err
		}
		_, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home.Root, team, next)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = old.readStoredMailReply(context.Background(), "message-1")
	if observed != first.CertificateID {
		t.Fatalf("old admitted client sent %s, want %s", observed, first.CertificateID)
	}
	// This is exactly signAppRequest's signing stage.
	identity, err := svc.appSigningIdentity(admitted, team)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse("https://app.example/v1/tool")
	headers := make(http.Header)
	if err := signIDRequestHeaders(headers, http.MethodPost, target, identity, []byte("{}"), map[string]any{}, true, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	signed, err := awid.DecodeTeamCertificateHeader(headers.Get("X-AWID-Team-Certificate"))
	if err != nil {
		t.Fatal(err)
	}
	if signed.CertificateID != first.CertificateID {
		t.Fatalf("one admitted operation used old client certificate %s then live signing certificate %s (new=%s)", first.CertificateID, signed.CertificateID, next.CertificateID)
	}
}

func TestSecurityReviewOlderCaptureDoesNotPublishAfterNewerRefusal(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no first client")
	}
	old, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	commitTeams(t, c.home, "newer")
	if c.deps(t).client == nil {
		t.Fatal("no newer client")
	}
	generation := c.snapshotGeneration
	writeTeams(t, c.home, "unpublished")
	if c.deps(t).client != nil {
		t.Fatal("new unpublished request should refuse")
	}
	_ = c.admitCapture(context.Background(), old, nil)
	c.clientMu.Lock()
	current := c.snapshotGeneration
	c.clientMu.Unlock()
	if current < generation {
		t.Fatalf("old captured generation %d replaced generation %d after a newer refusal", current, generation)
	}
}

func TestSecurityReviewCompletedInstallRecoveryPublishesItsMarker(t *testing.T) {
	_, teamKey, _ := awid.GenerateKeypair()
	registry := newCertificateRegistry(t, teamKey)
	home, didKey := keyOnlyHome(t)
	cert := signedMemberCertificate(t, teamKey, didKey, "", awid.IdentityModeLocal)
	registry.register(cert, false)
	request := installRequest(t, registry, home, certificateFile(t, cert))
	if _, err := installTeamCertificateFile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	// State after the first install's file writes, but before its manifest was published.
	if err := os.Remove(filepath.Join(home, "credential-generation.json")); err != nil {
		t.Fatal(err)
	}
	encoded, err := awid.EncodeTeamCertificateFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	op := awconfig.CredentialOperation{Command: "install-cert", Intent: awconfig.CredentialIntent(map[string]any{"team_id": cert.Team, "certificate_id": cert.CertificateID, "certificate_sha256": hex.EncodeToString(sum[:])})}
	marker := awconfig.CredentialMarker{TxID: "interrupted-after-files", Operation: op, Base: awconfig.CredentialBase{}, TargetGeneration: 1}
	raw, _ := json.Marshal(marker)
	if err := os.WriteFile(filepath.Join(home, "credential-update.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installTeamCertificateFile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	state, err := awconfig.ReadCredentialState(home)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Published() || state.Marker != nil || state.Generation != 1 {
		t.Fatalf("same-operation retry returned success but left the completed install unpublished: generation=%d marker=%+v", state.Generation, state.Marker)
	}
}

func TestSecurityReviewCaptureRootCannotBeASymlink(t *testing.T) {
	c := newCaptureService(t)
	outside := t.TempDir()
	root := filepath.Join(c.home, custodyCaptureDir)
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Fatal(err)
	}
	capture, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := c.writeCapture(capture.CredentialCapture)
	if err == nil {
		actual, _ := filepath.EvalSymlinks(dir)
		t.Fatalf("resident signing-key capture was copied through a symlink outside its home: %s", actual)
	}
}

func TestSecurityReviewOldCaptureCannotPublishAfterANewerBuildFails(t *testing.T) {
	c := newCaptureService(t)
	if c.deps(t).client == nil {
		t.Fatal("no original client")
	}
	old, err := c.captureCredentials()
	if err != nil {
		t.Fatal(err)
	}
	connect := c.connectClient
	commitTeams(t, c.home, "newer-but-failing")
	c.connectClient = func(context.Context, awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error) {
		return nil, nil, errors.New("new build failed")
	}
	if c.deps(t).client != nil {
		t.Fatal("new failed generation should refuse")
	}
	c.connectClient = connect
	_ = c.admitCapture(context.Background(), old, nil)
	c.clientMu.Lock()
	got := c.client
	gen := c.snapshotGeneration
	c.clientMu.Unlock()
	if got != nil {
		t.Fatalf("old generation %d was rebuilt and served after a newer published generation failed its build", gen)
	}
}

// A capture's read precedes its decision; an equal-generation refusal must
// not be cleared merely because that old capture reaches the mutex later.
func TestSecurityReviewDelayedCaptureDoesNotClearAnEqualGenerationRefusal(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		name := "unpublished_older_writer"
		if interrupted {
			name = "interrupted_supported_writer"
		}
		t.Run(name, func(t *testing.T) {
			c := newCaptureService(t)
			commitTeams(t, c.home, "second")
			if c.deps(t).client == nil {
				t.Fatal("no published client")
			}
			earlier, err := c.captureCredentials()
			if err != nil {
				t.Fatal(err)
			}
			if interrupted {
				stop := errors.New("interrupted before publication")
				err = awconfig.UpdateCredentials(c.home, teamsOp, func(begin func() error) error {
					if err := begin(); err != nil {
						return err
					}
					writeTeams(t, c.home, "partial")
					return stop
				})
				if !errors.Is(err, stop) {
					t.Fatalf("did not leave the interrupted update: %v", err)
				}
			} else {
				writeTeams(t, c.home, "unpublished")
			}
			if c.deps(t).client != nil {
				t.Fatal("changed home should refuse")
			}
			builds := len(c.builtOn)
			old := c.admitCapture(context.Background(), earlier, nil)
			c.clientMu.Lock()
			published := c.client
			c.clientMu.Unlock()
			if old.client != nil || published != nil {
				t.Fatalf("capture read before the refusal reattached a client: returned=%p published=%p builds=%d", old.client, published, len(c.builtOn)-builds)
			}
		})
	}
}
