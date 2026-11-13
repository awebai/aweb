package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/awebai/aw/internal/custodypath"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var custodyCmd = &cobra.Command{Use: "custody", Short: "Local resident custody service"}

var custodyServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve local resident custody operations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCustodyServe(cmd.Context())
	},
}

var custodyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Probe local resident custody service",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := runCustodyStatus(cmd.Context())
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(status, "", "  ")
		fmt.Fprintln(commandStdout, string(b))
		return nil
	},
}

var custodyStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop local resident custody service",
	RunE:  func(cmd *cobra.Command, args []string) error { return runCustodyStop(cmd.Context()) },
}

func init() {
	custodyCmd.AddCommand(custodyServeCmd, custodyStatusCmd, custodyStopCmd)
	rootCmd.AddCommand(custodyCmd)
}

type custodyStatusReport struct {
	Status     string `json:"status"`
	ServiceID  string `json:"service_id,omitempty"`
	SocketPath string `json:"socket_path"`
	Resident   struct {
		DIDAW   string `json:"did_aw,omitempty"`
		DIDKey  string `json:"did_key,omitempty"`
		Address string `json:"address,omitempty"`
		Alias   string `json:"alias,omitempty"`
	} `json:"resident"`
	Teams     []map[string]any    `json:"teams"`
	Keys      map[string]any      `json:"keys"`
	Ops       []string            `json:"ops"`
	Freshness map[string]any      `json:"freshness"`
	Client    custodyClientStatus `json:"client"`
	Errors    []string            `json:"errors,omitempty"`
}

// custodyClientStatus reports custody's connection to the aweb server. The
// client is built on the first request that needs it; last_error is the
// sanitized code of the latest failed request and when it failed.
type custodyClientStatus struct {
	Connected   bool   `json:"connected"`
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`
}

type custodyGrantStatus struct {
	Active                                                  bool
	Scopes                                                  []string
	GrantDIDKey, TeamID, Status, EffectiveStatus, ExpiresAt string
	LastCheckedAt                                           string
}

type custodyService struct {
	residentHome        string
	socketPath          string
	identity            *awconfig.ResolvedIdentity
	signingKey          ed25519.PrivateKey
	e2eeAssertion       *awid.EncryptionKeyAssertion
	e2eePrivateKey      *ecdh.PrivateKey
	client              *aweb.Client
	grantStatus         func(context.Context, string) (custodyGrantStatus, error)
	readinessCheck      func(context.Context) (string, error)
	readStoredEnvelope  func(context.Context, string, string, string) (*awid.E2EEMessageEnvelope, error)
	readStoredMailReply func(context.Context, string) (*awid.InboxMessage, error)
	resolveRecipient    func(context.Context, string) (*awid.ResolvedIdentity, error)
	e2eeKeyError        string
	// connectClient selects the resident's team and builds its aweb client.
	// With AWEB_URL set it probes the server for the API base, so custody
	// calls it on the first request that needs the client, never at start.
	// connectClient builds from home, a capture of the resident home's
	// credentials, never from the resident home itself.
	connectClient func(ctx context.Context, home awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error)
	// workingDir is the directory the service was started from.
	workingDir string
	// readerLock marks the resident home as served for the service's
	// lifetime: supported writers then keep it coherent for this reader.
	readerLock io.Closer
	// The published snapshot: the credential generation and projection the
	// client and its derived functions were built from, and the team
	// certificates that capture held. identityChanged is set, until restart,
	// once the resident home holds another identity than this service started
	// with.
	snapshotGeneration  int64
	snapshotProjection  string
	snapshotTeams       []awconfig.StoredTeamCertificate
	snapshotCertificate *awid.TeamCertificate
	identityChanged     bool
	// observedGeneration is the newest generation any admission observed,
	// built or not. captures orders captures by when they read the home, and
	// lastRefusal is the order of the newest capture that was refused, so
	// nothing read before it admits a client or publishes over it.
	observedGeneration int64
	captures           atomic.Int64
	lastRefusal        int64
	// clientMu serializes building the client and guards the client, the
	// functions derived from it, the selection-derived fields and the last
	// failure.
	clientMu         sync.Mutex
	lastError        string
	lastErrorAt      string
	logOut           io.Writer
	selectedTeam     string
	appDeniedOrigins []string
	serviceID        string
	now              func() time.Time
	mu               sync.Mutex
	replay           map[string]string
	replayAt         map[string]time.Time
	results          map[string]any
	server           *http.Server
}

func newCustodyService(home awconfig.IdentityHome) (*custodyService, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	// ResolveIdentityHome canonicalizes the default cwd. Use the same spelling
	// for resolution and the local fallback, even when Getwd preserves PWD.
	wd, err = filepath.EvalSymlinks(wd)
	if err != nil {
		return nil, fmt.Errorf("resolve custody working directory: %w", err)
	}
	if awconfig.IsGrantHome(home.Root) {
		return nil, usageError("custody serve requires the resident identity home, not a grant home")
	}
	identity, err := awconfig.ResolveIdentityFromHome(wd, home.Root)
	if err != nil && filepath.Clean(home.Root) == awconfig.WorktreeIdentityHome(wd) {
		// Legacy local init intentionally omits identity.yaml. Reuse only this
		// workspace's certificate/key-bound resolver, never another selected home
		// or an existing malformed identity file.
		if _, statErr := os.Lstat(filepath.Join(home.Root, "identity.yaml")); os.IsNotExist(statErr) {
			identity, err = resolveLocalIdentityWithoutState(wd)
		}
	}
	if err != nil {
		return nil, err
	}
	if err := validateResolvedIdentity(identity); err != nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return nil, err
	}
	e2eeAssertion, e2eePrivateKey, e2eeKeyErr := loadCustodyE2EEKey(home.Root, identity)
	e2eeKeyError := ""
	if e2eeKeyErr != nil {
		e2eeKeyError = "encryption_key_unavailable"
	}
	serviceID, _ := awid.GenerateUUID4()
	svc := &custodyService{residentHome: home.Root, socketPath: awconfig.CustodySocketPath(home.Root), identity: identity, signingKey: key, e2eeAssertion: e2eeAssertion, e2eePrivateKey: e2eePrivateKey, e2eeKeyError: e2eeKeyError, serviceID: serviceID, now: time.Now, replay: map[string]string{}, replayAt: map[string]time.Time{}, results: map[string]any{}}
	svc.workingDir = wd
	svc.connectClient = func(ctx context.Context, captured awconfig.IdentityHome) (*awconfig.Selection, *aweb.Client, error) {
		sel, err := resolveSelectionAtIdentityHome(wd, "", captured)
		if err != nil {
			return nil, nil, err
		}
		client, _, err := buildClientForSelectionAtIdentityHome(ctx, wd, externalIdentityHomeRoot(captured), sel, resolveAuthenticatedBaseURLContext)
		return sel, client, err
	}
	// Selection reads local configuration only. Keep it even when it later
	// fails to build a client so status can report the selected team without
	// exposing resolver details.
	if sel, err := resolveSelectionAtIdentityHome(wd, "", home); err != nil {
		svc.reportFailure("select team", custodyClientInitializationErrorCode(err), err)
	} else {
		svc.applySelectionLocked(sel)
	}
	if err := svc.bootstrapCredentials(); err != nil {
		return nil, err
	}
	return svc, nil
}

func (s *custodyService) applySelectionLocked(sel *awconfig.Selection) {
	if sel == nil {
		return
	}
	s.selectedTeam = strings.TrimSpace(sel.TeamID)
	s.appDeniedOrigins = grantAppDeniedOrigins(sel.BaseURL, sel.RegistryURL)
}

// custodyClientDeps is a consistent view of the client-derived state.
type custodyClientDeps struct {
	client              *aweb.Client
	grantStatus         func(context.Context, string) (custodyGrantStatus, error)
	readinessCheck      func(context.Context) (string, error)
	readStoredEnvelope  func(context.Context, string, string, string) (*awid.E2EEMessageEnvelope, error)
	readStoredMailReply func(context.Context, string) (*awid.InboxMessage, error)
	resolveRecipient    func(context.Context, string) (*awid.ResolvedIdentity, error)
	appDeniedOrigins    []string
	// certificate is the selected team certificate the snapshot was built
	// with; requests that sign as the team member use it.
	certificate *awid.TeamCertificate
}

// admittedDepsKey carries a request's admitted client-derived functions.
type admittedDepsKey struct{}

// admit returns ctx carrying the client-derived functions admitted for one
// request, so every part of the request uses the same snapshot.
func (s *custodyService) admit(ctx context.Context) context.Context {
	return context.WithValue(ctx, admittedDepsKey{}, s.clientDeps(ctx))
}

// admitted wraps a credential-using handler so its request is admitted once.
func (s *custodyService) admitted(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler(w, r.WithContext(s.admit(r.Context())))
	}
}

// custodyCaptureWait bounds how long admission waits for a credential update
// of the resident home to finish.
const custodyCaptureWait = 2 * time.Second

// clientDeps returns the client-derived functions for a request: those its
// admission took, or, admitting it now, the published snapshot after
// capturing the resident home's credentials once. A capture that holds
// another identity than this service started with latches identity_changed
// until restart; one with an incomplete update, or changed without a
// published generation, admits no client. A capture of another projection
// than the snapshot's is built, from that capture and nothing else, and
// published only if no newer snapshot was published meanwhile. A failure is
// logged and reported by status; the next request tries again.
func (s *custodyService) clientDeps(ctx context.Context) custodyClientDeps {
	if deps, ok := ctx.Value(admittedDepsKey{}).(custodyClientDeps); ok {
		return deps
	}
	if s.connectClient == nil {
		// Given fixed client functions, the service builds nothing from the
		// resident home, so there is nothing to admit against it.
		s.clientMu.Lock()
		defer s.clientMu.Unlock()
		return s.depsLocked()
	}
	capture, captureErr := s.captureCredentials()
	return s.admitCapture(ctx, capture, captureErr)
}

// admitCapture admits a request on capture, the resident home's credentials
// as its admission read them. The decision is taken under clientMu; a build
// it needs runs outside it, and its result is published only if nothing the
// service observed meanwhile supersedes it.
func (s *custodyService) admitCapture(ctx context.Context, capture *custodyCapture, captureErr error) custodyClientDeps {
	s.clientMu.Lock()
	deps, build := s.decideLocked(capture, captureErr)
	s.clientMu.Unlock()
	if !build {
		return deps
	}
	built, err := s.buildSnapshot(ctx, capture.CredentialCapture)
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	return s.publishLocked(capture, built, err)
}

// decideLocked decides what capture admits. Observations are fenced: a
// capture of a generation older than one already observed, or read before a
// capture that was refused, changes nothing and admits no client; a refusal
// records its capture's order, so a build from a capture read before it
// never publishes. It reports whether a build is needed.
func (s *custodyService) decideLocked(capture *custodyCapture, captureErr error) (custodyClientDeps, bool) {
	switch {
	case s.identityChanged:
		return custodyClientDeps{}, false
	case captureErr != nil:
		code := "credential_update_incomplete"
		if errors.Is(captureErr, awconfig.ErrLockUnavailable) {
			code = "credential_update_busy"
		}
		s.reportFailureLocked("load credentials", code, captureErr)
		return custodyClientDeps{}, false
	}
	if err := s.checkPinLocked(capture.CredentialCapture); err != nil {
		// identityChanged refuses every later admission and publication.
		s.identityChanged = true
		s.detachClientLocked()
		s.reportFailureLocked("load credentials", "identity_changed", err)
		return custodyClientDeps{}, false
	}
	if capture.State.Generation < s.observedGeneration || capture.order < s.lastRefusal {
		return custodyClientDeps{}, false
	}
	s.observedGeneration = capture.State.Generation
	if !capture.State.Published() {
		code := awconfig.ErrCredentialUpdateUnpublished.Error()
		if capture.State.Marker != nil && !capture.State.Committed() {
			code = awconfig.ErrCredentialUpdateIncomplete.Error()
		}
		s.refuseLocked(capture)
		s.reportFailureLocked("load credentials", code, fmt.Errorf("the resident home's credentials are not a published generation"))
		return custodyClientDeps{}, false
	}
	if s.client != nil && capture.Projection == s.snapshotProjection {
		return s.depsLocked(), false
	}
	// The superseded snapshot is dropped before the build, so a failed build
	// serves nothing rather than credentials known to be replaced.
	s.detachClientLocked()
	return custodyClientDeps{}, true
}

// refuseLocked drops the served snapshot and records capture's order as the
// newest refused one: decideLocked refuses nothing older than lastRefusal
// before reaching here, so the order only grows.
func (s *custodyService) refuseLocked(capture *custodyCapture) {
	s.lastRefusal = capture.order
	s.detachClientLocked()
}

// builtSnapshot is a client built from one capture, with what the capture's
// selection held.
type builtSnapshot struct {
	selection   *awconfig.Selection
	client      *aweb.Client
	teams       []awconfig.StoredTeamCertificate
	certificate *awid.TeamCertificate
}

// publishLocked publishes built, the result of building capture, unless the
// service has since observed a newer generation or refused a capture read
// after it, or a concurrent build already published this generation.
func (s *custodyService) publishLocked(capture *custodyCapture, built *builtSnapshot, err error) custodyClientDeps {
	switch {
	case s.identityChanged || capture.order < s.lastRefusal || capture.State.Generation < s.observedGeneration:
		return custodyClientDeps{}
	case err != nil:
		s.reportFailureLocked("connect to aweb", custodyClientInitializationErrorCode(err), err)
		return custodyClientDeps{}
	case s.client != nil && s.snapshotGeneration >= capture.State.Generation:
		if s.snapshotProjection == capture.Projection {
			return s.depsLocked()
		}
		return custodyClientDeps{}
	}
	s.applySelectionLocked(built.selection)
	s.attachClientLocked(built.client)
	s.snapshotGeneration, s.snapshotProjection = capture.State.Generation, capture.Projection
	s.snapshotTeams, s.snapshotCertificate = built.teams, built.certificate
	return s.depsLocked()
}

// custodyCapture is one capture of the resident home's credentials and its
// order among this service's captures: a capture with a higher order read
// the home no earlier than one with a lower order.
type custodyCapture struct {
	*awconfig.CredentialCapture
	order int64
}

// captureCredentials reads the resident home's credentials once, under the
// shared side of its credential lock, waiting at most custodyCaptureWait for
// an update to finish. The capture's order is taken under the lock, just
// before the read.
func (s *custodyService) captureCredentials() (*custodyCapture, error) {
	deadline := time.Now().Add(custodyCaptureWait)
	for {
		lock, err := awconfig.LockCredentialsShared(s.residentHome)
		if err == nil {
			defer lock.Close()
			order := s.captures.Add(1)
			capture, err := awconfig.CaptureCredentials(s.residentHome)
			if err != nil {
				return nil, err
			}
			return &custodyCapture{CredentialCapture: capture, order: order}, nil
		}
		if !errors.Is(err, awconfig.ErrLockUnavailable) || time.Now().After(deadline) {
			return nil, fmt.Errorf("the resident home's credentials are being updated: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// checkPinLocked refuses a capture whose identity or signing key is not the
// one this service started with.
func (s *custodyService) checkPinLocked(capture *awconfig.CredentialCapture) error {
	if s.identity == nil {
		return nil
	}
	pinned := strings.TrimSpace(s.identity.DID)
	var identity awconfig.WorktreeIdentity
	if err := yaml.Unmarshal(capture.Files["identity.yaml"], &identity); err != nil {
		return fmt.Errorf("the resident home's identity cannot be read: %w", err)
	}
	if did := strings.TrimSpace(identity.DID); did != "" && did != pinned {
		return fmt.Errorf("the resident home now holds %s, not %s; restart the custody service", did, pinned)
	}
	if data, ok := capture.Files["signing.key"]; ok {
		key, err := awid.ParseSigningKey(data)
		if err != nil {
			return fmt.Errorf("the resident home's signing key cannot be read: %w", err)
		}
		if did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)); did != pinned {
			return fmt.Errorf("the resident home's signing key is %s, not %s; restart the custody service", did, pinned)
		}
	}
	return nil
}

// buildSnapshot builds the client from capture, written to a private
// directory in the resident home that is removed as soon as the client is
// built: the built client keeps no path into it. It reads the selected team
// certificate from the capture too, so signing uses the admitted one.
func (s *custodyService) buildSnapshot(ctx context.Context, capture *awconfig.CredentialCapture) (*builtSnapshot, error) {
	dir, err := s.writeCapture(capture)
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return nil, err
	}
	captured := awconfig.IdentityHome{Root: dir, Source: awconfig.IdentityHomeFlag}
	sel, client, err := s.connectClient(ctx, captured)
	if err == nil && client == nil {
		err = errors.New("no aweb client for the selected team")
	}
	if err != nil {
		return nil, err
	}
	built := &builtSnapshot{selection: sel, client: client}
	built.teams, _ = awconfig.ListTeamCertificatesFromIdentityHome(dir)
	if sel != nil && strings.TrimSpace(sel.WorkspacePath) != "" {
		built.certificate, _ = loadSelectedTeamCertificate(sel)
	}
	return built, nil
}

// custodyCaptureDir holds the resident home's private credential captures
// while a client is built from one.
const custodyCaptureDir = ".custody-captures"

// writeCapture writes capture into a fresh directory under the resident
// home's capture root. The root must be a real directory of this user's in
// the resident home: a symlink, a symlinked parent or anything but a
// directory is refused before any key bytes are written, and changing its
// mode fails for a directory this user does not own.
func (s *custodyService) writeCapture(capture *awconfig.CredentialCapture) (string, error) {
	root := filepath.Join(s.residentHome, custodyCaptureDir)
	check := func() error {
		return pathpreflight.PreflightDir(root, "custody capture directory", pathpreflight.AllowTempAmbientSymlinkPrefix())
	}
	if err := check(); err != nil {
		return "", err
	}
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", err
	}
	if err := check(); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "capture-")
	if err != nil {
		return "", err
	}
	if err := os.Remove(dir); err != nil {
		return "", err
	}
	return dir, capture.WriteTo(dir)
}

// removeCaptures removes captures a stopped service left behind.
func removeCaptures(residentHome string) error {
	return os.RemoveAll(filepath.Join(residentHome, custodyCaptureDir))
}

func (s *custodyService) depsLocked() custodyClientDeps {
	return custodyClientDeps{certificate: s.snapshotCertificate,
		client: s.client, grantStatus: s.grantStatus, readinessCheck: s.readinessCheck,
		readStoredEnvelope: s.readStoredEnvelope, readStoredMailReply: s.readStoredMailReply,
		resolveRecipient: s.resolveRecipient, appDeniedOrigins: s.appDeniedOrigins,
	}
}

// detachClientLocked drops the client and every function derived from it.
func (s *custodyService) detachClientLocked() {
	s.client, s.grantStatus, s.readStoredEnvelope, s.readStoredMailReply, s.resolveRecipient, s.readinessCheck = nil, nil, nil, nil, nil, nil
	s.snapshotProjection, s.snapshotCertificate = "", nil
}

func (s *custodyService) attachClientLocked(client *aweb.Client) {
	s.client = client
	s.grantStatus = grantStatusViaClient(client)
	s.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		return s.storedE2EEEnvelopeViaClient(ctx, client, kind, messageID, conversationID)
	}
	s.readStoredMailReply = func(ctx context.Context, messageID string) (*awid.InboxMessage, error) {
		return s.storedMailReplyViaClient(ctx, client, messageID)
	}
	s.resolveRecipient = client.ResolveIdentity
	s.readinessCheck = func(ctx context.Context) (string, error) {
		return client.ProbeIdentityGrantStatus(ctx)
	}
}

// reportFailure logs a failed operation with its cause and keeps its sanitized
// code for status. Status reports only the code; the log has the cause.
func (s *custodyService) reportFailure(op, code string, err error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	s.reportFailureLocked(op, code, err)
}

func (s *custodyService) reportFailureLocked(op, code string, err error) {
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	s.lastError = code
	s.lastErrorAt = now().UTC().Format(time.RFC3339)
	out := s.logOut
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "%s aw custody: %s failed: %s: %v\n", s.lastErrorAt, op, code, err)
}

func (s *custodyService) clientStatus() custodyClientStatus {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	return custodyClientStatus{Connected: s.client != nil || (s.connectClient == nil && s.grantStatus != nil), LastError: s.lastError, LastErrorAt: s.lastErrorAt}
}

func custodyClientInitializationErrorCode(err error) string {
	if err == nil {
		return "client_initialization_unavailable"
	}
	if isIdentityMismatchError(err) {
		return "client_initialization_identity_mismatch"
	}
	if status, ok := awid.HTTPStatusCode(err); ok {
		return fmt.Sprintf("client_initialization_http_%d", status)
	}
	if exitCode(err) == 2 {
		return "client_initialization_selection_refused"
	}
	return "client_initialization_failed"
}

func grantStatusViaClient(client *aweb.Client) func(context.Context, string) (custodyGrantStatus, error) {
	return func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
		g, err := client.IdentityGrantStatus(ctx, strings.TrimSpace(grantID))
		if err != nil {
			return custodyGrantStatus{}, err
		}
		effective := strings.TrimSpace(g.EffectiveStatus)
		return custodyGrantStatus{Active: effective == "active", Scopes: g.Scopes, GrantDIDKey: g.GrantDIDKey, TeamID: g.TeamID, Status: g.Status, EffectiveStatus: effective, ExpiresAt: g.ExpiresAt, LastCheckedAt: g.LastCheckedAt}, nil
	}
}

func runCustodyServe(ctx context.Context) error {
	home, err := identityHomeForDir(mustGetwd())
	if err != nil {
		return err
	}
	svc, err := newCustodyService(home)
	if err != nil {
		return err
	}
	return svc.serve(ctx)
}

// custodyReaderWait bounds how long a starting service waits for a supported
// credential update of its resident home to finish.
const custodyReaderWait = 30 * time.Second

// bootstrapCredentials runs once as the service starts. It marks the resident
// home as served, waiting for a supported update that is writing it, so it
// never starts on a half-written home; it holds that mark for its lifetime.
// It removes captures a stopped service left behind, and adopts the resident
// home's current credentials as its next generation when they are valid and
// not already the published ones. An interrupted update or an invalid home is
// not adopted; requests then fail closed until a supported update or a
// restart resolves it.
func (s *custodyService) bootstrapCredentials() error {
	deadline := time.Now().Add(custodyReaderWait)
	for {
		reader, err := awconfig.LockCredentialReader(s.residentHome)
		if err == nil {
			s.readerLock = reader
			break
		}
		if !errors.Is(err, awconfig.ErrLockUnavailable) || time.Now().After(deadline) {
			return fmt.Errorf("a credential update of %s is still running: %w", s.residentHome, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := removeCaptures(s.residentHome); err != nil {
		s.reportFailure("remove credential captures", "credential_update_incomplete", err)
	}
	if _, err := awconfig.AdoptCredentials(s.residentHome, s.validateCapture); err != nil {
		code := awconfig.ErrCredentialUpdateUnpublished.Error()
		if errors.Is(err, awconfig.ErrCredentialUpdateIncomplete) {
			code = awconfig.ErrCredentialUpdateIncomplete.Error()
		}
		s.reportFailure("adopt credentials", code, err)
	}
	return nil
}

// validateCapture accepts a capture whose identity and signing key are this
// service's and whose selected team certificate, when the home selects one,
// names that key. A home with no selection yet is a readiness state, not an
// invalid one.
func (s *custodyService) validateCapture(capture *awconfig.CredentialCapture) error {
	if err := s.checkPinLocked(capture); err != nil {
		return err
	}
	dir, err := s.writeCapture(capture)
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	if err != nil {
		return err
	}
	sel, err := resolveSelectionAtIdentityHome(s.workingDir, "", awconfig.IdentityHome{Root: dir, Source: awconfig.IdentityHomeFlag})
	if err != nil {
		return nil
	}
	cert, err := loadSelectedTeamCertificate(sel)
	if err != nil {
		return nil
	}
	if s.identity != nil && cert.MemberDIDKey != strings.TrimSpace(s.identity.DID) {
		return fmt.Errorf("the selected team certificate names %s, not this service's key %s", cert.MemberDIDKey, s.identity.DID)
	}
	return nil
}

func (s *custodyService) serve(ctx context.Context) error {
	if err := validateCustodySocketPathLength(s.socketPath); err != nil {
		return err
	}
	if strings.TrimSpace(s.serviceID) == "" {
		id, _ := awid.GenerateUUID4()
		s.serviceID = id
	}
	if err := custodypath.Prepare(s.socketPath); err != nil {
		return err
	}
	runDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.socketPath); err == nil {
		if err := custodyHTTPTimeout(ctx, s.socketPath, http.MethodGet, "/ping", nil, nil, 500*time.Millisecond); err == nil {
			return usageError("custody service already running at %s", s.socketPath)
		} else if !isStaleCustodySocketError(err) {
			return usageError("custody service already running or not safely stale at %s: %v", s.socketPath, err)
		}
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("remove stale custody socket: %w", err)
		}
	}
	ln, err := listenCustodySocket(s.socketPath)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/sign_plain_message", s.admitted(s.handleSignPlainMessage))
	mux.HandleFunc("/create_e2ee_envelope", s.admitted(s.handleCreateE2EEEnvelope))
	mux.HandleFunc("/unwrap_e2ee_message", s.admitted(s.handleUnwrapE2EEMessage))
	mux.HandleFunc("/sign_app_request", s.admitted(s.handleSignAppRequest))
	mux.HandleFunc("/stop", s.handleStop)

	renewalCtx, stopRenewal := context.WithCancel(ctx)
	defer stopRenewal()
	go s.renewEncryptionAssertions(renewalCtx)
	s.server = &http.Server{Handler: mux}
	go func() { <-ctx.Done(); _ = s.server.Close() }()
	err = s.server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *custodyService) handlePing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "service_id": strings.TrimSpace(s.serviceID)})
}

func (s *custodyService) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.status(r.Context(), "running", nil))
}
func (s *custodyService) status(ctx context.Context, status string, errs []string) custodyStatusReport {
	var out custodyStatusReport
	out.Status = status
	out.ServiceID = strings.TrimSpace(s.serviceID)
	out.SocketPath = s.socketPath
	out.Resident.DIDAW = s.identity.StableID
	out.Resident.DIDKey = s.identity.DID
	out.Resident.Address = s.identity.Address
	out.Resident.Alias = s.identity.Handle
	deps := s.clientDeps(ctx)
	if deps.grantStatus == nil {
		if code := s.clientStatus().LastError; code != "" {
			errs = append(errs, code)
		}
	}
	grantStatusReady := deps.grantStatus != nil
	lastCheckedAt := any(nil)
	if deps.readinessCheck != nil {
		// Custody checks retain their short freshness/read budget within the calling request.
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		checkedAt, err := deps.readinessCheck(checkCtx)
		cancel()
		if err != nil {
			grantStatusReady = false
			errs = append(errs, "grant_status_unavailable")
			s.reportFailure("check grant status endpoint", "grant_status_unavailable", err)
		} else {
			lastCheckedAt = strings.TrimSpace(checkedAt)
		}
	}
	teams, teamErrs := s.teamReadiness(grantStatusReady)
	out.Teams = teams
	if len(teamErrs) > 0 {
		errs = append(errs, teamErrs...)
	}
	encryptionKeyID := ""
	if s.e2eeAssertion != nil {
		encryptionKeyID = strings.TrimSpace(s.e2eeAssertion.EncryptionKeyID)
	}
	if strings.TrimSpace(s.e2eeKeyError) != "" {
		errs = append(errs, strings.TrimSpace(s.e2eeKeyError))
	}
	out.Keys = map[string]any{"signing_key_loaded": s.signingKey != nil, "signing_ready": s.signingKey != nil && grantStatusReady, "encryption_ready": s.e2eeAssertion != nil && s.e2eePrivateKey != nil && grantStatusReady, "encryption_key_id": encryptionKeyID}
	out.Ops = []string{"status.v1", "sign_plain_message.v1", "sign_app_request.v1", "grant_never_ttl.v1"}
	if s.e2eeAssertion != nil && s.e2eePrivateKey != nil {
		out.Ops = append(out.Ops, "create_e2ee_envelope.v1", "unwrap_e2ee_message.v1", "mail_reply_continuation.v1")
	}
	out.Freshness = map[string]any{"source": "identity-grants", "last_checked_at": lastCheckedAt, "max_cache_age_seconds": 30}
	out.Client = s.clientStatus()
	out.Errors = errs
	return out
}
func (s *custodyService) teamReadiness(grantStatusReady bool) ([]map[string]any, []string) {
	// A service that builds its client from the resident home reports the
	// teams of the snapshot it serves; one given fixed client functions has no
	// snapshot and reports the home's certificates.
	s.clientMu.Lock()
	certs, fixed := s.snapshotTeams, s.connectClient == nil
	s.clientMu.Unlock()
	if fixed {
		if strings.TrimSpace(s.residentHome) == "" {
			return nil, nil
		}
		listed, err := awconfig.ListTeamCertificatesFromIdentityHome(s.residentHome)
		if err != nil {
			return nil, []string{"team_certificates_unavailable"}
		}
		certs = listed
	}
	teams := make([]map[string]any, 0, len(certs))
	for _, cert := range certs {
		teamID := strings.TrimSpace(cert.TeamID)
		if teamID == "" {
			continue
		}
		certificatePresent := cert.Certificate != nil
		teams = append(teams, map[string]any{
			"team_id":                     teamID,
			"ready":                       s.signingKey != nil && certificatePresent && grantStatusReady,
			"certificate_present":         certificatePresent,
			"certificate_loadable":        certificatePresent,
			"grant_status_endpoint_ready": grantStatusReady,
		})
	}
	return teams, nil
}

func (s *custodyService) handleStop(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "stopping"})
	go func() { time.Sleep(50 * time.Millisecond); _ = s.server.Close() }()
}

func (s *custodyService) handleSignPlainMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "unsupported_operation", 405)
		return
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(&raw); err != nil {
		writeCustodyError(w, 400, "bad_request")
		return
	}
	allowed := map[string]bool{"v": true, "op": true, "grant_id": true, "session_did_key": true, "team_id": true, "subject_did_aw": true, "subject_did_key": true, "aud": true, "nonce": true, "timestamp": true, "request_digest": true, "signature": true, "envelope": true}
	for k := range raw {
		if !allowed[k] {
			writeCustodyError(w, 403, "message_not_allowed")
			return
		}
	}
	if envRaw, ok := raw["envelope"]; ok {
		var envMap map[string]json.RawMessage
		if json.Unmarshal(envRaw, &envMap) == nil {
			envAllowed := map[string]bool{"from": true, "from_did": true, "to": true, "to_did": true, "type": true, "priority": true, "wait_seconds": true, "subject": true, "body": true, "timestamp": true, "from_stable_id": true, "to_stable_id": true, "message_id": true, "conversation_id": true, "reply_to": true, "sender_leaving": true, "hang_on": true}
			for k := range envMap {
				if !envAllowed[k] {
					writeCustodyError(w, 403, "message_not_allowed")
					return
				}
			}
		}
	}
	b, _ := json.Marshal(raw)
	var req awid.PlainMessageSignRequest
	if err := json.Unmarshal(b, &req); err != nil {
		writeCustodyError(w, 400, "bad_request")
		return
	}
	out, err := s.signPlainMessage(r.Context(), &req)
	if err != nil {
		writeCustodyError(w, 403, err.Error())
		return
	}
	writeJSON(w, out)
}

func (s *custodyService) signPlainMessage(ctx context.Context, req *awid.PlainMessageSignRequest) (*awid.PlainMessageSignResponse, error) {
	if err := awid.VerifyCustodyProof(req); err != nil {
		return nil, err
	}
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(req.Timestamp))
	if err != nil {
		return nil, fmt.Errorf("bad_timestamp")
	}
	if s.now().Sub(ts) > 60*time.Second || ts.Sub(s.now()) > 60*time.Second {
		return nil, fmt.Errorf("bad_timestamp")
	}
	if strings.TrimSpace(req.Audience) != "local-resident-custody:"+strings.TrimSpace(s.serviceID) {
		return nil, fmt.Errorf("bad_audience")
	}
	if req.SubjectDIDKey != s.identity.DID || (req.SubjectDIDAW != "" && req.SubjectDIDAW != s.identity.StableID) {
		return nil, fmt.Errorf("grant_subject_mismatch")
	}
	kind := strings.TrimSpace(req.Envelope.Type)
	if kind != "mail" && kind != "chat" {
		return nil, fmt.Errorf("message_not_allowed")
	}
	if req.Envelope.Signature != "" || req.Envelope.SigningKeyID != "" || req.Envelope.FromDID != "" {
		return nil, fmt.Errorf("message_not_allowed")
	}
	if from := strings.TrimSpace(req.Envelope.From); from != "" && from != strings.TrimSpace(s.identity.Address) && from != strings.TrimSpace(s.identity.Handle) {
		return nil, fmt.Errorf("message_not_allowed")
	}
	grantStatus := s.clientDeps(ctx).grantStatus
	if grantStatus == nil {
		return nil, fmt.Errorf("grant_freshness_unavailable")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := grantStatus(freshCtx, req.GrantID)
	if err != nil {
		s.reportFailure("check grant freshness", "grant_freshness_unavailable", err)
		return nil, fmt.Errorf("grant_freshness_unavailable")
	}
	if !st.Active {
		switch firstNonEmpty(strings.TrimSpace(st.EffectiveStatus), strings.TrimSpace(st.Status)) {
		case "expired":
			return nil, fmt.Errorf("grant_expired")
		case "revoked":
			return nil, fmt.Errorf("grant_revoked")
		case "issuer_revoked":
			return nil, fmt.Errorf("grant_issuer_revoked")
		case "issuer_not_registered":
			return nil, fmt.Errorf("grant_issuer_not_registered")
		case "subject_inactive":
			return nil, fmt.Errorf("grant_subject_inactive")
		}
		return nil, fmt.Errorf("grant_scope_denied")
	}
	if strings.TrimSpace(st.ExpiresAt) == "" {
		return nil, fmt.Errorf("grant_freshness_unavailable")
	}
	if err := checkGrantExpiry(st.ExpiresAt, s.now()); err != nil {
		return nil, err
	}
	if strings.TrimSpace(st.GrantDIDKey) != strings.TrimSpace(req.SessionDIDKey) {
		return nil, fmt.Errorf("grant_session_mismatch")
	}
	if strings.TrimSpace(st.TeamID) != strings.TrimSpace(req.TeamID) {
		return nil, fmt.Errorf("grant_team_mismatch")
	}
	requiredScope := kind + ".send"
	ok := false
	for _, sc := range st.Scopes {
		if strings.TrimSpace(sc) == requiredScope {
			ok = true
		}
	}
	if !ok {
		return nil, fmt.Errorf("grant_scope_denied")
	}
	key, cached, err := s.reserveCustodyReplay(req.GrantID, req.SessionDIDKey, req.Nonce, req.RequestDigest, &awid.PlainMessageSignResponse{})
	if err != nil {
		return nil, err
	}
	if res, _ := cached.(*awid.PlainMessageSignResponse); res != nil {
		return res, nil
	}
	env := req.Envelope
	env.FromDID = s.identity.DID
	env.FromStableID = s.identity.StableID
	env.From = firstNonEmpty(s.identity.Address, s.identity.Handle)
	env.Timestamp = s.now().UTC().Format(time.RFC3339)
	if env.MessageID == "" {
		id, err := awid.GenerateUUID4()
		if err != nil {
			return nil, err
		}
		env.MessageID = id
	}
	sig, err := awid.SignMessage(s.signingKey, &env)
	if err != nil {
		return nil, err
	}
	out := &awid.PlainMessageSignResponse{FromDID: s.identity.DID, SigningKeyID: s.identity.DID, FromStableID: s.identity.StableID, ToDID: env.ToDID, ToStableID: env.ToStableID, MessageID: env.MessageID, Timestamp: env.Timestamp, Signature: sig, SignedPayload: awid.CanonicalJSON(&env)}
	s.cacheCustodyReplayResult(key, out)
	return out, nil
}

func (s *custodyService) evictReplayLocked(cutoff time.Time) {
	for key, at := range s.replayAt {
		if at.Before(cutoff) {
			delete(s.replayAt, key)
			delete(s.replay, key)
			delete(s.results, key)
		}
	}
}

func (s *custodyService) reserveCustodyReplay(grantID, sessionDIDKey, nonce, digest string, resultType any) (string, any, error) {
	key := strings.TrimSpace(grantID) + "|" + strings.TrimSpace(sessionDIDKey) + "|" + strings.TrimSpace(nonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.replay == nil {
		s.replay = map[string]string{}
	}
	if s.replayAt == nil {
		s.replayAt = map[string]time.Time{}
	}
	if s.results == nil {
		s.results = map[string]any{}
	}
	s.evictReplayLocked(s.now().Add(-2 * time.Minute))
	if old, exists := s.replay[key]; exists {
		if old != strings.TrimSpace(digest) {
			return "", nil, fmt.Errorf("replay_detected")
		}
		if res := s.results[key]; res != nil {
			switch resultType.(type) {
			case *awid.E2EEEnvelopeCreateResponse:
				if _, ok := res.(*awid.E2EEEnvelopeCreateResponse); ok {
					return key, res, nil
				}
			case *awid.E2EEUnwrapResponse:
				if _, ok := res.(*awid.E2EEUnwrapResponse); ok {
					return key, res, nil
				}
			case *awid.PlainMessageSignResponse:
				if _, ok := res.(*awid.PlainMessageSignResponse); ok {
					return key, res, nil
				}
			case *awid.AppRequestSignResponse:
				if _, ok := res.(*awid.AppRequestSignResponse); ok {
					return key, res, nil
				}
			}
		}
		return "", nil, fmt.Errorf("replay_detected")
	}
	s.replay[key] = strings.TrimSpace(digest)
	s.replayAt[key] = s.now()
	return key, nil, nil
}

func (s *custodyService) cacheCustodyReplayResult(key string, result any) {
	if strings.TrimSpace(key) == "" || result == nil {
		return
	}
	s.mu.Lock()
	if s.results == nil {
		s.results = map[string]any{}
	}
	s.results[key] = result
	s.mu.Unlock()
}

func runCustodyStatus(ctx context.Context) (custodyStatusReport, error) {
	socket, err := activeCustodySocketPath()
	if err != nil {
		return custodyStatusReport{}, err
	}
	var out custodyStatusReport
	if err := custodyHTTP(ctx, socket, http.MethodGet, "/status", nil, &out); err != nil {
		return custodyUnavailableStatus(socket), nil
	}
	return out, nil
}

func custodyUnavailableStatus(socket string) custodyStatusReport {
	var out custodyStatusReport
	out.Status = "not_running"
	out.SocketPath = socket
	out.Errors = []string{"custody_unavailable"}
	return out
}
func runCustodyStop(ctx context.Context) error {
	socket, err := activeCustodySocketPath()
	if err != nil {
		return err
	}
	return custodyHTTP(ctx, socket, http.MethodPost, "/stop", nil, nil)
}
func activeCustodySocketPath() (string, error) {
	wd := mustGetwd()
	home, err := identityHomeForDir(wd)
	if err != nil {
		return "", err
	}
	if awconfig.IsGrantHome(home.Root) {
		grant, err := awconfig.LoadGrantHome(home.Root)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(grant.Custody.SocketPath) == "" {
			return "", usageError("grant home has no custody.socket_path locator")
		}
		return strings.TrimSpace(grant.Custody.SocketPath), nil
	}
	return awconfig.CustodySocketPath(home.Root), nil
}
func custodyHTTP(ctx context.Context, socket, method, path string, in any, out any) error {
	return custodyHTTPTimeout(ctx, socket, method, path, in, out, 5*time.Second)
}

func custodyHTTPTimeout(ctx context.Context, socket, method, path string, in any, out any, timeout time.Duration) error {
	if err := custodypath.Check(socket); err != nil {
		return err
	}
	var body strings.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = *strings.NewReader(string(b))
	}
	hc := &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	req, err := http.NewRequestWithContext(ctx, method, "http://local"+path, &body)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("custody service returned %d", resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func validateCustodySocketPathLength(path string) error {
	limit := custodySocketPathLimit()
	if limit <= 0 || len(path) < limit {
		return nil
	}
	return usageError("custody_socket_path_too_long: custody socket path is %d bytes, platform limit is %d; use a shorter resident identity home path such as /private/tmp/idtest-custody for local rehearsal", len(path), limit-1)
}

func custodySocketPathLimit() int {
	switch runtime.GOOS {
	case "darwin":
		return 104
	case "linux", "freebsd", "openbsd", "netbsd":
		return 108
	default:
		return 0
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func writeCustodyError(w http.ResponseWriter, code int, e string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e})
}
func mustGetwd() string { wd, _ := os.Getwd(); return wd }

func (s *custodyService) reloadActiveE2EEKey() error {
	if strings.TrimSpace(s.residentHome) == "" {
		if s.e2eeAssertion != nil && s.e2eePrivateKey != nil {
			return nil
		}
		s.e2eeKeyError = "encryption_key_unavailable"
		return fmt.Errorf("sender_key_unavailable")
	}
	assertion, privateKey, err := loadCustodyE2EEKey(s.residentHome, s.identity)
	if err != nil {
		s.e2eeKeyError = "encryption_key_unavailable"
		return fmt.Errorf("sender_key_unavailable")
	}
	s.e2eeAssertion = assertion
	s.e2eePrivateKey = privateKey
	s.e2eeKeyError = ""
	return nil
}

func loadCustodyE2EEKey(identityHome string, identity *awconfig.ResolvedIdentity) (*awid.EncryptionKeyAssertion, *ecdh.PrivateKey, error) {
	statePath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "encryption.yaml")
	if err != nil {
		return nil, nil, err
	}
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		return nil, nil, err
	}
	record := state.ActiveRecord()
	if record == nil {
		return nil, nil, fmt.Errorf("no active encryption key")
	}
	material, err := validateEncryptionRecordPrivateKeyAt("", identityHome, record)
	if err != nil {
		return nil, nil, err
	}
	assertion, err := loadEncryptionAssertionAt("", identityHome, record.AssertionPath)
	if err != nil {
		return nil, nil, err
	}
	if err := validateEncryptionRecordForRead(identity, record, assertion, material); err != nil {
		return nil, nil, err
	}
	privatePath, err := resolveIdentityStoredPath("", identityHome, record.PrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := awid.LoadX25519PrivateKey(privatePath)
	if err != nil {
		return nil, nil, err
	}
	return assertion, privateKey, nil
}

func (s *custodyService) handleCreateE2EEEnvelope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "unsupported_operation", 405)
		return
	}
	var req awid.E2EEEnvelopeCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeCustodyError(w, 400, "bad_request")
		return
	}
	out, err := s.createE2EEEnvelope(r.Context(), &req)
	if err != nil {
		writeCustodyError(w, 403, err.Error())
		return
	}
	writeJSON(w, out)
}

func (s *custodyService) handleUnwrapE2EEMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "unsupported_operation", 405)
		return
	}
	var req awid.E2EEUnwrapRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeCustodyError(w, 400, "bad_request")
		return
	}
	out, err := s.unwrapE2EEMessage(r.Context(), &req)
	if err != nil {
		writeCustodyError(w, 403, err.Error())
		return
	}
	writeJSON(w, out)
}

func (s *custodyService) validateE2EECommon(ctx context.Context, op string, reqFields map[string]string, nonce, timestamp string, requiredScope string) (custodyGrantStatus, error) {
	ts, err := time.Parse(time.RFC3339, strings.TrimSpace(timestamp))
	if err != nil {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if s.now().Sub(ts) > 60*time.Second || ts.Sub(s.now()) > 60*time.Second {
		return custodyGrantStatus{}, fmt.Errorf("bad_timestamp")
	}
	if strings.TrimSpace(reqFields["aud"]) != "local-resident-custody:"+strings.TrimSpace(s.serviceID) {
		return custodyGrantStatus{}, fmt.Errorf("bad_audience")
	}
	if reqFields["subject_did_key"] != s.identity.DID || (reqFields["subject_did_aw"] != "" && reqFields["subject_did_aw"] != s.identity.StableID) {
		return custodyGrantStatus{}, fmt.Errorf("grant_subject_mismatch")
	}
	grantStatus := s.clientDeps(ctx).grantStatus
	if grantStatus == nil {
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := grantStatus(freshCtx, reqFields["grant_id"])
	if err != nil {
		s.reportFailure("check grant freshness", "grant_freshness_unavailable", err)
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	if !st.Active {
		switch firstNonEmpty(strings.TrimSpace(st.EffectiveStatus), strings.TrimSpace(st.Status)) {
		case "expired":
			return st, fmt.Errorf("grant_expired")
		case "revoked":
			return st, fmt.Errorf("grant_revoked")
		case "issuer_revoked":
			return st, fmt.Errorf("grant_issuer_revoked")
		case "issuer_not_registered":
			return st, fmt.Errorf("grant_issuer_not_registered")
		case "subject_inactive":
			return st, fmt.Errorf("grant_subject_inactive")
		}
		return st, fmt.Errorf("grant_scope_denied")
	}
	if strings.TrimSpace(st.ExpiresAt) == "" {
		return st, fmt.Errorf("grant_freshness_unavailable")
	}
	if err := checkGrantExpiry(st.ExpiresAt, s.now()); err != nil {
		return st, err
	}
	if strings.TrimSpace(st.GrantDIDKey) != strings.TrimSpace(reqFields["session_did_key"]) {
		return st, fmt.Errorf("grant_session_mismatch")
	}
	if strings.TrimSpace(st.TeamID) != strings.TrimSpace(reqFields["team_id"]) {
		return st, fmt.Errorf("grant_team_mismatch")
	}
	// An empty requiredScope means authority comes from the resident's
	// mint-time app tool snapshot rather than a server grant scope.
	if requiredScope != "" {
		ok := false
		for _, sc := range st.Scopes {
			if strings.TrimSpace(sc) == requiredScope {
				ok = true
			}
		}
		if !ok {
			return st, fmt.Errorf("grant_scope_denied")
		}
	}
	return st, nil
}

func (s *custodyService) createE2EEEnvelope(ctx context.Context, req *awid.E2EEEnvelopeCreateRequest) (*awid.E2EEEnvelopeCreateResponse, error) {
	if err := awid.VerifyE2EECreateCustodyProof(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Operation) != "create_e2ee_envelope" {
		return nil, fmt.Errorf("unsupported_operation")
	}
	kind := strings.TrimSpace(req.Kind)
	if kind != "mail" && kind != "chat" {
		return nil, fmt.Errorf("message_not_allowed")
	}
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	grant, err := s.validateE2EECommon(ctx, req.Operation, fields, req.Nonce, req.Timestamp, kind+".send")
	if err != nil {
		return nil, err
	}
	replyContinuation := kind == "mail" && req.ReplyToMessageID != "" && len(req.Recipients) == 1 && req.Recipients[0].Address == ""
	if replyContinuation {
		canRead := false
		for _, scope := range grant.Scopes {
			if scope == "mail.read" {
				canRead = true
			}
		}
		if !canRead {
			return nil, fmt.Errorf("grant_scope_denied")
		}
	}
	key, cached, err := s.reserveCustodyReplay(req.GrantID, req.SessionDIDKey, req.Nonce, req.RequestDigest, &awid.E2EEEnvelopeCreateResponse{})
	if err != nil {
		return nil, err
	}
	if out, _ := cached.(*awid.E2EEEnvelopeCreateResponse); out != nil {
		return out, nil
	}
	if s.residentHome != "" {
		maybeRenewIdentityEncryptionAssertion(ctx, "", explicitEncryptionKeyIdentityHome(s.residentHome), os.Stderr)
	}
	if err := s.reloadActiveE2EEKey(); err != nil {
		return nil, err
	}
	recipients := req.Recipients
	if replyContinuation {
		recipient, err := s.storedMailReplyRecipient(ctx, req)
		if err != nil {
			return nil, err
		}
		recipients = []awid.E2EERecipientKey{recipient}
	} else if err := s.verifyE2EERecipients(ctx, recipients); err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	params := awid.E2EEEncryptMessageParams{Kind: kind, Sender: awid.E2EESenderKey{Address: s.identity.Address, DID: s.identity.DID, StableID: s.identity.StableID, TeamID: req.TeamID, EncryptionKey: s.e2eeAssertion, SigningKey: s.signingKey}, Recipients: recipients, Subject: req.Subject, Body: req.Body, MessageID: req.MessageID, ConversationID: req.ConversationID, ReplyToMessageID: req.ReplyToMessageID, CreatedAt: now, DeliveryOrigin: req.DeliveryOrigin, ObservedInboundMode: req.ObservedInboundMode}
	var env *awid.E2EEMessageEnvelope
	var encryptErr error
	if kind == "mail" {
		env, encryptErr = awid.EncryptE2EEMail(params)
	} else {
		env, encryptErr = awid.EncryptE2EEChat(params)
	}
	if encryptErr != nil {
		return nil, fmt.Errorf("envelope_build_failed")
	}
	out := &awid.E2EEEnvelopeCreateResponse{ContentMode: awid.ContentModeEncryptedV2, MessageVersion: awid.E2EEMessageVersion, EncryptedEnvelope: env}
	s.cacheCustodyReplayResult(key, out)
	return out, nil
}

// storedMailReplyRecipient authorizes only a same-service reply to one stored
// source. Worker assertions and participant display metadata cannot grant it.
func (s *custodyService) storedMailReplyRecipient(ctx context.Context, req *awid.E2EEEnvelopeCreateRequest) (awid.E2EERecipientKey, error) {
	refuse := func(reason string) (awid.E2EERecipientKey, error) {
		return awid.E2EERecipientKey{}, fmt.Errorf("%s", reason)
	}
	claimed := req.Recipients[0]
	if req.DeliveryOrigin != "" || req.ObservedInboundMode != "" || claimed.DeliveryOrigin != "" || claimed.InboundMode != "" {
		return refuse("reply_routing_not_allowed")
	}
	readStoredMailReply := s.clientDeps(ctx).readStoredMailReply
	if readStoredMailReply == nil {
		return refuse("stored_message_unavailable")
	}
	message, err := readStoredMailReply(ctx, req.ReplyToMessageID)
	if err != nil {
		return awid.E2EERecipientKey{}, err
	}
	if message == nil || message.MessageID != req.ReplyToMessageID || message.ConversationID != req.ConversationID {
		return refuse("stored_message_mismatch")
	}
	// Federated incoming mail has no local sender actor. This exception must
	// not derive a remote return route from a worker hint or a source envelope.
	if strings.TrimSpace(message.FromAgentID) == "" {
		return refuse("reply_requires_local_sender")
	}
	stored := message.Encrypted
	if stored == nil || stored.Kind != "mail" || stored.MessageID != req.ReplyToMessageID || stored.ConversationID != req.ConversationID {
		return refuse("stored_message_mismatch")
	}
	if err := awid.VerifyE2EEMessageEnvelopeSignature(stored); err != nil {
		return refuse("stored_message_signature_invalid")
	}
	if stored.From.Address != "" {
		return refuse("reply_requires_address_resolution")
	}

	// An archive wrap proves readability, not delivery to the resident. Require
	// an explicit outer recipient and its matching delivery wrap; decryption
	// below authenticates the matching inner recipient set as well.
	delivered := false
	for _, recipient := range stored.Recipients {
		if recipient.DID != s.identity.DID || (recipient.StableID != "" && recipient.StableID != s.identity.StableID) {
			continue
		}
		for _, wrap := range stored.KeyWraps {
			if wrap.WrapPurpose == "delivery" && wrap.WrapID == recipient.WrapID &&
				wrap.RecipientDID == recipient.DID && wrap.RecipientStableID == recipient.StableID &&
				wrap.RecipientAddress == recipient.Address && wrap.RecipientEncryptionKeyID == recipient.EncryptionKeyID {
				delivered = true
			}
		}
	}
	if !delivered {
		return refuse("not_a_delivery_recipient")
	}
	if stored.From.DID == s.identity.DID || (s.identity.StableID != "" && stored.From.StableID == s.identity.StableID) {
		return refuse("reply_source_is_resident")
	}
	decryptIdentity, err := s.decryptIdentityForE2EEEnvelope(stored)
	if err != nil {
		return awid.E2EERecipientKey{}, err
	}
	plain, err := awid.DecryptE2EEMessage(stored, decryptIdentity)
	if err != nil {
		return refuse("decrypt_failed")
	}
	if plain.Kind != "mail" || plain.MessageID != req.ReplyToMessageID || plain.ConversationID != req.ConversationID {
		return refuse("stored_message_mismatch")
	}
	derived, err := awid.E2EERecipientFromEnvelopeSender(stored, s.now())
	if err != nil {
		return awid.E2EERecipientKey{}, fmt.Errorf("source sender key is missing, expired or invalid; ask them to send a new message: %w", err)
	}
	claimedJSON, err := awid.CanonicalJSONValue(claimed)
	if err != nil {
		return refuse("recipient_binding_mismatch")
	}
	derivedJSON, err := awid.CanonicalJSONValue(derived)
	if err != nil || claimedJSON != derivedJSON {
		return refuse("recipient_binding_mismatch")
	}
	return derived, nil
}

func (s *custodyService) verifyE2EERecipients(ctx context.Context, recipients []awid.E2EERecipientKey) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipient_binding_unavailable")
	}
	resolveRecipient := s.clientDeps(ctx).resolveRecipient
	if resolveRecipient == nil {
		return fmt.Errorf("recipient_binding_unavailable")
	}
	for _, recipient := range recipients {
		stableID := strings.TrimSpace(recipient.StableID)
		if stableID == "" || !strings.HasPrefix(stableID, "did:aw:") {
			continue
		}
		// The registry resolver refuses bare did:aw first contact, so resolve
		// through the recipient's routable address, as the root client's
		// e2eeGlobalRecipientFromAgent does, and bind the result back to the
		// claimed stable id. A global recipient without an address fails closed.
		address := strings.TrimSpace(recipient.Address)
		if address == "" {
			return fmt.Errorf("recipient_binding_unavailable")
		}
		resolved, err := resolveRecipient(ctx, address)
		if err != nil {
			s.reportFailure("resolve recipient", "recipient_binding_unavailable", err)
			return fmt.Errorf("recipient_binding_unavailable")
		}
		if resolved == nil {
			return fmt.Errorf("recipient_binding_unavailable")
		}
		if strings.TrimSpace(resolved.DID) != strings.TrimSpace(recipient.DID) || strings.TrimSpace(resolved.StableID) != stableID {
			return fmt.Errorf("recipient_binding_mismatch")
		}
		if resolved.EncryptionKey == nil || strings.TrimSpace(resolved.EncryptionKey.EncryptionKeyID) != strings.TrimSpace(recipient.EncryptionKey.EncryptionKeyID) {
			return fmt.Errorf("recipient_binding_mismatch")
		}
	}
	return nil
}

func (s *custodyService) storedMailReplyViaClient(ctx context.Context, client *aweb.Client, messageID string) (*awid.InboxMessage, error) {
	if client == nil {
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var message awid.InboxMessage
	if err := client.Get(readCtx, "/v1/messages/"+url.PathEscape(messageID), &message); err != nil {
		s.reportFailure("read stored message", "stored_message_unavailable", err)
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	return &message, nil
}

func (s *custodyService) storedE2EEEnvelopeViaClient(ctx context.Context, client *aweb.Client, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
	if client == nil {
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	kind = strings.TrimSpace(kind)
	messageID = strings.TrimSpace(messageID)
	conversationID = strings.TrimSpace(conversationID)
	if messageID == "" {
		return nil, fmt.Errorf("bad_request")
	}
	// Custody checks retain their short freshness/read budget within the calling request.
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch kind {
	case "mail":
		var msg awid.InboxMessage
		if err := client.Get(readCtx, "/v1/messages/"+url.PathEscape(messageID), &msg); err != nil {
			s.reportFailure("read stored message", "stored_message_unavailable", err)
			return nil, fmt.Errorf("stored_message_unavailable")
		}
		if strings.TrimSpace(msg.MessageID) != messageID || (conversationID != "" && strings.TrimSpace(msg.ConversationID) != conversationID) {
			return nil, fmt.Errorf("stored_message_mismatch")
		}
		if msg.Encrypted == nil || (msg.ContentMode != "" && msg.ContentMode != awid.ContentModeEncryptedV2) || (msg.MessageVersion != 0 && msg.MessageVersion != awid.E2EEMessageVersion) {
			return nil, fmt.Errorf("stored_message_mismatch")
		}
		return msg.Encrypted, nil
	case "chat":
		if conversationID == "" {
			return nil, fmt.Errorf("bad_request")
		}
		var out awid.ChatHistoryResponse
		path := "/v1/chat/sessions/" + url.PathEscape(conversationID) + "/messages?message_id=" + url.QueryEscape(messageID)
		if err := client.Get(readCtx, path, &out); err != nil {
			s.reportFailure("read stored message", "stored_message_unavailable", err)
			return nil, fmt.Errorf("stored_message_unavailable")
		}
		if len(out.Messages) != 1 {
			return nil, fmt.Errorf("stored_message_unavailable")
		}
		msg := out.Messages[0]
		if strings.TrimSpace(msg.MessageID) != messageID || strings.TrimSpace(msg.ConversationID) != conversationID {
			return nil, fmt.Errorf("stored_message_mismatch")
		}
		if msg.Encrypted == nil || (msg.ContentMode != "" && msg.ContentMode != awid.ContentModeEncryptedV2) || (msg.MessageVersion != 0 && msg.MessageVersion != awid.E2EEMessageVersion) {
			return nil, fmt.Errorf("stored_message_mismatch")
		}
		return msg.Encrypted, nil
	default:
		return nil, fmt.Errorf("message_not_allowed")
	}
}

func e2eeEnvelopesEqual(a, b *awid.E2EEMessageEnvelope) bool {
	left, err := awid.CanonicalJSONValue(a)
	if err != nil {
		return false
	}
	right, err := awid.CanonicalJSONValue(b)
	if err != nil {
		return false
	}
	return left == right
}

func custodyIdentityFieldMatches(wrapValue, localValue string) bool {
	wrapValue = strings.TrimSpace(wrapValue)
	localValue = strings.TrimSpace(localValue)
	return wrapValue == "" || (localValue != "" && wrapValue == localValue)
}

func (s *custodyService) requiredE2EERecipientKeyID(envelope *awid.E2EEMessageEnvelope) (string, error) {
	if envelope == nil {
		return "", fmt.Errorf("bad_request")
	}
	for i := range envelope.KeyWraps {
		wrap := envelope.KeyWraps[i]
		if !custodyIdentityFieldMatches(wrap.RecipientDID, s.identity.DID) {
			continue
		}
		if !custodyIdentityFieldMatches(wrap.RecipientStableID, s.identity.StableID) {
			continue
		}
		if !custodyIdentityFieldMatches(wrap.RecipientAddress, s.identity.Address) {
			continue
		}
		keyID := strings.TrimSpace(wrap.RecipientEncryptionKeyID)
		if keyID == "" {
			return "", fmt.Errorf("recipient_key_unavailable")
		}
		return keyID, nil
	}
	return "", fmt.Errorf("not_a_recipient")
}

func (s *custodyService) decryptIdentityForE2EEEnvelope(envelope *awid.E2EEMessageEnvelope) (awid.E2EEDecryptIdentity, error) {
	keyID, err := s.requiredE2EERecipientKeyID(envelope)
	if err != nil {
		return awid.E2EEDecryptIdentity{}, err
	}
	activeKeyID := ""
	if s.e2eeAssertion != nil {
		activeKeyID = strings.TrimSpace(s.e2eeAssertion.EncryptionKeyID)
	}
	if keyID == activeKeyID && s.e2eePrivateKey != nil {
		return awid.E2EEDecryptIdentity{Address: s.identity.Address, DID: s.identity.DID, StableID: s.identity.StableID, EncryptionKeyID: keyID, PrivateKey: s.e2eePrivateKey}, nil
	}
	statePath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: s.residentHome}, "encryption.yaml")
	if err != nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	state, err := awconfig.LoadEncryptionKeyStateFrom(statePath)
	if err != nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	record := state.RecordForKeyID(keyID)
	if record == nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	if _, err := validateEncryptionRecordPrivateKeyAt("", s.residentHome, record); err != nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	privatePath, err := resolveIdentityStoredPath("", s.residentHome, record.PrivateKeyPath)
	if err != nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	privateKey, err := awid.LoadX25519PrivateKey(privatePath)
	if err != nil {
		return awid.E2EEDecryptIdentity{}, fmt.Errorf("archived_key_unavailable")
	}
	return awid.E2EEDecryptIdentity{Address: s.identity.Address, DID: s.identity.DID, StableID: s.identity.StableID, EncryptionKeyID: keyID, PrivateKey: privateKey}, nil
}

func (s *custodyService) unwrapE2EEMessage(ctx context.Context, req *awid.E2EEUnwrapRequest) (*awid.E2EEUnwrapResponse, error) {
	if err := awid.VerifyE2EEUnwrapCustodyProof(req); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Operation) != "unwrap_e2ee_message" {
		return nil, fmt.Errorf("unsupported_operation")
	}
	kind := strings.TrimSpace(req.Kind)
	if kind != "mail" && kind != "chat" {
		return nil, fmt.Errorf("message_not_allowed")
	}
	if strings.TrimSpace(req.OutputMode) != "" && strings.TrimSpace(req.OutputMode) != "plaintext" {
		return nil, fmt.Errorf("output_mode_unsupported")
	}
	if req.Envelope == nil {
		return nil, fmt.Errorf("bad_request")
	}
	if req.Envelope.Kind != kind || req.Envelope.MessageID != strings.TrimSpace(req.MessageID) || req.Envelope.ConversationID != strings.TrimSpace(req.ConversationID) {
		return nil, fmt.Errorf("message_binding_mismatch")
	}
	fields := map[string]string{"grant_id": req.GrantID, "session_did_key": req.SessionDIDKey, "team_id": req.TeamID, "subject_did_aw": req.SubjectDIDAW, "subject_did_key": req.SubjectDIDKey, "aud": req.Audience}
	if _, err := s.validateE2EECommon(ctx, req.Operation, fields, req.Nonce, req.Timestamp, kind+".read"); err != nil {
		return nil, err
	}
	key, cached, err := s.reserveCustodyReplay(req.GrantID, req.SessionDIDKey, req.Nonce, req.RequestDigest, &awid.E2EEUnwrapResponse{})
	if err != nil {
		return nil, err
	}
	if out, _ := cached.(*awid.E2EEUnwrapResponse); out != nil {
		return out, nil
	}
	readStoredEnvelope := s.clientDeps(ctx).readStoredEnvelope
	if readStoredEnvelope == nil {
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	storedEnvelope, err := readStoredEnvelope(ctx, kind, strings.TrimSpace(req.MessageID), strings.TrimSpace(req.ConversationID))
	if err != nil {
		return nil, err
	}
	if !e2eeEnvelopesEqual(storedEnvelope, req.Envelope) {
		return nil, fmt.Errorf("stored_message_mismatch")
	}
	decryptIdentity, err := s.decryptIdentityForE2EEEnvelope(storedEnvelope)
	if err != nil {
		return nil, err
	}
	plain, err := awid.DecryptE2EEMessage(storedEnvelope, decryptIdentity)
	if err != nil {
		return nil, fmt.Errorf("decrypt_failed")
	}
	out := &awid.E2EEUnwrapResponse{Kind: plain.Kind, MessageID: plain.MessageID, ConversationID: plain.ConversationID, CreatedAt: plain.CreatedAt, From: plain.From, Recipients: plain.Recipients, Subject: plain.Subject, Body: plain.Body, Attachments: plain.Attachments}
	s.cacheCustodyReplayResult(key, out)
	return out, nil
}

// Custody owns the resident signing key. Grant seats never receive that key or
// sign assertions themselves; renewal continues even when no grant sends mail.
func (s *custodyService) renewEncryptionAssertions(ctx context.Context) {
	if s.residentHome == "" {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		maybeRenewIdentityEncryptionAssertion(ctx, "", explicitEncryptionKeyIdentityHome(s.residentHome), os.Stderr)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
