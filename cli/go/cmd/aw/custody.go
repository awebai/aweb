package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
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
		fmt.Println(string(b))
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
	Teams     []map[string]any `json:"teams"`
	Keys      map[string]any   `json:"keys"`
	Ops       []string         `json:"ops"`
	Freshness map[string]any   `json:"freshness"`
	Errors    []string         `json:"errors,omitempty"`
}

type custodyGrantStatus struct {
	Active                                                  bool
	Scopes                                                  []string
	GrantDIDKey, TeamID, Status, EffectiveStatus, ExpiresAt string
	LastCheckedAt                                           string
}

type custodyService struct {
	residentHome       string
	socketPath         string
	identity           *awconfig.ResolvedIdentity
	signingKey         ed25519.PrivateKey
	e2eeAssertion      *awid.EncryptionKeyAssertion
	e2eePrivateKey     *ecdh.PrivateKey
	client             *aweb.Client
	grantStatus        func(context.Context, string) (custodyGrantStatus, error)
	readinessCheck     func(context.Context) (string, error)
	readStoredEnvelope func(context.Context, string, string, string) (*awid.E2EEMessageEnvelope, error)
	resolveRecipient   func(context.Context, string) (*awid.ResolvedIdentity, error)
	e2eeKeyError       string
	selectedTeam       string
	appDeniedOrigins   []string
	serviceID          string
	now                func() time.Time
	mu                 sync.Mutex
	replay             map[string]string
	replayAt           map[string]time.Time
	results            map[string]any
	server             *http.Server
}

func newCustodyService(home awconfig.IdentityHome) (*custodyService, error) {
	wd, _ := os.Getwd()
	if awconfig.IsGrantHome(home.Root) {
		return nil, usageError("custody serve requires the resident identity home, not a grant home")
	}
	identity, err := awconfig.ResolveIdentityFromHome(wd, home.Root)
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
	client, sel, clientErr := resolveClientSelectionAtIdentityHome(wd, home)
	serviceID, _ := awid.GenerateUUID4()
	svc := &custodyService{residentHome: home.Root, socketPath: awconfig.CustodySocketPath(home.Root), identity: identity, signingKey: key, e2eeAssertion: e2eeAssertion, e2eePrivateKey: e2eePrivateKey, e2eeKeyError: e2eeKeyError, serviceID: serviceID, now: time.Now, replay: map[string]string{}, replayAt: map[string]time.Time{}, results: map[string]any{}}
	if sel != nil {
		svc.selectedTeam = strings.TrimSpace(sel.TeamID)
		svc.appDeniedOrigins = grantAppDeniedOrigins(sel.BaseURL, sel.RegistryURL)
	}
	if clientErr == nil && client != nil {
		svc.client = client
		svc.grantStatus = grantStatusViaClient(client)
		svc.readStoredEnvelope = svc.storedE2EEEnvelopeViaClient
		svc.resolveRecipient = client.ResolveIdentity
		svc.readinessCheck = func(ctx context.Context) (string, error) {
			return client.ProbeIdentityGrantStatus(ctx)
		}
	}
	return svc, nil
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

func (s *custodyService) serve(ctx context.Context) error {
	if err := validateCustodySocketPathLength(s.socketPath); err != nil {
		return err
	}
	if strings.TrimSpace(s.serviceID) == "" {
		id, _ := awid.GenerateUUID4()
		s.serviceID = id
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
	mux.HandleFunc("/sign_plain_message", s.handleSignPlainMessage)
	mux.HandleFunc("/create_e2ee_envelope", s.handleCreateE2EEEnvelope)
	mux.HandleFunc("/unwrap_e2ee_message", s.handleUnwrapE2EEMessage)
	mux.HandleFunc("/sign_app_request", s.handleSignAppRequest)
	mux.HandleFunc("/stop", s.handleStop)
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
	grantStatusReady := s.grantStatus != nil
	lastCheckedAt := any(nil)
	if s.readinessCheck != nil {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		checkedAt, err := s.readinessCheck(checkCtx)
		cancel()
		if err != nil {
			grantStatusReady = false
			errs = append(errs, "grant_status_unavailable")
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
	out.Keys = map[string]any{"signing_ready": s.signingKey != nil && grantStatusReady, "encryption_ready": s.e2eeAssertion != nil && s.e2eePrivateKey != nil && grantStatusReady, "encryption_key_id": encryptionKeyID}
	out.Ops = []string{"status.v1", "sign_plain_message.v1", "sign_app_request.v1"}
	if s.e2eeAssertion != nil && s.e2eePrivateKey != nil {
		out.Ops = append(out.Ops, "create_e2ee_envelope.v1", "unwrap_e2ee_message.v1")
	}
	out.Freshness = map[string]any{"source": "identity-grants", "last_checked_at": lastCheckedAt, "max_cache_age_seconds": 30}
	out.Errors = errs
	return out
}
func (s *custodyService) teamReadiness(grantStatusReady bool) ([]map[string]any, []string) {
	if strings.TrimSpace(s.residentHome) == "" {
		return nil, nil
	}
	certs, err := awconfig.ListTeamCertificatesFromIdentityHome(s.residentHome)
	if err != nil {
		return nil, []string{"team_certificates_unavailable"}
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
	if s.grantStatus == nil {
		return nil, fmt.Errorf("grant_freshness_unavailable")
	}
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.grantStatus(freshCtx, req.GrantID)
	if err != nil {
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
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(st.ExpiresAt))
	if err != nil {
		return nil, fmt.Errorf("grant_freshness_unavailable")
	}
	if !s.now().Before(expiresAt) {
		return nil, fmt.Errorf("grant_expired")
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
	if err := validateEncryptionRecordAssertion(identity, record, assertion, material); err != nil {
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
	if s.grantStatus == nil {
		return custodyGrantStatus{}, fmt.Errorf("grant_freshness_unavailable")
	}
	freshCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := s.grantStatus(freshCtx, reqFields["grant_id"])
	if err != nil {
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
	expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(st.ExpiresAt))
	if err != nil {
		return st, fmt.Errorf("grant_freshness_unavailable")
	}
	if !s.now().Before(expiresAt) {
		return st, fmt.Errorf("grant_expired")
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
	if _, err := s.validateE2EECommon(ctx, req.Operation, fields, req.Nonce, req.Timestamp, kind+".send"); err != nil {
		return nil, err
	}
	key, cached, err := s.reserveCustodyReplay(req.GrantID, req.SessionDIDKey, req.Nonce, req.RequestDigest, &awid.E2EEEnvelopeCreateResponse{})
	if err != nil {
		return nil, err
	}
	if out, _ := cached.(*awid.E2EEEnvelopeCreateResponse); out != nil {
		return out, nil
	}
	if err := s.reloadActiveE2EEKey(); err != nil {
		return nil, err
	}
	if err := s.verifyE2EERecipients(ctx, req.Recipients); err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	params := awid.E2EEEncryptMessageParams{Kind: kind, Sender: awid.E2EESenderKey{Address: s.identity.Address, DID: s.identity.DID, StableID: s.identity.StableID, TeamID: req.TeamID, EncryptionKey: s.e2eeAssertion, SigningKey: s.signingKey}, Recipients: req.Recipients, Subject: req.Subject, Body: req.Body, MessageID: req.MessageID, ConversationID: req.ConversationID, ReplyToMessageID: req.ReplyToMessageID, CreatedAt: now, DeliveryOrigin: req.DeliveryOrigin, ObservedInboundMode: req.ObservedInboundMode}
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

func (s *custodyService) verifyE2EERecipients(ctx context.Context, recipients []awid.E2EERecipientKey) error {
	if len(recipients) == 0 {
		return fmt.Errorf("recipient_binding_unavailable")
	}
	if s.resolveRecipient == nil {
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
		resolved, err := s.resolveRecipient(ctx, address)
		if err != nil || resolved == nil {
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

func (s *custodyService) storedE2EEEnvelopeViaClient(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
	if s.client == nil {
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	kind = strings.TrimSpace(kind)
	messageID = strings.TrimSpace(messageID)
	conversationID = strings.TrimSpace(conversationID)
	if messageID == "" {
		return nil, fmt.Errorf("bad_request")
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	switch kind {
	case "mail":
		var msg awid.InboxMessage
		if err := s.client.Get(readCtx, "/v1/messages/"+url.PathEscape(messageID), &msg); err != nil {
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
		if err := s.client.Get(readCtx, path, &out); err != nil {
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
	if s.readStoredEnvelope == nil {
		return nil, fmt.Errorf("stored_message_unavailable")
	}
	storedEnvelope, err := s.readStoredEnvelope(ctx, kind, strings.TrimSpace(req.MessageID), strings.TrimSpace(req.ConversationID))
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
	out := &awid.E2EEUnwrapResponse{Kind: plain.Kind, MessageID: plain.MessageID, ConversationID: plain.ConversationID, Subject: plain.Subject, Body: plain.Body}
	s.cacheCustodyReplayResult(key, out)
	return out, nil
}
