package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
	residentHome   string
	socketPath     string
	identity       *awconfig.ResolvedIdentity
	signingKey     ed25519.PrivateKey
	grantStatus    func(context.Context, string) (custodyGrantStatus, error)
	readinessCheck func(context.Context) (string, error)
	selectedTeam   string
	serviceID      string
	now            func() time.Time
	mu             sync.Mutex
	replay         map[string]string
	results        map[string]*awid.PlainMessageSignResponse
	server         *http.Server
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
	client, sel, clientErr := resolveClientSelectionAtIdentityHome(wd, home)
	serviceID, _ := awid.GenerateUUID4()
	svc := &custodyService{residentHome: home.Root, socketPath: awconfig.CustodySocketPath(home.Root), identity: identity, signingKey: key, serviceID: serviceID, now: time.Now, replay: map[string]string{}, results: map[string]*awid.PlainMessageSignResponse{}}
	if sel != nil {
		svc.selectedTeam = strings.TrimSpace(sel.TeamID)
	}
	if clientErr == nil && client != nil {
		svc.grantStatus = grantStatusViaClient(client)
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
		if effective == "" {
			effective = strings.TrimSpace(g.Status)
		}
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
	if strings.TrimSpace(s.serviceID) == "" {
		id, _ := awid.GenerateUUID4()
		s.serviceID = id
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(s.socketPath); err == nil {
		if err := custodyHTTP(ctx, s.socketPath, http.MethodGet, "/status", nil, &custodyStatusReport{}); err == nil {
			return usageError("custody service already running at %s", s.socketPath)
		}
		if err := os.Remove(s.socketPath); err != nil {
			return fmt.Errorf("remove stale custody socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.socketPath, 0o600); err != nil {
		_ = ln.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/sign_plain_message", s.handleSignPlainMessage)
	mux.HandleFunc("/stop", s.handleStop)
	s.server = &http.Server{Handler: mux}
	go func() { <-ctx.Done(); _ = s.server.Close() }()
	err = s.server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
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
	teamID := strings.TrimSpace(s.selectedTeam)
	if teamID == "" {
		teamID = "unknown"
	}
	out.Teams = []map[string]any{{"team_id": teamID, "ready": s.signingKey != nil && grantStatusReady, "certificate_present": grantStatusReady, "grant_status_endpoint_ready": grantStatusReady}}
	out.Keys = map[string]any{"signing_ready": s.signingKey != nil && grantStatusReady, "encryption_ready": false, "encryption_key_id": ""}
	out.Ops = []string{"status.v1", "sign_plain_message.v1"}
	out.Freshness = map[string]any{"source": "identity-grants", "last_checked_at": lastCheckedAt, "max_cache_age_seconds": 30}
	out.Errors = errs
	return out
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
	if strings.TrimSpace(st.ExpiresAt) != "" {
		if expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(st.ExpiresAt)); err == nil && !s.now().Before(expiresAt) {
			return nil, fmt.Errorf("grant_expired")
		}
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
	key := strings.TrimSpace(req.GrantID) + "|" + strings.TrimSpace(req.SessionDIDKey) + "|" + strings.TrimSpace(req.Nonce)
	s.mu.Lock()
	if old, exists := s.replay[key]; exists {
		if old != req.RequestDigest {
			s.mu.Unlock()
			return nil, fmt.Errorf("replay_detected")
		}
		if res := s.results[key]; res != nil {
			s.mu.Unlock()
			return res, nil
		}
		s.mu.Unlock()
		return nil, fmt.Errorf("replay_detected")
	}
	s.replay[key] = req.RequestDigest
	s.mu.Unlock()
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
	s.mu.Lock()
	s.results[key] = out
	s.mu.Unlock()
	return out, nil
}

func runCustodyStatus(ctx context.Context) (custodyStatusReport, error) {
	socket, err := activeCustodySocketPath()
	if err != nil {
		return custodyStatusReport{}, err
	}
	var out custodyStatusReport
	if err := custodyHTTP(ctx, socket, http.MethodGet, "/status", nil, &out); err != nil {
		out.Status = "not_running"
		out.SocketPath = socket
		out.Errors = []string{err.Error()}
		return out, nil
	}
	return out, nil
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
	var body strings.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = *strings.NewReader(string(b))
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
