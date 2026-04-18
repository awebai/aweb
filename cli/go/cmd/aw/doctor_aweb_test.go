package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/awebai/aw/awconfig"
)

type doctorAwebServer struct {
	Server          *httptest.Server
	Hits            atomic.Int32
	DestructiveHits atomic.Int32
	APIKeyAuthHits  atomic.Int32
	TeamAuthHits    atomic.Int32
	MessageAuthHits atomic.Int32

	OmitWorkspace  bool
	Deleted        bool
	AliasMismatch  bool
	ClaimsMismatch bool
	Unauthorized   bool
	Unavailable    bool
	VersionHeader  string
	RolesTeamID    string
	WorkspaceError string
}

func newDoctorAwebServer(t *testing.T, cfg *doctorAwebServer) *doctorAwebServer {
	t.Helper()
	if cfg == nil {
		cfg = &doctorAwebServer{}
	}
	cfg.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.Hits.Add(1)
		if strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer ") {
			cfg.APIKeyAuthHits.Add(1)
		}
		if r.Method != http.MethodGet {
			cfg.DestructiveHits.Add(1)
			http.Error(w, "doctor must be read-only", http.StatusMethodNotAllowed)
			return
		}
		if cfg.Unavailable {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/v1/agents/heartbeat":
			w.Header().Set("Content-Type", "application/json")
			if strings.TrimSpace(cfg.VersionHeader) != "" {
				w.Header().Set("X-Latest-Client-Version", cfg.VersionHeader)
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/v1/workspaces/team":
			if !cfg.requireTeamAuth(w, r) {
				return
			}
			if strings.TrimSpace(cfg.WorkspaceError) != "" {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, cfg.WorkspaceError, http.StatusInternalServerError)
				return
			}
			workspaces := []map[string]any{}
			if !cfg.OmitWorkspace {
				alias := "mia"
				if cfg.AliasMismatch {
					alias = "other"
				}
				row := map[string]any{
					"workspace_id":   "ws-ephemeral",
					"alias":          alias,
					"agent_lifetime": "ephemeral",
					"status":         "active",
					"last_seen":      "2026-04-18T00:00:00Z",
					"claims": []map[string]any{{
						"task_ref":   "AWEB-08",
						"title":      "Doctor checks",
						"claimed_at": "2026-04-18T00:00:00Z",
					}},
				}
				if cfg.Deleted {
					row["deleted_at"] = "2026-04-18T00:01:00Z"
					row["status"] = "deleted"
				}
				workspaces = append(workspaces, row)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": workspaces, "has_more": false})
		case "/v1/status":
			if !cfg.requireTeamAuth(w, r) {
				return
			}
			claims := []map[string]any{{
				"task_ref":       "AWEB-08",
				"workspace_id":   "ws-ephemeral",
				"alias":          "mia",
				"claimed_at":     "2026-04-18T00:00:00Z",
				"claimant_count": 1,
			}}
			if cfg.ClaimsMismatch {
				claims = nil
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"workspace_id": "ws-ephemeral", "workspace_count": 1},
				"agents":              []any{},
				"claims":              claims,
				"conflicts":           []any{},
				"locks":               []any{},
				"escalations_pending": 0,
				"timestamp":           "2026-04-18T00:00:00Z",
			})
		case "/v1/roles/active":
			if !cfg.requireTeamAuth(w, r) {
				return
			}
			teamID := "backend:example.com"
			if strings.TrimSpace(cfg.RolesTeamID) != "" {
				teamID = cfg.RolesTeamID
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id":        "roles-1",
				"active_team_roles_id": "roles-1",
				"team_id":              teamID,
				"version":              1,
				"updated_at":           "2026-04-18T00:00:00Z",
				"roles":                map[string]any{},
			})
		case "/v1/messages/inbox":
			if !cfg.requireMessageAuth(w, r) {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}})
		case "/v1/chat/pending":
			if !cfg.requireMessageAuth(w, r) {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"pending": []any{}, "messages_waiting": 0})
		case "/v1/chat/sessions":
			if !cfg.requireMessageAuth(w, r) {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"sessions": []any{}})
		case "/v1/contacts":
			if !cfg.requireMessageAuth(w, r) {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"contacts": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cfg.Server.Close)
	return cfg
}

func (s *doctorAwebServer) requireTeamAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.Unauthorized {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if !strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "DIDKey ") || strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
		http.Error(w, "missing team cert auth", http.StatusUnauthorized)
		return false
	}
	s.TeamAuthHits.Add(1)
	return true
}

func (s *doctorAwebServer) requireMessageAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.Unauthorized {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if !strings.HasPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "DIDKey ") {
		http.Error(w, "missing DIDKey auth", http.StatusUnauthorized)
		return false
	}
	if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) != "" {
		http.Error(w, "messaging doctor should use identity auth", http.StatusUnauthorized)
		return false
	}
	s.MessageAuthHits.Add(1)
	return true
}

func TestAwDoctorAwebOfflineDoesNotContactServer(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--offline", "--json")
	if err != nil {
		t.Fatalf("doctor offline failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckServerReachable, doctorStatusUnknown)
	if check.Detail["reason"] != "offline_mode" {
		t.Fatalf("offline reason=%v", check.Detail["reason"])
	}
	if server.Hits.Load() != 0 {
		t.Fatalf("offline contacted server %d times", server.Hits.Load())
	}
}

func TestAwDoctorAwebAutoDoesNotContactServer(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--json")
	if err != nil {
		t.Fatalf("doctor auto failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckServerReachable, doctorStatusUnknown)
	if check.Detail["reason"] != "auto_mode" {
		t.Fatalf("auto reason=%v", check.Detail["reason"])
	}
	if server.Hits.Load() != 0 {
		t.Fatalf("auto contacted server %d times", server.Hits.Load())
	}
}

func TestAwDoctorAwebOnlineHappyPath(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)
	before := readWorkspaceYAMLForDoctorTest(t, tmp)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	for _, id := range []string{
		doctorCheckServerReachable,
		doctorCheckWorkspaceTeamRead,
		doctorCheckWorkspaceCurrentRow,
		doctorCheckWorkspaceIdentityMatch,
		doctorCheckWorkspaceDeletedState,
		doctorCheckWorkspacePresence,
		doctorCheckCoordinationStatusRead,
		doctorCheckCoordinationClaims,
		doctorCheckCoordinationCoherence,
		doctorCheckTeamRolesRead,
		doctorCheckTeamMembershipAuth,
		doctorCheckMessagingInboxRead,
		doctorCheckMessagingChatPending,
		doctorCheckMessagingChatSessions,
		doctorCheckMessagingContactsRead,
	} {
		requireDoctorCheckStatus(t, got, id, doctorStatusOK)
	}
	policy := requireDoctorCheckStatus(t, got, doctorCheckMessagingPolicyRead, doctorStatusUnknown)
	if policy.Detail["reason"] != "no_read_endpoint" {
		t.Fatalf("policy_read reason=%v", policy.Detail["reason"])
	}
	if server.DestructiveHits.Load() != 0 {
		t.Fatalf("doctor made destructive requests: %d", server.DestructiveHits.Load())
	}
	if server.APIKeyAuthHits.Load() != 0 {
		t.Fatalf("doctor used API-key authorization")
	}
	if server.TeamAuthHits.Load() == 0 || server.MessageAuthHits.Load() == 0 {
		t.Fatalf("expected team and messaging auth hits, team=%d messaging=%d", server.TeamAuthHits.Load(), server.MessageAuthHits.Load())
	}
	after := readWorkspaceYAMLForDoctorTest(t, tmp)
	if before != after {
		t.Fatalf("doctor rewrote workspace.yaml\nbefore:\n%s\nafter:\n%s", before, after)
	}
	assertNoDuplicateDoctorChecks(t, got)
}

func TestAwDoctorAwebVersionHeaderReported(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{VersionHeader: "v9.8.7"})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckServerVersion, doctorStatusOK)
	if check.Detail["present"] != true {
		t.Fatalf("version header present=%v", check.Detail["present"])
	}
	if check.Detail["latest_client_version"] != "v9.8.7" {
		t.Fatalf("latest_client_version=%v", check.Detail["latest_client_version"])
	}
}

func TestAwDoctorAwebURLConfusionHostedBase(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Fatalf("unexpected method %s %s", r.Method, r.URL.Path)
		}
		switch r.URL.Path {
		case "/v1/agents/heartbeat":
			w.Header().Set("Content-Type", "text/html")
			http.NotFound(w, r)
		case "/api/v1/agents/heartbeat":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.URL)
	before := readWorkspaceYAMLForDoctorTest(t, tmp)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckServerAwebURLRuntime, doctorStatusWarn)
	if check.Detail["recommended_aweb_url"] != server.URL+"/api" {
		t.Fatalf("recommended_aweb_url=%v", check.Detail["recommended_aweb_url"])
	}
	if before != readWorkspaceYAMLForDoctorTest(t, tmp) {
		t.Fatalf("doctor rewrote workspace.yaml for URL confusion")
	}
	if hits.Load() == 0 {
		t.Fatalf("expected online URL probe hits")
	}

	local := localRuntimePathCheck("https://app.aweb.ai")
	if local.Status != doctorStatusWarn || local.Detail["recommended_aweb_url"] != "https://app.aweb.ai/api" {
		t.Fatalf("hosted local classification=%#v", local)
	}
}

func TestAwDoctorWorkspaceMissingServerRowFails(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{OmitWorkspace: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceCurrentRow, doctorStatusFail)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceIdentityMatch, doctorStatusBlocked)
	if server.DestructiveHits.Load() != 0 {
		t.Fatalf("doctor made destructive requests: %d", server.DestructiveHits.Load())
	}
}

func TestAwDoctorWorkspaceDeletedFails(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{Deleted: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceDeletedState, doctorStatusFail)
	if server.DestructiveHits.Load() != 0 {
		t.Fatalf("doctor made destructive requests: %d", server.DestructiveHits.Load())
	}
}

func TestAwDoctorWorkspaceIdentityMismatchFails(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{AliasMismatch: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceIdentityMatch, doctorStatusFail)
}

func TestAwDoctorCoordinationClaimsIncoherentWarns(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{ClaimsMismatch: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckCoordinationCoherence, doctorStatusWarn)
}

func TestAwDoctorTeamMembershipAuthorizedDetectsTeamMismatch(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{RolesTeamID: "backend:other.example.com"})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "team", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor team failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckTeamMembershipAuth, doctorStatusFail)
	if check.Detail["local_team_id"] != "backend:example.com" {
		t.Fatalf("local_team_id=%v", check.Detail["local_team_id"])
	}
	if check.Detail["server_team_id"] != "backend:other.example.com" {
		t.Fatalf("server_team_id=%v", check.Detail["server_team_id"])
	}
}

func TestAwDoctorAwebUnauthorizedBlocked(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{Unauthorized: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceTeamRead, doctorStatusBlocked)
	requireDoctorCheckStatus(t, got, doctorCheckTeamRolesRead, doctorStatusBlocked)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingInboxRead, doctorStatusBlocked)
}

func TestAwDoctorAwebUnavailableUnknown(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{Unavailable: true})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckServerReachable, doctorStatusUnknown)
}

func TestAwDoctorAwebHTTPErrorIncludesRequestIDOnly(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, &doctorAwebServer{WorkspaceError: `{"request_id":"req-123","detail":{"secret":"do-not-include"}}`})
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckWorkspaceTeamRead, doctorStatusUnknown)
	if check.Detail["request_id"] != "req-123" {
		t.Fatalf("request_id=%v", check.Detail["request_id"])
	}
	if strings.Contains(string(out), "do-not-include") {
		t.Fatalf("doctor output leaked sibling secret:\n%s", string(out))
	}
}

func TestAwDoctorMessagingLocalDryRunSignsWithoutNetwork(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "messaging", "--offline", "--json")
	if err != nil {
		t.Fatalf("doctor messaging offline failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingMailSignature, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingChatSignature, doctorStatusOK)
	text := string(out)
	for _, forbidden := range []string{"signed_payload", "Authorization", "doctor-check"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("messaging dry-run leaked %q:\n%s", forbidden, text)
		}
	}
	if server.Hits.Load() != 0 {
		t.Fatalf("offline messaging contacted server %d times", server.Hits.Load())
	}
}

func TestAwDoctorMessagingOnlineReadOnly(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "messaging", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor messaging online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingInboxRead, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingChatPending, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingChatSessions, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckMessagingContactsRead, doctorStatusOK)
	policy := requireDoctorCheckStatus(t, got, doctorCheckMessagingPolicyRead, doctorStatusUnknown)
	if policy.Detail["reason"] != "no_read_endpoint" {
		t.Fatalf("policy_read reason=%v", policy.Detail["reason"])
	}
	if server.DestructiveHits.Load() != 0 {
		t.Fatalf("doctor messaging made destructive requests: %d", server.DestructiveHits.Load())
	}
	if server.MessageAuthHits.Load() != 4 {
		t.Fatalf("messaging auth hits=%d, want 4", server.MessageAuthHits.Load())
	}
}

func TestAwDoctorRootOnlineHasNoDuplicateCheckIDs(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor root online failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	assertNoDuplicateDoctorChecks(t, got)
}

func readWorkspaceYAMLForDoctorTest(t *testing.T, workingDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()))
	if err != nil {
		t.Fatalf("read workspace.yaml: %v", err)
	}
	return string(data)
}

func assertNoDuplicateDoctorChecks(t *testing.T, got doctorOutput) {
	t.Helper()
	seen := map[string]bool{}
	for _, check := range got.Checks {
		if seen[check.ID] {
			t.Fatalf("duplicate check id %s in %#v", check.ID, got.Checks)
		}
		seen[check.ID] = true
	}
}

func TestAwDoctorAwebNoAPIKeyAuthorizationWithLegacyKey(t *testing.T) {
	t.Parallel()

	server := newDoctorAwebServer(t, nil)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.Server.URL)
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, awconfig.DefaultWorktreeWorkspaceRelativePath()))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	workspace.APIKey = "aw_sk_should_not_be_used"
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, awconfig.DefaultWorktreeWorkspaceRelativePath()), workspace); err != nil {
		t.Fatalf("save workspace: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "workspace", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor workspace online failed: %v\n%s", err, string(out))
	}
	if server.APIKeyAuthHits.Load() != 0 {
		t.Fatalf("doctor used API-key Authorization")
	}
}
