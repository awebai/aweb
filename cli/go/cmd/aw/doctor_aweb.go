package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const (
	doctorCheckServerAwebURLConfigured = "server.aweb_url.configured"
	doctorCheckServerAwebURLRuntime    = "server.aweb_url.runtime_path"
	doctorCheckServerReachable         = "server.aweb_url.reachable"
	doctorCheckServerVersion           = "server.aweb_url.version_header"
	doctorCheckServerTeamAuth          = "server.auth.team_certificate_request"

	doctorCheckWorkspaceTeamRead       = "workspace.server.team_read"
	doctorCheckWorkspaceCurrentRow     = "workspace.server.current_row"
	doctorCheckWorkspaceIdentityMatch  = "workspace.server.identity_matches_local"
	doctorCheckWorkspaceDeletedState   = "workspace.server.deleted_state"
	doctorCheckWorkspacePresence       = "workspace.server.presence_visible"
	doctorCheckWorkspaceReadOnly       = "workspace.lifecycle.read_only_invariant"
	doctorCheckTeamRolesRead           = "team.server.roles_read"
	doctorCheckTeamSelectedRoleMatches = "team.server.selected_role_matches_local"
	doctorCheckTeamMembershipAuth      = "team.server.membership_authorized"
	doctorCheckCoordinationStatusRead  = "coordination.server.status_read"
	doctorCheckCoordinationClaims      = "coordination.server.claims_visible"
	doctorCheckCoordinationCoherence   = "coordination.server.claims_coherent"
	doctorCheckCoordinationLocks       = "coordination.server.locks_visible"
	doctorCheckCoordinationConflicts   = "coordination.server.conflicts_visible"
)

type doctorAwebState struct {
	workingDir string

	workspacePath string
	workspace     *awconfig.WorktreeWorkspace
	workspaceErr  error
	membership    *awconfig.WorktreeMembership

	certPath string
	cert     *awid.TeamCertificate
	certErr  error

	signingKey    ed25519.PrivateKey
	signingKeyDID string
	signingKeyErr error

	baseURL string
	urlErr  error
}

type doctorAwebProbeResult struct {
	ConfiguredURL      string
	RecommendedURL     string
	ConfiguredOK       bool
	RecommendedOK      bool
	ConfiguredStatus   int
	RecommendedStatus  int
	ConfiguredHTML     bool
	RecommendedHTML    bool
	ConfiguredVersion  string
	RecommendedVersion string
	Err                error
}

func (r *doctorRunner) runWorkspaceDoctorChecks() {
	state := collectDoctorAwebState(r.workingDir)
	r.addServerConfiguredChecks(state, r.opts.Mode != doctorModeOnline)
	r.addWorkspaceReadOnlyInvariant()
	networkIDs := []string{
		doctorCheckServerReachable,
		doctorCheckServerVersion,
		doctorCheckServerTeamAuth,
		doctorCheckWorkspaceTeamRead,
		doctorCheckWorkspaceCurrentRow,
		doctorCheckWorkspaceIdentityMatch,
		doctorCheckWorkspaceDeletedState,
		doctorCheckWorkspacePresence,
		doctorCheckCoordinationStatusRead,
		doctorCheckCoordinationClaims,
		doctorCheckCoordinationCoherence,
		doctorCheckCoordinationLocks,
		doctorCheckCoordinationConflicts,
	}
	if state.hasNoWorkspaceContext() {
		r.addNoContextAwebChecks(networkIDs, "no_workspace_context")
		return
	}
	if r.opts.Mode != doctorModeOnline {
		r.addSkippedAwebChecks(networkIDs)
		return
	}
	if !r.addOnlineServerProbeChecks(state) {
		r.addBlockedAwebChecks(networkIDs[2:], doctorCheckServerReachable)
		return
	}
	client, prereq := r.doctorTeamClient(state)
	if prereq != "" {
		r.addBlockedAwebChecks(networkIDs[2:], prereq)
		return
	}
	r.addWorkspaceOnlineChecks(state, client)
}

func (r *doctorRunner) runTeamDoctorChecks() {
	state := collectDoctorAwebState(r.workingDir)
	networkIDs := []string{
		doctorCheckTeamRolesRead,
		doctorCheckTeamSelectedRoleMatches,
		doctorCheckTeamMembershipAuth,
	}
	if state.hasNoWorkspaceContext() {
		r.addNoContextAwebChecks(networkIDs, "no_workspace_context")
		return
	}
	if r.opts.Mode != doctorModeOnline {
		r.addSkippedAwebChecks(networkIDs)
		return
	}
	client, prereq := r.doctorTeamClient(state)
	if prereq != "" {
		r.addBlockedAwebChecks(networkIDs, prereq)
		return
	}
	r.addTeamOnlineChecks(state, client)
}

func (s *doctorAwebState) hasNoWorkspaceContext() bool {
	return s != nil && errors.Is(s.workspaceErr, os.ErrNotExist)
}

func collectDoctorAwebState(workingDir string) *doctorAwebState {
	state := &doctorAwebState{
		workingDir:    strings.TrimSpace(workingDir),
		workspacePath: filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()),
		certPath:      "",
		signingKeyDID: "",
		signingKeyErr: nil,
		workspaceErr:  nil,
		certErr:       nil,
		urlErr:        nil,
	}
	workspace, workspacePath, err := loadDoctorWorkspaceFromDir(workingDir)
	if err != nil {
		state.workspaceErr = err
	} else {
		state.workspace = workspace
		state.workspacePath = workspacePath
		if teamState, err := awconfig.LoadTeamState(workingDir); err == nil {
			state.membership = awconfig.ActiveMembershipFor(workspace, teamState)
		}
		if safe, err := sanitizeLocalURLForOutput(workspace.AwebURL); err != nil {
			state.urlErr = err
		} else {
			state.baseURL = strings.TrimSuffix(safe, "/")
		}
	}
	if state.membership != nil {
		state.certPath = resolveWorkspaceCertificatePath(workingDir, state.membership.CertPath)
		if strings.TrimSpace(state.certPath) == "" {
			state.certErr = errors.New("missing certificate path")
		} else if cert, err := awid.LoadTeamCertificate(state.certPath); err != nil {
			state.certErr = err
		} else {
			state.cert = cert
		}
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(workingDir))
	if err != nil {
		state.signingKeyErr = err
	} else {
		state.signingKey = signingKey
		state.signingKeyDID = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	}
	return state
}

func (r *doctorRunner) addServerConfiguredChecks(state *doctorAwebState, includeRuntime bool) {
	target := localPathTarget(state.workspacePath)
	if state.workspaceErr != nil {
		if errors.Is(state.workspaceErr, os.ErrNotExist) {
			r.add(awebCheck(doctorCheckServerAwebURLConfigured, doctorStatusInfo, target, "No workspace aweb_url is configured because workspace.yaml is missing.", "Run `aw init` when you are ready to connect this directory.", map[string]any{"reason": "no_workspace_context"}))
			if includeRuntime {
				r.add(awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusInfo, target, "Aweb runtime URL classification is not available without workspace context.", "Run `aw init` when you are ready to connect this directory.", map[string]any{"reason": "no_workspace_context"}))
			}
			return
		}
		r.add(awebCheck(doctorCheckServerAwebURLConfigured, doctorStatusFail, target, "Aweb server URL is unavailable because workspace.yaml is invalid.", "Resolve local workspace checks first.", map[string]any{"reason": "workspace_invalid"}))
		if includeRuntime {
			r.add(awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusBlocked, target, "Aweb runtime URL classification requires a configured workspace aweb_url.", "Resolve local workspace checks first.", map[string]any{"prerequisite": doctorCheckServerAwebURLConfigured}))
		}
		return
	}
	if state.urlErr != nil {
		r.add(awebCheck(doctorCheckServerAwebURLConfigured, doctorStatusFail, target, "Workspace aweb_url is invalid.", "Repair .aw/workspace.yaml with a valid aweb API URL.", map[string]any{"error": state.urlErr.Error()}))
		if includeRuntime {
			r.add(awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusBlocked, target, "Aweb runtime URL classification requires a valid aweb_url.", "Repair .aw/workspace.yaml first.", map[string]any{"prerequisite": doctorCheckServerAwebURLConfigured}))
		}
		return
	}
	r.add(awebCheck(doctorCheckServerAwebURLConfigured, doctorStatusOK, target, "Workspace aweb_url is configured.", "", map[string]any{"aweb_url": state.baseURL}))
	if includeRuntime {
		r.add(localRuntimePathCheck(state.baseURL))
	}
}

func localRuntimePathCheck(baseURL string) doctorCheck {
	parsed, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || parsed.Host == "" {
		return awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusBlocked, nil, "Aweb runtime URL classification requires a valid URL.", "Repair .aw/workspace.yaml first.", map[string]any{"prerequisite": doctorCheckServerAwebURLConfigured})
	}
	path := strings.TrimRight(parsed.Path, "/")
	switch {
	case strings.Contains(path, "/api/api"):
		return awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusFail, nil, "Workspace aweb_url appears to contain a duplicated /api runtime path.", "Use the single mounted runtime URL, for example https://app.aweb.ai/api.", map[string]any{"reason": "duplicated_api_path"})
	case parsed.Host == "app.aweb.ai" && path == "":
		recommended := *parsed
		recommended.Path = "/api"
		return awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusWarn, nil, "Hosted cloud workspace aweb_url points at the app origin instead of the /api runtime.", "Set aweb_url to the hosted runtime URL ending in /api; doctor will not rewrite it automatically.", map[string]any{"reason": "hosted_cloud_api_runtime", "recommended_aweb_url": recommended.String()})
	default:
		return awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusOK, nil, "Workspace aweb_url does not match a known hosted /api confusion pattern.", "", map[string]any{"aweb_url": baseURL})
	}
}

func (r *doctorRunner) addWorkspaceReadOnlyInvariant() {
	r.add(localCheck(
		doctorCheckWorkspaceReadOnly,
		doctorStatusOK,
		nil,
		"Doctor workspace checks are read-only and do not run cleanup or lifecycle deletion.",
		"",
		map[string]any{"cleanup_allowed": false, "delete_allowed": false},
	))
}

func (r *doctorRunner) addOnlineServerProbeChecks(state *doctorAwebState) bool {
	if strings.TrimSpace(state.baseURL) == "" || state.urlErr != nil {
		r.add(awebCheck(doctorCheckServerReachable, doctorStatusBlocked, nil, "Aweb reachability requires a valid configured aweb_url.", "Resolve server.aweb_url.configured first.", map[string]any{"prerequisite": doctorCheckServerAwebURLConfigured}))
		r.add(awebCheck(doctorCheckServerVersion, doctorStatusBlocked, nil, "Version header check requires a reachable aweb server.", "Resolve server.aweb_url.reachable first.", map[string]any{"prerequisite": doctorCheckServerReachable}))
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := probeDoctorAwebRuntime(ctx, state.baseURL)
	if probe.ConfiguredOK {
		r.add(awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusOK, nil, "Configured aweb_url is the reachable API runtime.", "", map[string]any{"aweb_url": state.baseURL, "status_code": probe.ConfiguredStatus}))
		r.add(awebCheck(doctorCheckServerReachable, doctorStatusOK, nil, "Configured aweb API runtime is reachable with a read-only probe.", "", map[string]any{"aweb_url": state.baseURL, "status_code": probe.ConfiguredStatus}))
		if probe.ConfiguredVersion != "" {
			r.add(awebCheck(doctorCheckServerVersion, doctorStatusOK, nil, "Server advertised the latest client version header.", "", map[string]any{"present": true, "latest_client_version": probe.ConfiguredVersion}))
		} else {
			r.add(awebCheck(doctorCheckServerVersion, doctorStatusInfo, nil, "No compatible version header was advertised by the server probe.", "", map[string]any{"present": false}))
		}
		return true
	}
	if probe.RecommendedOK {
		r.add(awebCheck(doctorCheckServerAwebURLRuntime, doctorStatusWarn, nil, "Configured aweb_url does not appear to be the API runtime, but /api does.", "Update .aw/workspace.yaml to the recommended runtime URL; doctor will not rewrite it automatically.", map[string]any{"reason": "api_runtime_at_recommended_path", "configured_aweb_url": state.baseURL, "recommended_aweb_url": probe.RecommendedURL}))
		r.add(awebCheck(doctorCheckServerReachable, doctorStatusUnknown, nil, "Configured aweb API runtime was not reachable at its current path.", "Use the recommended /api runtime URL and retry doctor --online.", map[string]any{"reason": "configured_runtime_unreachable", "configured_status_code": probe.ConfiguredStatus, "recommended_status_code": probe.RecommendedStatus}))
		r.add(awebCheck(doctorCheckServerVersion, doctorStatusBlocked, nil, "Version header check requires the configured aweb runtime to be reachable.", "Resolve server.aweb_url.runtime_path first.", map[string]any{"prerequisite": doctorCheckServerAwebURLRuntime}))
		return false
	}
	detail := map[string]any{"reason": "aweb_unavailable", "aweb_url": state.baseURL}
	if probe.ConfiguredStatus != 0 {
		detail["status_code"] = probe.ConfiguredStatus
	}
	if probe.ConfiguredHTML {
		detail["html_response"] = true
	}
	r.add(awebCheck(doctorCheckServerReachable, doctorStatusUnknown, nil, "Configured aweb API runtime is not reachable with a read-only probe.", "Check the configured aweb_url and network connectivity.", detail))
	r.add(awebCheck(doctorCheckServerVersion, doctorStatusBlocked, nil, "Version header check requires a reachable aweb server.", "Resolve server.aweb_url.reachable first.", map[string]any{"prerequisite": doctorCheckServerReachable}))
	return false
}

func probeDoctorAwebRuntime(ctx context.Context, baseURL string) doctorAwebProbeResult {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	result := doctorAwebProbeResult{ConfiguredURL: baseURL}
	status, html, version, err := probeDoctorAwebEndpoint(ctx, baseURL)
	result.ConfiguredStatus = status
	result.ConfiguredHTML = html
	result.ConfiguredVersion = version
	if err != nil {
		result.Err = err
	}
	result.ConfiguredOK = err == nil && status != http.StatusNotFound && !html && status < 500
	if strings.HasSuffix(baseURL, "/api") {
		return result
	}
	recommended := baseURL + "/api"
	result.RecommendedURL = recommended
	status, html, version, err = probeDoctorAwebEndpoint(ctx, recommended)
	result.RecommendedStatus = status
	result.RecommendedHTML = html
	result.RecommendedVersion = version
	result.RecommendedOK = err == nil && status != http.StatusNotFound && !html && status < 500
	return result
}

func probeDoctorAwebEndpoint(ctx context.Context, baseURL string) (int, bool, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(baseURL, "/")+"/v1/agents/heartbeat", nil)
	if err != nil {
		return 0, false, "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return 0, false, "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	return resp.StatusCode, strings.Contains(resp.Header.Get("Content-Type"), "text/html"), sanitizeDoctorVersionHeader(resp.Header.Get("X-Latest-Client-Version")), nil
}

func sanitizeDoctorVersionHeader(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 80 {
			break
		}
	}
	return b.String()
}

func (r *doctorRunner) doctorTeamClient(state *doctorAwebState) (*aweb.Client, string) {
	if state.workspaceErr != nil {
		return nil, doctorCheckWorkspaceParse
	}
	if state.membership == nil {
		return nil, doctorCheckWorkspaceMembership
	}
	if strings.TrimSpace(state.baseURL) == "" || state.urlErr != nil {
		return nil, doctorCheckServerAwebURLConfigured
	}
	if state.certErr != nil || state.cert == nil {
		return nil, doctorCheckCertificateParse
	}
	if state.signingKeyErr != nil || state.signingKey == nil {
		return nil, doctorCheckSigningKeyParse
	}
	if state.signingKeyDID != strings.TrimSpace(state.cert.MemberDIDKey) {
		return nil, doctorCheckSigningKeyMatchesCert
	}
	client, err := aweb.NewWithCertificate(state.baseURL, state.signingKey, state.cert)
	if err != nil {
		return nil, doctorCheckSigningKeyMatchesCert
	}
	client.SetAddress(strings.TrimSpace(state.cert.MemberAddress))
	if strings.TrimSpace(state.cert.MemberDIDAW) != "" {
		client.SetStableID(strings.TrimSpace(state.cert.MemberDIDAW))
	}
	return client, ""
}

func (r *doctorRunner) addWorkspaceOnlineChecks(state *doctorAwebState, client *aweb.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workspaceID := ""
	if state.membership != nil {
		workspaceID = strings.TrimSpace(state.membership.WorkspaceID)
	}
	teamResp, err := client.WorkspaceTeam(ctx, aweb.WorkspaceTeamParams{
		IncludeClaims:            true,
		IncludePresence:          true,
		OnlyWithClaims:           false,
		AlwaysIncludeWorkspaceID: workspaceID,
		Limit:                    50,
	})
	if err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckServerTeamAuth, err, "Authenticated team workspace read failed.", "Retry with the active workspace certificate or repair local team credentials.")
		r.addAwebHTTPErrorCheck(doctorCheckWorkspaceTeamRead, err, "Workspace team read failed.", "Retry after server/auth issues are resolved.")
		r.addBlockedAwebChecks([]string{doctorCheckWorkspaceCurrentRow, doctorCheckWorkspaceIdentityMatch, doctorCheckWorkspaceDeletedState, doctorCheckWorkspacePresence}, doctorCheckWorkspaceTeamRead)
	} else {
		r.add(awebCheck(doctorCheckServerTeamAuth, doctorStatusOK, nil, "Caller-owned team certificate authenticated to the aweb server.", "", map[string]any{"team_id": strings.TrimSpace(state.cert.Team)}))
		r.add(awebCheck(doctorCheckWorkspaceTeamRead, doctorStatusOK, nil, "Authenticated team workspace read succeeded.", "", map[string]any{"workspace_count": len(teamResp.Workspaces)}))
		r.addWorkspaceRowChecks(state, teamResp)
	}

	statusResp, err := client.CoordinationStatus(ctx, workspaceID)
	if err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckCoordinationStatusRead, err, "Coordination status read failed.", "Retry after server/auth issues are resolved.")
		r.addBlockedAwebChecks([]string{doctorCheckCoordinationClaims, doctorCheckCoordinationCoherence, doctorCheckCoordinationLocks, doctorCheckCoordinationConflicts}, doctorCheckCoordinationStatusRead)
		return
	}
	r.add(awebCheck(doctorCheckCoordinationStatusRead, doctorStatusOK, nil, "Coordination status read succeeded.", "", map[string]any{"workspace_id": workspaceID}))
	r.addCoordinationChecks(workspaceID, teamResp, statusResp)
}

func (r *doctorRunner) addWorkspaceRowChecks(state *doctorAwebState, teamResp *aweb.WorkspaceListResponse) {
	workspaceID := ""
	alias := ""
	if state.membership != nil {
		workspaceID = strings.TrimSpace(state.membership.WorkspaceID)
		alias = strings.TrimSpace(state.membership.Alias)
	}
	if strings.TrimSpace(workspaceID) == "" {
		r.add(awebCheck(doctorCheckWorkspaceCurrentRow, doctorStatusBlocked, nil, "Current workspace row lookup requires a local workspace_id.", "Resolve local workspace membership checks first.", map[string]any{"prerequisite": doctorCheckWorkspaceWorkspaceID}))
		r.addBlockedAwebChecks([]string{doctorCheckWorkspaceIdentityMatch, doctorCheckWorkspaceDeletedState, doctorCheckWorkspacePresence}, doctorCheckWorkspaceCurrentRow)
		return
	}
	var self *aweb.WorkspaceInfo
	for i := range teamResp.Workspaces {
		if strings.TrimSpace(teamResp.Workspaces[i].WorkspaceID) == workspaceID {
			self = &teamResp.Workspaces[i]
			break
		}
	}
	if self == nil {
		r.add(awebCheck(doctorCheckWorkspaceCurrentRow, doctorStatusFail, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server did not return the current workspace row.", "Confirm this worktree is still registered with the active team.", map[string]any{"workspace_id": workspaceID}))
		r.addBlockedAwebChecks([]string{doctorCheckWorkspaceIdentityMatch, doctorCheckWorkspaceDeletedState, doctorCheckWorkspacePresence}, doctorCheckWorkspaceCurrentRow)
		return
	}
	r.add(awebCheck(doctorCheckWorkspaceCurrentRow, doctorStatusOK, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server returned the current workspace row.", "", map[string]any{"workspace_id": workspaceID}))
	detail := map[string]any{
		"local_alias":  alias,
		"server_alias": strings.TrimSpace(self.Alias),
	}
	if strings.TrimSpace(self.Alias) != alias {
		r.add(awebCheck(doctorCheckWorkspaceIdentityMatch, doctorStatusFail, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server workspace alias does not match local active membership.", "Reinitialize or repair the workspace binding before coordinating.", detail))
	} else {
		r.add(awebCheck(doctorCheckWorkspaceIdentityMatch, doctorStatusOK, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server workspace identity matches local active membership.", "", detail))
	}
	if self.DeletedAt != nil && strings.TrimSpace(*self.DeletedAt) != "" {
		r.add(awebCheck(doctorCheckWorkspaceDeletedState, doctorStatusFail, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server workspace row is marked deleted.", "Reconnect or create a new workspace; doctor will not restore or delete anything automatically.", map[string]any{"deleted_at": strings.TrimSpace(*self.DeletedAt)}))
	} else {
		r.add(awebCheck(doctorCheckWorkspaceDeletedState, doctorStatusOK, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server workspace row is not marked deleted.", "", nil))
	}
	if strings.TrimSpace(self.Status) != "" || (self.LastSeen != nil && strings.TrimSpace(*self.LastSeen) != "") {
		r.add(awebCheck(doctorCheckWorkspacePresence, doctorStatusOK, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server returned read-only presence fields for this workspace.", "", map[string]any{"status": strings.TrimSpace(self.Status), "last_seen_present": self.LastSeen != nil && strings.TrimSpace(*self.LastSeen) != ""}))
	} else {
		r.add(awebCheck(doctorCheckWorkspacePresence, doctorStatusUnknown, &doctorTarget{Type: "workspace", ID: workspaceID}, "Server did not include visible presence fields for this workspace.", "Run normal coordination commands if you need to refresh presence; doctor does not send heartbeat.", map[string]any{"reason": "presence_not_visible"}))
	}
}

func (r *doctorRunner) addCoordinationChecks(workspaceID string, teamResp *aweb.WorkspaceListResponse, statusResp *aweb.CoordinationStatusResponse) {
	claimCount := 0
	statusClaimCount := 0
	if teamResp != nil {
		for _, workspace := range teamResp.Workspaces {
			if strings.TrimSpace(workspace.WorkspaceID) == workspaceID {
				claimCount = len(workspace.Claims)
				break
			}
		}
	}
	for _, claim := range statusResp.Claims {
		if strings.TrimSpace(claim.WorkspaceID) == workspaceID {
			statusClaimCount++
		}
	}
	r.add(awebCheck(doctorCheckCoordinationClaims, doctorStatusOK, nil, "Current workspace task claims are visible from read-only coordination state.", "", map[string]any{"workspace_team_claims": claimCount, "status_claims": statusClaimCount}))
	if claimCount != statusClaimCount {
		r.add(awebCheck(doctorCheckCoordinationCoherence, doctorStatusWarn, nil, "Workspace claim counts differ between workspace and coordination status reads.", "Refresh coordination status later or inspect task claims manually.", map[string]any{"workspace_team_claims": claimCount, "status_claims": statusClaimCount}))
	} else {
		r.add(awebCheck(doctorCheckCoordinationCoherence, doctorStatusOK, nil, "Workspace claim counts are coherent across read-only server views.", "", map[string]any{"claim_count": claimCount}))
	}
	r.add(awebCheck(doctorCheckCoordinationLocks, doctorStatusOK, nil, "Coordination locks are visible from status.", "", map[string]any{"lock_count": len(statusResp.Locks)}))
	if len(statusResp.Conflicts) > 0 {
		r.add(awebCheck(doctorCheckCoordinationConflicts, doctorStatusWarn, nil, "Coordination status reports task claim conflicts.", "Resolve task claim conflicts before assuming work ownership is clean.", map[string]any{"conflict_count": len(statusResp.Conflicts)}))
	} else {
		r.add(awebCheck(doctorCheckCoordinationConflicts, doctorStatusOK, nil, "Coordination status reports no task claim conflicts.", "", map[string]any{"conflict_count": 0}))
	}
}

func (r *doctorRunner) addTeamOnlineChecks(state *doctorAwebState, client *aweb.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	roles, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{OnlySelected: true})
	if err != nil {
		r.addAwebHTTPErrorCheck(doctorCheckTeamRolesRead, err, "Active team roles read failed.", "Retry with the active workspace certificate or repair local team credentials.")
		r.addBlockedAwebChecks([]string{doctorCheckTeamSelectedRoleMatches, doctorCheckTeamMembershipAuth}, doctorCheckTeamRolesRead)
		return
	}
	r.add(awebCheck(doctorCheckTeamRolesRead, doctorStatusOK, &doctorTarget{Type: "team", ID: strings.TrimSpace(roles.TeamID)}, "Active team roles read succeeded.", "", map[string]any{"team_id": strings.TrimSpace(roles.TeamID), "version": roles.Version}))
	localRole := ""
	if state.membership != nil {
		localRole = strings.TrimSpace(state.membership.RoleName)
	}
	selectedRole := ""
	if roles.SelectedRole != nil {
		selectedRole = strings.TrimSpace(roles.SelectedRole.RoleName)
	}
	if localRole != "" && selectedRole != "" && localRole != selectedRole {
		r.add(awebCheck(doctorCheckTeamSelectedRoleMatches, doctorStatusWarn, &doctorTarget{Type: "team", ID: strings.TrimSpace(roles.TeamID)}, "Selected server role differs from local membership role_name.", "Switch roles or repair local workspace metadata if this is unexpected.", map[string]any{"local_role_name": localRole, "server_role_name": selectedRole}))
	} else {
		r.add(awebCheck(doctorCheckTeamSelectedRoleMatches, doctorStatusOK, &doctorTarget{Type: "team", ID: strings.TrimSpace(roles.TeamID)}, "Selected team role is coherent where visible.", "", map[string]any{"local_role_name": localRole, "server_role_name": selectedRole}))
	}
	serverTeamID := strings.TrimSpace(roles.TeamID)
	localTeamID := ""
	if state.cert != nil {
		localTeamID = strings.TrimSpace(state.cert.Team)
	}
	if localTeamID != "" && serverTeamID != "" && localTeamID != serverTeamID {
		r.add(awebCheck(doctorCheckTeamMembershipAuth, doctorStatusFail, &doctorTarget{Type: "team", ID: localTeamID}, "Caller-owned team certificate authenticated, but the server returned a different team id.", "Confirm the active local team certificate and configured aweb server belong to the same team.", map[string]any{"local_team_id": localTeamID, "server_team_id": serverTeamID}))
		return
	}
	r.add(awebCheck(doctorCheckTeamMembershipAuth, doctorStatusOK, &doctorTarget{Type: "team", ID: localTeamID}, "Caller-owned team certificate is authorized for matching team reads.", "", map[string]any{"local_team_id": localTeamID, "server_team_id": serverTeamID}))
}

func (r *doctorRunner) addAwebHTTPErrorCheck(id string, err error, message, nextStep string) {
	status := doctorStatusUnknown
	reason := "aweb_unavailable"
	detail := map[string]any{"reason": reason}
	if code, ok := awid.HTTPStatusCode(err); ok {
		detail["status_code"] = code
		switch code {
		case http.StatusUnauthorized:
			status = doctorStatusBlocked
			reason = "caller_not_authorized"
		case http.StatusForbidden:
			status = doctorStatusBlocked
			reason = "caller_lacks_visibility"
		case http.StatusNotFound:
			status = doctorStatusFail
			reason = "not_found"
		default:
			if code >= 500 {
				status = doctorStatusUnknown
				reason = "aweb_unavailable"
			}
		}
		detail["reason"] = reason
	}
	if requestID, ok := doctorRequestIDFromError(err); ok {
		detail["request_id"] = requestID
	}
	r.add(awebCheck(id, status, nil, message, nextStep, detail))
}

func (r *doctorRunner) addSkippedAwebChecks(ids []string) {
	reason := "auto_mode"
	if r.opts.Mode == doctorModeOffline {
		reason = "offline_mode"
	}
	for _, id := range ids {
		r.add(awebCheck(id, doctorStatusUnknown, nil, "Online aweb check was skipped.", "Run `aw doctor --online` to contact the aweb server.", map[string]any{"skipped": true, "reason": reason}))
	}
}

func (r *doctorRunner) addNoContextAwebChecks(ids []string, reason string) {
	for _, id := range ids {
		r.add(awebCheck(id, doctorStatusInfo, nil, "Aweb server check is not available without workspace context.", "Run `aw init` when you are ready to connect this directory.", map[string]any{"reason": reason}))
	}
}

func (r *doctorRunner) addBlockedAwebChecks(ids []string, prerequisite string) {
	for _, id := range ids {
		r.add(awebCheck(id, doctorStatusBlocked, nil, "Aweb server check is blocked by a prerequisite.", "Resolve the prerequisite check first.", map[string]any{"prerequisite": prerequisite}))
	}
}

func awebCheck(id string, status doctorStatus, target *doctorTarget, message, nextStep string, detail map[string]any) doctorCheck {
	return doctorCheck{
		ID:            id,
		Status:        status,
		Source:        doctorSourceAweb,
		Authority:     doctorAuthorityCaller,
		Target:        target,
		Authoritative: false,
		Message:       message,
		Detail:        detail,
		NextStep:      nextStep,
	}
}

func readJSONBody(resp *http.Response, out any) error {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, awid.MaxResponseSize))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &awid.APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
