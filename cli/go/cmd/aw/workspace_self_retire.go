package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Self-retirement of a hosted local member.
//
// `aw workspace delete` used to be the whole retirement story for a temporary
// local member, and it was only half of one: it soft-deletes
// coordination rows and never touches AWID. The membership certificate stayed
// active, AWID refuses a second active certificate for an alias, and the alias
// was never reusable - while the command, and the oats.aweb hook wrapping it,
// reported success. Reporting retirement that did not happen is the defect; the
// alias leak is its symptom.
//
// So `aw workspace delete`, for a member deleting its OWN hosted local
// workspace, now calls the cloud's self-remove route, which revokes the
// certificate through the cloud-held team controller and runs the same
// coordination cascade. Every other case keeps today's behaviour and says so.

const selfRetireSuffix = "/agents/self-remove"

// Why the alias was or was not released. These are the strings a retirement hook
// switches on, so they are constants rather than inline literals.
const (
	// The command was not asked to retire the caller's own workspace.
	aliasReleaseNotSelf = "not_own_workspace"
	// Self-hosted or BYOT: no cloud-held controller to revoke through, so this
	// command cannot release the alias and does not claim to.
	aliasReleaseNotHosted = "team_not_hosted"
	// A global identity outlives its workspace. Releasing its alias is a
	// team-authorized removal, not a self-service one.
	aliasReleaseGlobalIdentity = "global_identity"
	// The local config carries neither a workspace-bound key nor a team
	// certificate to authenticate as. The name is kept because retirement hooks
	// switch on it; what it means is "no member credential of either kind".
	aliasReleaseNoCredential = "no_workspace_credential"
)

type selfRetireResponse struct {
	Status              string `json:"status"`
	TeamID              string `json:"team_id"`
	CanonicalTeamID     string `json:"canonical_team_id"`
	Alias               string `json:"alias"`
	IdentityScope       string `json:"identity_scope"`
	AliasReleased       bool   `json:"alias_released"`
	AliasReleasedReason string `json:"alias_released_reason"`
	RevokeOutcome       string `json:"revoke_outcome"`
	CertificateID       string `json:"certificate_id"`
	AgentID             string `json:"agent_id"`
	WorkspaceID         string `json:"workspace_id"`
	ClaimsReleased      *int   `json:"claims_released"`
	AuditID             string `json:"audit_id"`
}

// selfRetirePlan says whether this delete can retire the member, and when it
// cannot, why - so the caller reports a reason instead of an unexplained false.
type selfRetirePlan struct {
	eligible bool
	reason   string
	awebURL  string
	// apiKey is set only when the workspace carries a workspace-bound key. It is
	// empty on the certificate path, which is the ORDINARY case: a member that
	// joined by invite (`aw team join`) holds signing.key plus a team
	// certificate and never receives an API key.
	apiKey string
	// certificate is set when the retirement is authenticated with the member's
	// own team certificate instead. Exactly one of apiKey and certificate is set
	// on an eligible plan; the route accepts either credential and takes the
	// subject from whichever one it verified.
	certificate bool
	teamID      string
	alias       string
}

// planSelfRetire decides whether `aw workspace delete <target>` is a hosted
// local member retiring itself.
//
// All three conditions must hold, and each maps to a distinct reason so a false
// is actionable: the target must be the caller's OWN workspace (self-remove
// only ever retires the caller), the team must be in the hosted zone (only the
// cloud holds a team controller that can revoke), and the identity must be
// local (a global identity's alias is released by team-authorized removal only).
func planSelfRetire(workingDir string, sel *awconfig.Selection, targetWorkspaceID string) selfRetirePlan {
	if sel == nil {
		return selfRetirePlan{reason: aliasReleaseNotSelf}
	}
	own := strings.TrimSpace(sel.WorkspaceID)
	if own == "" || !strings.EqualFold(own, strings.TrimSpace(targetWorkspaceID)) {
		return selfRetirePlan{reason: aliasReleaseNotSelf}
	}
	teamID := strings.TrimSpace(sel.TeamID)
	domain, _, parseErr := awid.ParseTeamID(teamID)
	if teamID == "" || parseErr != nil || !isAwebHostedNamespace(domain) {
		return selfRetirePlan{reason: aliasReleaseNotHosted}
	}
	// Fail closed on an unknown scope rather than guessing "local": guessing
	// wrong here would attempt to revoke a global identity's certificate.
	if !strings.EqualFold(strings.TrimSpace(sel.IdentityScope), "local") {
		return selfRetirePlan{reason: aliasReleaseGlobalIdentity}
	}
	// Workspace state only, NOT LoadWorkspaceAndTeamState: that one also loads
	// teams.yaml and returns its error, so a missing or unreadable team-state file
	// would silently make every member ineligible for self-retirement - the
	// command would go back to reporting a delete that leaks the alias, and the
	// reason would say "no credential" when a credential was sitting right there.
	// Nothing here needs team state; the team id comes from the selection.
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil || workspace == nil {
		return selfRetirePlan{reason: aliasReleaseNoCredential}
	}
	// Either credential authorizes the route, so either one makes this plan
	// eligible. The API key is preferred only because it is the narrower
	// credential of the two, not because the certificate is a fallback: a member
	// that joined by invite has no API key at all, and refusing it here is what
	// made `aw workspace delete` report no_workspace_credential for the normal
	// OATS member and leak its alias.
	apiKey := strings.TrimSpace(workspace.APIKey)
	certificate := false
	if apiKey == "" {
		if !hasSelfRetireTeamCertificate(workingDir, sel, workspace, teamID) {
			return selfRetirePlan{reason: aliasReleaseNoCredential}
		}
		certificate = true
	}
	awebURL := strings.TrimSpace(sel.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(workspace.AwebURL)
	}
	if awebURL == "" {
		return selfRetirePlan{reason: aliasReleaseNoCredential}
	}
	return selfRetirePlan{
		eligible:    true,
		awebURL:     awebURL,
		apiKey:      apiKey,
		certificate: certificate,
		teamID:      teamID,
		alias:       strings.TrimSpace(sel.Alias),
	}
}

// hasSelfRetireTeamCertificate reports whether this workspace holds its own
// membership certificate for teamID.
//
// It resolves the certificate exactly the way resolveCertificateClient does -
// the membership's cert_path, under the selection's identity home - so the plan
// cannot say "certificate" for a path the client would then fail to load. It
// loads rather than stats, because an unreadable file is not a credential.
func hasSelfRetireTeamCertificate(
	workingDir string,
	sel *awconfig.Selection,
	workspace *awconfig.WorktreeWorkspace,
	teamID string,
) bool {
	if sel == nil || workspace == nil {
		return false
	}
	membership := workspace.Membership(teamID)
	if membership == nil || strings.TrimSpace(membership.CertPath) == "" {
		return false
	}
	certHome := strings.TrimSpace(sel.IdentityHome)
	if certHome == "" {
		dir := strings.TrimSpace(sel.WorkingDir)
		if dir == "" {
			dir = workingDir
		}
		certHome = awconfig.WorktreeIdentityHome(dir)
	}
	certPath, err := awconfig.IdentityHomeStoredPath(awconfig.IdentityHome{Root: certHome}, membership.CertPath)
	if err != nil {
		return false
	}
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := awid.LoadTeamCertificate(certPath); err != nil {
		return false
	}
	return true
}

// selfRetireRequest is SelfRemoveHostedAgentMemberRequest.
//
// There is deliberately nothing here but the alias: the route resolves the
// subject from the verified credential and never from the body, so a member
// cannot name someone else.
type selfRetireRequest struct {
	Alias string `json:"alias,omitempty"`
}

// selfRetireClientPath is the self-remove route as the aweb client addresses it.
//
// It is the same route as hostedRemovalAPIPath's, spelled the way every other
// client method spells a path: relative to the client's base URL, which already
// carries the /api segment. hostedRemovalAPIPath builds an absolute path against
// a raw aweb URL instead, which is what the API-key path needs and this one
// must not reuse.
func selfRetireClientPath(teamID string) string {
	return "/v1/teams/" + urlPathSegmentEscape(teamID) + selfRetireSuffix
}

// postSelfRetire calls the cloud self-remove route with the member's own
// credential: the workspace-bound API key when the workspace has one, otherwise
// the certificate-authenticated client the rest of the CLI already uses.
//
// The alias is sent so the SERVER can refuse a mismatch: it authenticates the
// caller from the credential and never selects by this value. That turns "the
// local config thinks it is alice but the credential is bob" into a refusal
// instead of retiring bob.
func postSelfRetire(ctx context.Context, client *aweb.Client, plan selfRetirePlan) (*selfRetireResponse, error) {
	var out selfRetireResponse
	var err error
	if plan.certificate {
		out, err = postSelfRetireWithCertificate(ctx, client, plan)
	} else {
		out, err = postSelfRetireWithAPIKey(ctx, plan)
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.Status) == "" {
		return nil, fmt.Errorf("self retirement response is missing status")
	}
	// The response describes the caller's own alias. If it names a different one,
	// something resolved to the wrong member and the result must not be reported
	// as this member's retirement.
	if plan.alias != "" && strings.TrimSpace(out.Alias) != "" && !strings.EqualFold(strings.TrimSpace(out.Alias), plan.alias) {
		return nil, fmt.Errorf(
			"self retirement response names alias %q, not %q",
			strings.TrimSpace(out.Alias),
			plan.alias,
		)
	}
	return &out, nil
}

// postSelfRetireWithCertificate signs the POST with the member's team
// certificate, the credential _handle_team_certificate_request verifies and
// _authorize_hosted_self_removal reads request.state.cloud_team_identity from.
//
// It deliberately does NOT fall back to anything when the client cannot sign:
// the plan already established that this member's only credential is the
// certificate, so an unsigned attempt would be an unauthenticated call reported
// as a retirement.
func postSelfRetireWithCertificate(ctx context.Context, client *aweb.Client, plan selfRetirePlan) (selfRetireResponse, error) {
	var out selfRetireResponse
	if client == nil || !client.HasTeamCertificateAuth() {
		return out, fmt.Errorf("self retirement needs a team-certificate client, and this workspace has none")
	}
	if err := client.Post(ctx, selfRetireClientPath(plan.teamID), selfRetireRequest{Alias: plan.alias}, &out); err != nil {
		return selfRetireResponse{}, fmt.Errorf("self retirement failed: %w", err)
	}
	return out, nil
}

func postSelfRetireWithAPIKey(ctx context.Context, plan selfRetirePlan) (selfRetireResponse, error) {
	var out selfRetireResponse
	body, err := json.Marshal(selfRetireRequest{Alias: plan.alias})
	if err != nil {
		return out, err
	}
	path := hostedRemovalAPIPath(plan.awebURL, plan.teamID, selfRetireSuffix)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(plan.awebURL, "/")+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	responseBody, err := executeHostedRemovalRequest(req, plan.apiKey, "self retirement")
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return selfRetireResponse{}, fmt.Errorf("decode self retirement response: %w", err)
	}
	return out, nil
}
