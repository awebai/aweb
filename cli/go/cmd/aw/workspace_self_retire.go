package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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
	// The local config carries no workspace-bound key to authenticate as.
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
	apiKey   string
	teamID   string
	alias    string
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
	apiKey := strings.TrimSpace(workspace.APIKey)
	if apiKey == "" {
		return selfRetirePlan{reason: aliasReleaseNoCredential}
	}
	awebURL := strings.TrimSpace(sel.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(workspace.AwebURL)
	}
	if awebURL == "" {
		return selfRetirePlan{reason: aliasReleaseNoCredential}
	}
	return selfRetirePlan{
		eligible: true,
		awebURL:  awebURL,
		apiKey:   apiKey,
		teamID:   teamID,
		alias:    strings.TrimSpace(sel.Alias),
	}
}

// postSelfRetire calls the cloud self-remove route with the workspace-bound key.
//
// The alias is sent so the SERVER can refuse a mismatch: it authenticates the
// caller from the credential and never selects by this value. That turns "the
// local config thinks it is alice but the credential is bob" into a refusal
// instead of retiring bob.
func postSelfRetire(ctx context.Context, plan selfRetirePlan) (*selfRetireResponse, error) {
	payload := map[string]string{}
	if plan.alias != "" {
		payload["alias"] = plan.alias
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := hostedRemovalAPIPath(plan.awebURL, plan.teamID, selfRetireSuffix)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(plan.awebURL, "/")+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	responseBody, err := executeHostedRemovalRequest(req, plan.apiKey, "self retirement")
	if err != nil {
		return nil, err
	}
	var out selfRetireResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, fmt.Errorf("decode self retirement response: %w", err)
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
