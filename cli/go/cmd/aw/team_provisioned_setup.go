package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type provisionedMemberSelection struct {
	Home   awconfig.IdentityHome
	TeamID string
	Name   string
	Scope  awid.IdentityScope
}

// existingProvisionedMember binds local recovery to the same certificate,
// member key, team, name and scope. It does not prove current admission; normal
// connect still checks that before publication (docs/identity.md#provisioned-members-and-encryption-discovery).
func existingProvisionedMember(input provisionedMemberSelection) (*acceptedTeamInvite, error) {
	if strings.TrimSpace(input.Home.Root) == "" {
		return nil, errors.New("provisioned member selection requires an identity home")
	}
	if input.Scope != awid.IdentityScopeLocal && input.Scope != awid.IdentityScopeGlobal {
		return nil, errors.New("provisioned member scope is unknown")
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(input.Home.Root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if state.ActiveTeam != "" && state.ActiveTeam != input.TeamID {
		return nil, usageError("existing identity home %s acts in team %s; select %s with `aw --identity-home %s id team switch %s` before resuming setup", input.Home.Root, state.ActiveTeam, input.TeamID, shellQuote(input.Home.Root), shellQuote(input.TeamID))
	}
	member := state.Membership(input.TeamID)
	if member == nil {
		return nil, usageError("existing identity home %s has no membership in selected team %s", input.Home.Root, input.TeamID)
	}
	cert, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(input.Home.Root, input.TeamID)
	if err != nil {
		return nil, err
	}
	path, err := awconfig.IdentityHomePath(input.Home, "signing.key")
	if err != nil {
		return nil, err
	}
	key, err := awid.LoadSigningKey(path)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || cert.MemberDIDKey != awid.ComputeDIDKey(ed25519.PublicKey(key[ed25519.SeedSize:])) || cert.Team != input.TeamID || !strings.EqualFold(cert.Alias, input.Name) || awid.IdentityScope(cert.IdentityScope) != input.Scope {
		return nil, usageError("existing identity home %s does not match the selected member key, team, name and scope", input.Home.Root)
	}
	domain, team, err := awid.ParseTeamID(cert.Team)
	if err != nil {
		return nil, err
	}
	awebURL := member.AwebURL
	if awebURL == "" {
		workspacePath, err := awconfig.IdentityHomePath(input.Home, "workspace.yaml")
		if err != nil {
			return nil, err
		}
		workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read retained member's workspace binding: %w", err)
		}
		awebURL = workspaceAwebURLForTeam(workspace, state, cert.Team)
	}
	return &acceptedTeamInvite{Certificate: cert, Domain: domain, TeamName: team, RegistryURL: member.RegistryURL, AwebURL: awebURL, Output: &teamAcceptInviteOutput{Status: "accepted", TeamID: cert.Team, Alias: cert.Alias, CertPath: awconfig.TeamCertificateRelativePath(cert.Team)}}, nil
}

type provisionedSetupFailure struct {
	Cause       error
	Plan        teamHumanAddedAgent
	CreatorDir  string
	CreatorHome awconfig.IdentityHome
	Authority   creationAuthorityMode
	WorkDir     string
}

// retainProvisionedSetupFailure never substitutes registry revocation for
// coordination deletion. Admitted credentials remain available to resume setup
// or use the ordered retirement command (docs/aweb-sot.md §Self-retirement).
func retainProvisionedSetupFailure(input provisionedSetupFailure) error {
	args := []string{"aw"}
	if input.Authority == creationAuthorityInvitation || input.Authority == creationAuthorityController {
		args = append(args, "--identity-home", input.CreatorHome.Root)
	}
	args = append(args, "team", "admin", "add", "--home", input.Plan.HomeDir)
	if input.WorkDir != "" {
		args = append(args, "--work-dir", input.WorkDir)
	}
	if input.Plan.LocalBlueprintDir != "" {
		args = append(args, "--blueprint", input.Plan.LocalBlueprintDir)
	}
	args = append(args, teamAgentSetupRetrySpec(input.Plan))
	guidance := fmt.Sprintf("Setup failed: %v. Member %s in %s is retained at %s; setup did not finish. Fix the reported setup error, then from %s run `%s` with the same creation authority. This reuses the member; it does not issue another identity. Use `aw team admin remove-agent %s --team-id %s` from its controller workspace if you want to retire it instead.", input.Cause, input.Plan.Name, input.Plan.TeamID, input.Plan.HomeDir, input.CreatorDir, formatShellCommand(args), input.Plan.Name, input.Plan.TeamID)
	return &provisionedMembershipIncompleteError{cause: &plainRefusal{text: guidance, err: input.Cause}}
}

func teamAgentSetupRetrySpec(plan teamHumanAddedAgent) string {
	scope := strings.TrimSpace(plan.Scope)
	if plan.Profile == nil {
		return plan.Name + ":" + scope
	}
	spec := plan.Name + "@" + plan.Profile.SourceBlueprintRef + "/" + plan.Profile.ProfileRef + ":" + scope
	if plan.Profile.RuntimeKind != "" {
		spec += "=" + plan.Profile.RuntimeKind
	}
	return spec
}
