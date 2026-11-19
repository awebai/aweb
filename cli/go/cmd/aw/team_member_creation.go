package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type teamMemberCreation struct {
	SourceDir string
	HomeDir   string
	Name      string
	Scope     awid.IdentityScope
}

// createProvisionedTeamMember uses the selected creator and the shared mint and
// membership-record owners. Normal admission completes before encryption-key
// publication (docs/identity.md §Provisioned members and encryption discovery).
func createProvisionedTeamMember(input teamMemberCreation) (result *acceptedTeamInvite, resultErr error) {
	if input.Scope != awid.IdentityScopeLocal && input.Scope != awid.IdentityScopeGlobal {
		return nil, errors.New("team member creation scope is unknown")
	}
	anchorDir, homeDir, alias := input.SourceDir, input.HomeDir, input.Name
	team, domain, registryURL, awebURL, err := resolveTeamInviteTarget(anchorDir)
	if err != nil {
		// resolveTeamInviteTarget is shared with `aw id team invite`, whose error
		// mentions --team/--namespace. Those are not flags on `aw team admin add`: this
		// command mints against this workspace's active team.
		if errors.Is(err, errTeamInviteTargetHasNoActiveTeam) {
			return nil, usageError("aw team admin add mints against this workspace's active team, but none was found here; run `aw team admin create <name>` (or `aw init` with your team's AWEB_URL and AWEB_API_KEY) in this directory first, then re-run `aw team admin add`")
		}
		return nil, err
	}
	actorHome, err := identityHomeForDir(anchorDir)
	if err != nil {
		return nil, err
	}
	parentHome := ""
	if input.Scope == awid.IdentityScopeGlobal {
		chain, err := awconfig.LoadInstalledIDChain(actorHome.Root)
		if err != nil {
			return nil, err
		}
		if chain != nil {
			actor, err := resolveIDExchangeIdentity(anchorDir, actorHome.Root)
			if err != nil {
				return nil, err
			}
			if actor.StableID == "" {
				return nil, usageError("this local creator cannot parent a registered global child; use aw id team add-member for the controller's unconditional admission path")
			}
			ctx, cancel := commandAPIContext(nil)
			issuer, err := currentAgentIssuer(idChildOptions{WorkingDir: anchorDir, IdentityHome: actorHome.Root, Now: time.Now})
			if err == nil {
				err = checkSelectedTeamInviteIssuer(ctx, issuer)
			}
			cancel()
			if err != nil {
				return nil, err
			}
			parentHome = actorHome.Root
		}
	}
	memberAddress := ""
	if input.Scope == awid.IdentityScopeGlobal {
		identityExists, err := teamCreateHasIdentityMaterial(homeDir)
		if err != nil {
			return nil, err
		}
		if !identityExists {
			if err := bootstrapTeamCreateGlobalIdentity(globalIdentityBootstrap{WorkingDir: homeDir, Name: alias, Domain: domain, RegistryURL: registryURL, Purpose: globalIdentityForTeamMember}); err != nil {
				return nil, err
			}
		}
		// A prepared global identity can outlive a failed invite. Its key is
		// retained independently of whether membership acceptance was submitted.
		defer func() {
			if resultErr != nil {
				inspect := formatShellCommand([]string{"aw", "--identity-home", awconfig.WorktreeIdentityHome(homeDir), "id", "show"})
				resultErr = retainIdentityForRecovery(fmt.Errorf("%w; global identity material is retained at %s. Inspect it with `%s` and finish membership using this same identity and creator; do not create a replacement", resultErr, homeDir, inspect))
			}
		}()
		identity, _, err := awconfig.LoadWorktreeIdentityFromDir(homeDir)
		if err != nil {
			return nil, fmt.Errorf("read prepared global identity: %w", err)
		}
		if identity == nil {
			return nil, errors.New("prepared global identity is missing")
		}
		memberAddress = strings.TrimSpace(identity.Address)
	}

	plan, err := planTeamInvite(teamInviteSource{
		WorkingDir: anchorDir, Home: actorHome, Domain: domain, Team: team, RegistryURL: registryURL, AwebURL: awebURL,
	})
	if err != nil {
		return nil, err
	}
	scope := inviteMemberLocal
	if input.Scope == awid.IdentityScopeGlobal {
		scope = inviteMemberGlobal
	}
	created, err := mintPlannedTeamInvite(teamInviteMintRequest{Plan: plan, Scope: scope})
	if err != nil {
		return nil, err
	}
	token := created.Token
	acceptOpts := teamAcceptInviteOptions{IdentityHome: awconfig.WorktreeIdentityHome(homeDir), Name: alias, Scope: string(input.Scope), Address: memberAddress, ParentHome: parentHome}
	accepted, err := acceptProvisionedTeamInvite(anchorDir, actorHome.Root, homeDir, token, acceptOpts)
	if err != nil {
		return nil, err
	}
	// Agent provisioning writes the worktree binding immediately: the produced
	// agent is ready to run with no separate `aw init`.
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: homeDir, Output: accepted.Output, Certificate: accepted.Certificate, RegistryURL: accepted.RegistryURL, AwebURL: accepted.AwebURL, IdentityHome: explicitEncryptionKeyIdentityHome(awconfig.WorktreeIdentityHome(homeDir)), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding}); err != nil {
		return nil, err
	}
	return accepted, nil
}
