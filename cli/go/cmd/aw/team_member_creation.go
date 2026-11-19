package main

import (
	"errors"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func createAndAcceptTeamInviteForEmptyAgent(anchorDir, homeDir, alias string, global bool) (*acceptedTeamInvite, error) {
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
	if global {
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
	if global {
		identityExists, err := teamCreateHasIdentityMaterial(homeDir)
		if err != nil {
			return nil, err
		}
		if !identityExists {
			if err := bootstrapTeamCreateGlobalIdentity(homeDir, alias, domain, registryURL, false); err != nil {
				return nil, err
			}
		}
		if identity, _, err := awconfig.LoadWorktreeIdentityFromDir(homeDir); err == nil && identity != nil {
			memberAddress = strings.TrimSpace(identity.Address)
		}
	}

	plan, err := planTeamInvite(teamInviteSource{
		WorkingDir: anchorDir, Home: actorHome, Domain: domain, Team: team, RegistryURL: registryURL, AwebURL: awebURL,
	})
	if err != nil {
		return nil, err
	}
	scope := inviteMemberLocal
	if global {
		scope = inviteMemberGlobal
	}
	created, err := mintPlannedTeamInvite(teamInviteMintRequest{Plan: plan, Scope: scope})
	if err != nil {
		return nil, err
	}
	token := created.Token
	acceptOpts := teamAcceptInviteOptions{IdentityHome: awconfig.WorktreeIdentityHome(homeDir), Name: alias, Scope: teamAcceptScopeFromGlobal(global), Address: memberAddress, ParentHome: parentHome}
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
