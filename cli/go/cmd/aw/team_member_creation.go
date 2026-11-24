package main

import (
	"errors"
	"fmt"
	"path/filepath"
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
	home := awconfig.WorktreeIdentityHome(homeDir)
	memberAddress := ""
	var recovery *initInviteRecovery
	var recoveryPath string
	if input.Scope == awid.IdentityScopeGlobal {
		recoveryPath, err = (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: home}, Name: initInviteRecoveryFile}).Path()
		if err != nil {
			return nil, err
		}
		lockPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: home}, initInviteRecoveryFile+".lock")
		if err != nil {
			return nil, err
		}
		lock, err := awconfig.TryLockExclusive(lockPath)
		if err != nil {
			return nil, retainIdentityForRecovery(fmt.Errorf("lock member invite recovery: %w", err))
		}
		defer lock.Close()
		selection := rosterInviteSelection(anchorDir, actorHome.Root, awid.BuildTeamID(domain, team), alias)
		recovery, err = loadRosterInviteRecovery(recoveryPath, selection)
		if err != nil {
			return nil, err
		}
		// Another invocation may have finished while this one was in preflight.
		accepted, err := existingProvisionedMember(provisionedMemberSelection{Home: awconfig.IdentityHome{Root: home}, TeamID: selection.TeamID, Name: alias, Scope: input.Scope})
		if err != nil {
			return nil, retainIdentityForRecovery(err)
		}
		if accepted != nil {
			if err := completeProvisionedTeamMembership(provisionedTeamMembership{WorkingDir: homeDir, Home: awconfig.IdentityHome{Root: home}, AwebURL: accepted.AwebURL}); err != nil {
				return nil, retainIdentityForRecovery(err)
			}
			return accepted, nil
		}
		identityExists, err := teamCreateHasIdentityMaterial(homeDir)
		if err != nil {
			return nil, err
		}
		if !identityExists {
			if err := bootstrapTeamCreateGlobalIdentity(globalIdentityBootstrap{WorkingDir: homeDir, Name: alias, Domain: domain, RegistryURL: registryURL, Purpose: globalIdentityForTeamMember}); err != nil {
				return nil, err
			}
		}
		defer func() {
			if resultErr == nil {
				return
			}
			retained := fmt.Errorf("%w; global identity material is retained at %s", resultErr, homeDir)
			if recovery != nil {
				retained = fmt.Errorf("%w. To resume, rerun the original command with the same creator, team, name and agent home", retained)
			}
			resultErr = retainIdentityForRecovery(retained)
		}()
		identity, _, err := awconfig.LoadWorktreeIdentityFromDir(homeDir)
		if err != nil {
			return nil, fmt.Errorf("read prepared global identity: %w", err)
		}
		if identity == nil {
			return nil, errors.New("prepared global identity is missing")
		}
		memberAddress = strings.TrimSpace(identity.Address)
		if recovery == nil {
			key, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
			if err != nil {
				return nil, fmt.Errorf("read prepared global identity key: %w", err)
			}
			selection.DIDKey = didOf(key)
			if err := selection.save(recoveryPath); err != nil {
				return nil, err
			}
			recovery = &selection
		}
	}

	token := ""
	if recovery != nil {
		token = recovery.Token
	}
	if token == "" {
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
		token = created.Token
		if recovery != nil {
			recovery.Token = token
			if err := recovery.save(recoveryPath); err != nil {
				return nil, err
			}
		}
	}
	acceptOpts := teamAcceptInviteOptions{IdentityHome: home, Name: alias, Scope: string(input.Scope), Address: memberAddress, ParentHome: parentHome}
	accepted, err := acceptProvisionedTeamInvite(anchorDir, actorHome.Root, homeDir, token, acceptOpts)
	if err != nil {
		return nil, err
	}
	// Agent provisioning writes the worktree binding immediately: the produced
	// agent is ready to run with no separate `aw init`.
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: homeDir, Output: accepted.Output, Certificate: accepted.Certificate, RegistryURL: accepted.RegistryURL, AwebURL: accepted.AwebURL, IdentityHome: explicitEncryptionKeyIdentityHome(home), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding}); err != nil {
		return nil, err
	}
	if recovery != nil {
		if err := removeInitInviteRecovery(recoveryPath); err != nil {
			return nil, err
		}
	}
	return accepted, nil
}

func rosterInviteSelection(source, sourceHome, team, alias string) initInviteRecovery {
	return initInviteRecovery{Roster: true, Source: source, SourceHome: sourceHome, TeamID: team, Alias: alias, Scope: awid.IdentityModeGlobal}
}

func loadRosterInviteRecovery(path string, selection initInviteRecovery) (*initInviteRecovery, error) {
	recovery, err := loadInitInviteRecovery(path)
	if err != nil || recovery == nil {
		return recovery, err
	}
	if !recovery.Roster || !recovery.matchesSelection(selection) || !recovery.matchesKey(filepath.Dir(path)) {
		return nil, usageError("pending invite in %s requires the original command, creator, team, name and signing key", filepath.Dir(path))
	}
	return recovery, nil
}
