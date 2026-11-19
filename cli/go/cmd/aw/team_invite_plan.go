package main

import (
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const codeControllerKeyMissing = "controller_key_missing"

type teamInviteAuthorityKind string
type teamInviteMemberScope string

const (
	inviteAuthorityController teamInviteAuthorityKind = "controller"
	inviteAuthorityHosted     teamInviteAuthorityKind = "hosted"
	inviteMemberLocal         teamInviteMemberScope   = "local"
	inviteMemberGlobal        teamInviteMemberScope   = "global"
)

type teamInviteSource struct {
	WorkingDir  string
	Home        awconfig.IdentityHome
	Domain      string
	Team        string
	RegistryURL string
	AwebURL     string
}

type teamInvitePlan struct {
	Source teamInviteSource
	Kind   teamInviteAuthorityKind
}

type teamInviteMintRequest struct {
	Plan         teamInvitePlan
	Scope        teamInviteMemberScope
	ForHuman     *string
	ExpiresAfter time.Duration
}

type mintedTeamInvite struct {
	InviteID  string
	Token     string
	ExpiresAt string
	ForHuman  *string
}

// Controller custody chooses the controller mint; otherwise the configured
// service may authorize a hosted mint. A grant cannot borrow a root key
// (docs/cli-identity-selection.md:13,28-33). Planning creates no ID-child or token.
func planTeamInvite(source teamInviteSource) (teamInvitePlan, error) {
	plan := teamInvitePlan{Source: source, Kind: inviteAuthorityController}
	if !awconfig.IsGrantHome(source.Home.Root) {
		hasKey, err := awconfig.TeamKeyExists(source.Domain, source.Team)
		if err != nil {
			return plan, err
		}
		if hasKey {
			return plan, nil
		}
	}
	if strings.TrimSpace(source.AwebURL) != "" {
		plan.Kind = inviteAuthorityHosted
		return plan, nil
	}
	return plan, withErrorCode(codeControllerKeyMissing, usageError("no team key for %s/%s; run `aw id team create` first", source.Domain, source.Team))
}

func mintPlannedTeamInvite(request teamInviteMintRequest) (mintedTeamInvite, error) {
	if err := request.Scope.validate(); err != nil {
		return mintedTeamInvite{}, err
	}
	source := request.Plan.Source
	var humanOption []string
	if request.ForHuman != nil {
		humanOption = []string{*request.ForHuman}
	}
	localMember := request.Scope == inviteMemberLocal
	if request.Plan.Kind == inviteAuthorityHosted {
		if request.ExpiresAfter != 0 {
			return mintedTeamInvite{}, usageError("--expires selects a local controller invite lifetime; the hosted service sets its own expiry")
		}
		created, err := createHostedTeamInvite(source.WorkingDir, externalIdentityHomeRoot(source.Home), awid.BuildTeamID(source.Domain, source.Team), localMember, humanOption...)
		if err != nil {
			return mintedTeamInvite{}, err
		}
		return mintedTeamInvite{InviteID: strings.TrimSpace(created.InviteID), Token: strings.TrimSpace(created.Token), ExpiresAt: strings.TrimSpace(created.ExpiresAt), ForHuman: created.ForHuman}, nil
	}
	if request.Plan.Kind != inviteAuthorityController {
		return mintedTeamInvite{}, usageError("unknown invite authority; run the invite preflight before minting")
	}
	return createControllerTeamInvite(request)
}

func (scope teamInviteMemberScope) validate() error {
	switch scope {
	case inviteMemberLocal, inviteMemberGlobal:
		return nil
	default:
		return usageError("invitation member scope must be local or global")
	}
}
