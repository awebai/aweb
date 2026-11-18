package main

import (
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type teamInviteAuthorityKind string
type teamInviteMemberScope string
type teamInviteOutputStyle uint8

const (
	inviteAuthorityController teamInviteAuthorityKind = "controller"
	inviteAuthorityHosted     teamInviteAuthorityKind = "hosted"
	inviteMemberLocal         teamInviteMemberScope   = "local"
	inviteMemberGlobal        teamInviteMemberScope   = "global"
)

const (
	inviteOutputProtocol teamInviteOutputStyle = iota
	inviteOutputJoin
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
	Plan     teamInvitePlan
	Scope    teamInviteMemberScope
	ForHuman *string
}

type mintedTeamInvite struct {
	InviteID  string
	Token     string
	ExpiresAt string
	ForHuman  *string
}

type teamInvitePreflightOutput struct {
	TeamID      string                  `json:"team_id"`
	Kind        teamInviteAuthorityKind `json:"kind"`
	ExpiresAt   string                  `json:"expires_at"`
	ExpiryKnown bool                    `json:"expiry_known"`
}

var teamInvitePreflight bool

const identityReadOnlyFlagAnnotation = "aw.identity-read-only-flag"

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
	source := request.Plan.Source
	var humanOption []string
	if request.ForHuman != nil {
		humanOption = []string{*request.ForHuman}
	}
	localMember := request.Scope == inviteMemberLocal
	if request.Plan.Kind == inviteAuthorityHosted {
		created, err := createHostedTeamInvite(source.WorkingDir, externalIdentityHomeRoot(source.Home), awid.BuildTeamID(source.Domain, source.Team), localMember, humanOption...)
		if err != nil {
			return mintedTeamInvite{}, err
		}
		return mintedTeamInvite{InviteID: strings.TrimSpace(created.InviteID), Token: strings.TrimSpace(created.Token), ExpiresAt: strings.TrimSpace(created.ExpiresAt), ForHuman: created.ForHuman}, nil
	}
	if request.Plan.Kind != inviteAuthorityController {
		return mintedTeamInvite{}, usageError("unknown invite authority; run the invite preflight before minting")
	}
	inviteID, token, err := createTeamInviteTokenAt(source.Domain, source.Team, source.RegistryURL, source.AwebURL, localMember, "", source.WorkingDir, externalIdentityHomeRoot(source.Home), humanOption...)
	if err != nil {
		return mintedTeamInvite{}, err
	}
	saved, err := awconfig.LoadTeamInvite(inviteID)
	if err != nil {
		return mintedTeamInvite{}, err
	}
	return mintedTeamInvite{InviteID: inviteID, Token: token, ExpiresAt: saved.ExpiresAt, ForHuman: saved.ForHuman}, nil
}

func init() {
	teamInviteCmd.Flags().StringVar(&teamHumanInviteTeamID, "team-id", "", "Canonical team ID; use instead of --team and --namespace")
	teamInviteCmd.MarkFlagsMutuallyExclusive("team-id", "team")
	teamInviteCmd.MarkFlagsMutuallyExclusive("team-id", "namespace")
	for _, cmd := range []*cobra.Command{teamInviteCmd, teamHumanInviteCmd} {
		cmd.Flags().BoolVar(&teamInvitePreflight, "preflight", false, "Show the mint authority without creating a token or child invitation")
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		cmd.Annotations[identityReadOnlyFlagAnnotation] = "preflight"
	}
}
