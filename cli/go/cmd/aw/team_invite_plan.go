package main

import (
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type teamInviteAuthorityKind string
type teamInviteMemberScope = awid.IdentityScope
type teamInviteOutputStyle uint8

const (
	inviteAuthorityController teamInviteAuthorityKind = "controller"
	inviteAuthorityHosted     teamInviteAuthorityKind = "hosted"
	inviteMemberLocal         teamInviteMemberScope   = awid.IdentityScopeLocal
	inviteMemberGlobal        teamInviteMemberScope   = awid.IdentityScopeGlobal
)

const (
	inviteOutputProtocol teamInviteOutputStyle = iota
	inviteOutputJoin
)

type inviteMemberScopeFlags struct{ Global bool }

// The public --global/member-global flags opt into global membership; the
// released default remains local (docs/invite-inspection.md:52-54).
func inviteMemberScopeFromFlags(flags inviteMemberScopeFlags) teamInviteMemberScope {
	if flags.Global {
		return inviteMemberGlobal
	}
	return inviteMemberLocal
}

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

type teamInvitePreflightOutput struct {
	TeamID      string                  `json:"team_id"`
	Kind        teamInviteAuthorityKind `json:"kind"`
	ExpiresAt   string                  `json:"expires_at"`
	ExpiryKnown bool                    `json:"expiry_known"`
}

var teamInvitePreflight bool
var teamInviteExpiresAfter time.Duration

const identityReadOnlyFlagAnnotation = "aw.identity-read-only-flag"

// Controller custody chooses the controller mint; otherwise the configured
// service may authorize a hosted mint. A grant cannot borrow a root key
// (docs/cli-identity-selection.md:13,28-33). Planning creates no ID-child or token.
func planTeamInvite(source teamInviteSource) (teamInvitePlan, error) {
	plan := teamInvitePlan{Source: source, Kind: inviteAuthorityController}
	grant, err := loadGrantHomeAt(source.Home)
	if err != nil {
		return plan, err
	}
	if grant == nil {
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
	if err := validateInviteMemberScope(request.Scope); err != nil {
		return mintedTeamInvite{}, err
	}
	if request.Plan.Kind == inviteAuthorityHosted {
		if request.ExpiresAfter != 0 {
			return mintedTeamInvite{}, usageError("--expires selects a local controller invite lifetime; the hosted service sets its own expiry")
		}
		created, err := createHostedTeamInvite(request)
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

func validateInviteMemberScope(scope teamInviteMemberScope) error {
	switch scope {
	case inviteMemberLocal, inviteMemberGlobal:
		return nil
	default:
		return usageError("invitation member scope must be local or global")
	}
}

// Preflight reads the same lifetime owner as controller minting and creates no
// bearer or child invitation (docs/cli-integration-contract.md:131-147).
func preflightTeamInviteMint(request teamInviteMintRequest) (teamInvitePreflightOutput, error) {
	if err := validateInviteMemberScope(request.Scope); err != nil {
		return teamInvitePreflightOutput{}, err
	}
	out := teamInvitePreflightOutput{TeamID: awid.BuildTeamID(request.Plan.Source.Domain, request.Plan.Source.Team), Kind: request.Plan.Kind}
	switch request.Plan.Kind {
	case inviteAuthorityHosted:
		if request.Scope != inviteMemberLocal {
			return out, usageError("--member-global is not supported for hosted team invites")
		}
		if request.ExpiresAfter != 0 {
			return out, usageError("--expires selects a local controller invite lifetime; the hosted service sets its own expiry")
		}
	case inviteAuthorityController:
		lifetime, err := resolveControllerInviteLifetime(awconfig.TeamInviteLifetimeRequest{Now: time.Now(), Duration: request.ExpiresAfter})
		if err != nil {
			return out, err
		}
		out.ExpiryKnown, out.ExpiresAt = true, lifetime.ExpiresAt.Format(time.RFC3339Nano)
	default:
		return out, usageError("unknown invite authority; select the team and retry")
	}
	return out, nil
}

func init() {
	teamInviteCmd.Flags().StringVar(&teamHumanInviteTeamID, "team-id", "", "Canonical team ID; use instead of --team and --namespace")
	teamInviteCmd.MarkFlagsMutuallyExclusive("team-id", "team")
	teamInviteCmd.MarkFlagsMutuallyExclusive("team-id", "namespace")
	for _, cmd := range []*cobra.Command{teamInviteCmd, teamHumanInviteCmd} {
		cmd.Flags().BoolVar(&teamInvitePreflight, "preflight", false, "Show the mint authority without creating a token or child invitation")
		cmd.Flags().DurationVar(&teamInviteExpiresAfter, "expires", 0, "Controller invite lifetime (default 24h; maximum 720h)")
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		cmd.Annotations[identityReadOnlyFlagAnnotation] = "preflight"
	}
}
