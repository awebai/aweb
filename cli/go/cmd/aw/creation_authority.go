package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const creationWorkspaceNotice = "Using this workspace's signed invitation; the supplied agent API key is not creating the child."
const creationA5 = "This is an agent's workspace key. Run creation from that agent's workspace, or use a setup key from the dashboard. To create here from another workspace, use aw init --join-from <workspace>."

type creationAuthorityMode string

const (
	creationAuthorityUnselected creationAuthorityMode = ""
	creationAuthorityAPI        creationAuthorityMode = "api"
	creationAuthorityInvitation creationAuthorityMode = "invitation"
	creationAuthorityController creationAuthorityMode = "controller"
)

type creationKeyKind string

const (
	creationKeyKindUnspecified creationKeyKind = ""
	creationKeyKindPerson      creationKeyKind = "person"
	creationKeyKindWorkspace   creationKeyKind = "workspace"
)

type agentCreationRequest struct {
	WorkingDir    string
	APIKey        string
	AwebURL       string
	RequestedTeam string
	SelectedTeam  *apiKeyCreationTeam
}

type creationAuthorityInput struct {
	SuppliedKey     bool
	KeyKind         creationKeyKind
	SourceTeam      string
	RequestedTeam   string
	LocalController bool
}

type creationAuthority struct {
	Mode         creationAuthorityMode
	Notice       string
	SelectedTeam *apiKeyCreationTeam
	SourceTeam   string
}

// Only an authoritative workspace classification changes a supplied key's
// behavior. Missing and future kinds retain the released API path.
// Implements docs/grow-team.md:38-56 and docs/cli-identity-selection.md:43-49.
func decideCreationAuthority(in creationAuthorityInput) (creationAuthority, error) {
	if in.SuppliedKey && in.KeyKind != creationKeyKindWorkspace {
		return creationAuthority{Mode: creationAuthorityAPI}, nil
	}
	if in.SourceTeam != "" && (in.RequestedTeam == "" || in.SourceTeam == in.RequestedTeam) {
		mode := creationAuthorityInvitation
		if in.LocalController {
			mode = creationAuthorityController
		}
		notice := ""
		if in.SuppliedKey {
			notice = creationWorkspaceNotice
		}
		return creationAuthority{Mode: mode, Notice: notice, SourceTeam: in.SourceTeam}, nil
	}
	if in.SuppliedKey {
		if in.SourceTeam != "" {
			return creationAuthority{}, fmt.Errorf("This workspace belongs to %s, not %s. %s", in.SourceTeam, in.RequestedTeam, creationA5)
		}
		return creationAuthority{}, fmt.Errorf("%s", creationA5)
	}
	return creationAuthority{}, nil
}

// Inspect the selected acting principal, never a stored workspace API key.
// Issuer ancestry and current membership authority are verified by the existing
// invitation path when it signs; this preflight only selects that path.
func resolveAgentCreation(request agentCreationRequest) (creationAuthority, error) {
	input := creationAuthorityInput{SuppliedKey: strings.TrimSpace(request.APIKey) != "", RequestedTeam: request.RequestedTeam}
	selected := request.SelectedTeam
	if input.SuppliedKey {
		if selected == nil {
			ctx, cancel := commandAPIContext(nil)
			var err error
			selected, err = readAPIKeyCreationTeam(ctx, request.AwebURL, request.APIKey)
			cancel()
			if err != nil {
				return creationAuthority{}, err
			}
		}

		input.KeyKind = selected.APIKeyKind
		if input.KeyKind != creationKeyKindWorkspace {
			decision, err := decideCreationAuthority(input)
			decision.SelectedTeam = selected
			return decision, err
		}
		if request.RequestedTeam == "" {
			input.RequestedTeam = selected.CanonicalTeamID
		}
	}
	home, err := identityHomeForDir(request.WorkingDir)
	if err != nil {
		return creationAuthority{}, err
	}
	workspace, teams, _, err := loadCurrentWorkspaceAndTeamState(request.WorkingDir, externalIdentityHomeRoot(home))
	if err != nil && !os.IsNotExist(err) {
		return creationAuthority{}, err
	}
	if err == nil {
		membership := awconfig.ActiveMembershipFor(workspace, teams)
		if membership != nil {
			domain, team, err := awid.ParseTeamID(membership.TeamID)
			if err != nil {
				return creationAuthority{}, err
			}
			input.LocalController, err = awconfig.TeamKeyExists(domain, team)
			if err != nil {
				return creationAuthority{}, err
			}
			key, err := loadOptionalWorktreeSigningKey(request.WorkingDir)
			if err != nil {
				return creationAuthority{}, err
			}
			if input.LocalController {
				input.SourceTeam = membership.TeamID
			} else if key != nil {
				path, err := awconfig.IdentityHomePath(home, awconfig.TeamCertificateRelativePath(membership.TeamID))
				if err != nil {
					return creationAuthority{}, err
				}
				cert, err := awid.LoadTeamCertificate(path)
				if err != nil {
					return creationAuthority{}, err
				}
				if cert.MemberDIDKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
					return creationAuthority{}, fmt.Errorf("workspace signing key does not match its team certificate")
				}
				input.SourceTeam = membership.TeamID
			}
		}
	}
	decision, err := decideCreationAuthority(input)
	decision.SelectedTeam = selected
	return decision, err
}

func printCreationAuthority(decision creationAuthority) {
	if decision.Notice != "" {
		fmt.Fprintln(os.Stderr, decision.Notice)
	}
}

const creationAuthorityHelp = "Creation authority comes from the creator's native signing workspace, never its stored workspace API key. A supplied person's setup key takes the API path. A supplied workspace key uses the signing workspace for the requested team. Older servers and unknown api_key_kind values keep the existing API path.\n\n" + creationWorkspaceNotice + "\n\n" + creationA5
