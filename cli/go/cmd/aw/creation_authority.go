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

// creationAuthorityInput holds the facts the creation decision reads. The
// caller reads local facts only when takesAPIPath is false, and the team
// certificate only when needsCertificate is true.
type creationAuthorityInput struct {
	SuppliedKey     bool
	KeyKind         creationKeyKind
	KeyTeam         string
	RequestedTeam   string
	ActiveTeam      string
	LocalController bool
	SigningKeyDID   string
	CertificateDID  string
}

type creationAuthority struct {
	Mode         creationAuthorityMode
	Notice       string
	SelectedTeam *apiKeyCreationTeam
	SourceTeam   string
}

// Only an authoritative workspace classification changes a supplied key's
// behavior. Missing and future kinds retain the released API path.
func (in creationAuthorityInput) takesAPIPath() bool {
	return in.SuppliedKey && in.KeyKind != creationKeyKindWorkspace
}

// A local controller signs with the team key; any other member signer must
// hold the key its team certificate names.
func (in creationAuthorityInput) needsCertificate() bool {
	return in.ActiveTeam != "" && !in.LocalController && in.SigningKeyDID != ""
}

// Implements docs/grow-team.md:38-56 and docs/cli-identity-selection.md:43-49.
func decideCreationAuthority(in creationAuthorityInput) (creationAuthority, error) {
	if in.takesAPIPath() {
		return creationAuthority{Mode: creationAuthorityAPI}, nil
	}
	if in.needsCertificate() && in.CertificateDID != in.SigningKeyDID {
		return creationAuthority{}, errors.New("workspace signing key does not match its team certificate")
	}
	sourceTeam := ""
	if in.ActiveTeam != "" && (in.LocalController || in.SigningKeyDID != "") {
		sourceTeam = in.ActiveTeam
	}
	requestedTeam := in.RequestedTeam
	if in.SuppliedKey && requestedTeam == "" {
		requestedTeam = in.KeyTeam
	}
	if sourceTeam != "" && (requestedTeam == "" || sourceTeam == requestedTeam) {
		mode := creationAuthorityInvitation
		if in.LocalController {
			mode = creationAuthorityController
		}
		notice := ""
		if in.SuppliedKey {
			notice = creationWorkspaceNotice
		}
		return creationAuthority{Mode: mode, Notice: notice, SourceTeam: sourceTeam}, nil
	}
	if in.SuppliedKey {
		if sourceTeam != "" {
			return creationAuthority{}, fmt.Errorf("This workspace belongs to %s, not %s. %s", sourceTeam, requestedTeam, creationA5)
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
		input.KeyTeam = selected.CanonicalTeamID
	}
	if !input.takesAPIPath() {
		if err := readLocalCreationFacts(request.WorkingDir, &input); err != nil {
			return creationAuthority{}, err
		}
	}
	decision, err := decideCreationAuthority(input)
	decision.SelectedTeam = selected
	return decision, err
}

// readLocalCreationFacts reads the working directory's active membership, its
// team key and signing key, and the team certificate when the decision needs it.
func readLocalCreationFacts(workingDir string, input *creationAuthorityInput) error {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	workspace, teams, _, err := loadCurrentWorkspaceAndTeamState(workingDir, externalIdentityHomeRoot(home))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	membership := awconfig.ActiveMembershipFor(workspace, teams)
	if membership == nil {
		return nil
	}
	domain, team, err := awid.ParseTeamID(membership.TeamID)
	if err != nil {
		return err
	}
	input.ActiveTeam = membership.TeamID
	input.LocalController, err = awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return err
	}
	key, err := loadOptionalWorktreeSigningKey(workingDir)
	if err != nil {
		return err
	}
	if key != nil {
		input.SigningKeyDID = awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	}
	if !input.needsCertificate() {
		return nil
	}
	path, err := awconfig.IdentityHomePath(home, awconfig.TeamCertificateRelativePath(membership.TeamID))
	if err != nil {
		return err
	}
	cert, err := awid.LoadTeamCertificate(path)
	if err != nil {
		return err
	}
	input.CertificateDID = cert.MemberDIDKey
	return nil
}

func printCreationAuthority(decision creationAuthority) {
	if decision.Notice != "" {
		fmt.Fprintln(os.Stderr, decision.Notice)
	}
}

const creationAuthorityHelp = "Creation authority comes from the creator's native signing workspace, never its stored workspace API key. A supplied person's setup key takes the API path. A supplied workspace key uses the signing workspace for the requested team. Older servers and unknown api_key_kind values keep the existing API path.\n\n" + creationWorkspaceNotice + "\n\n" + creationA5
