package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// resolveMailSenderClientSelection carries the selected membership's actual
// certificate on address-dependent sends (trust-model.md:186-191). A stored
// membership can select a sender without manufacturing a workspace binding.
// Inbox/history continue to use their separate identity-scoped selection.
func resolveMailSenderClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	if activeHuman != nil {
		return activeHuman.client(teamFlag, "")
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return nil, nil, err
	}
	if awconfig.IsGrantHome(home.Root) {
		return resolveClientSelection()
	}
	selection, err := resolveSelectionForDir(wd)
	if err != nil {
		return nil, nil, err
	}
	if selection.WorkspacePath != "" {
		// A failed certificate check must remain a refusal, rather than silently
		// discarding the explicit member context and sending as a bare identity.
		return resolveClientSelection()
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home.Root)
	if errors.Is(err, os.ErrNotExist) {
		return resolveMailMessagingClientSelection()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("sender context is unknown: %w; repair this identity home's team state and pass --team", err)
	}
	member := state.ActiveMembership()
	if strings.TrimSpace(teamFlag) != "" {
		member = state.Membership(teamFlag)
	}
	if member == nil {
		return nil, nil, usageError("sender address is not selected; pass --team <team-id> for an installed membership")
	}
	return mailSenderFromMembership(selection, home, member)
}

func resolveMailContinuationClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	client, selection, err := resolveMailSenderClientSelection()
	var mismatch *awid.TeamCertificateKeyMismatchError
	if !errors.As(err, &mismatch) {
		return client, selection, err
	}
	recovery := fmt.Errorf("%w; ask the team controller to reissue a certificate for the current signing key", err)
	if strings.TrimSpace(teamFlag) != "" || activeHuman != nil {
		return nil, nil, recovery
	}
	// A global participant keeps its own conversation after key rotation. Use
	// the current identity credential so the server verifies the did:aw and
	// stored participant route again. This grants no team authority.
	identity, err := resolveIdentity()
	if err != nil || identity.IdentityScope != awid.IdentityModeGlobal || identity.Custody != awid.CustodySelf ||
		!strings.HasPrefix(identity.StableID, "did:aw:") || identity.StableID != mismatch.MemberDIDAW || identity.DID != mismatch.SigningDIDKey {
		return nil, nil, recovery
	}
	client, selection, err = resolveIdentityMessagingClientSelection()
	if err != nil {
		return nil, nil, err
	}
	if client.StableID() != identity.StableID || client.DID() != identity.DID {
		return nil, nil, recovery
	}
	selection.DID = client.DID()
	return client, selection, nil
}

func mailSenderFromMembership(selection *awconfig.Selection, home awconfig.IdentityHome, member *awconfig.TeamMembership) (*aweb.Client, *awconfig.Selection, error) {
	certPath, err := awconfig.IdentityHomeStoredPath(home, member.CertPath)
	if err != nil {
		return nil, nil, err
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load selected sender certificate: %w; fetch the team's current certificate", err)
	}
	if cert.Team != member.TeamID {
		return nil, nil, errors.New("the selected sender certificate names another team; repair this membership's certificate")
	}
	selected := *selection
	selected.IdentityHome = home.Root
	selected.TeamID = member.TeamID
	selected.Alias = cert.Alias
	selected.DID = cert.MemberDIDKey
	selected.StableID = cert.MemberDIDAW
	selected.Address = cert.MemberAddress
	selected.IdentityScope = cert.IdentityScope
	selected.RegistryURL = firstNonEmpty(member.RegistryURL, selected.RegistryURL)
	selected.Domain, _, err = awid.ParseTeamID(member.TeamID)
	if err != nil {
		return nil, nil, err
	}
	selected.AwebURL = member.AwebURL
	base := firstNonEmpty(strings.TrimSpace(os.Getenv("AWEB_URL")), member.AwebURL)
	if base == "" {
		return nil, nil, usageError("the selected sender membership has no server URL; run aw workspace connect --team %s --service <url>", member.TeamID)
	}
	selected.BaseURL, err = resolveAuthenticatedBaseURL(base)
	if err != nil {
		return nil, nil, err
	}
	if err := recheckUnconfirmedTeamKey(&selected, cert); err != nil {
		return nil, nil, err
	}
	selected.SigningKey, err = awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, nil, err
	}
	key, err := awid.LoadSigningKey(selected.SigningKey)
	if err != nil {
		return nil, nil, err
	}
	client, err := aweb.NewWithCertificate(selected.BaseURL, key, cert)
	if err != nil {
		return nil, nil, err
	}
	if err := configureResolvedClient(client, &selected, selected.BaseURL); err != nil {
		return nil, nil, err
	}
	client.SetTeamCertificateRefresh(func(ctx context.Context) (string, error) { return refreshOwnTeamCertificate(ctx, &selected, home.Root) })
	lastClient = client
	return client, &selected, nil
}
