package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// createHostedTeamInvite prepares the creator's exchange before minting
// a bearer (docs/id-tree-invite-issuance.md:16-24). Once minted, a failure to
// retain its local link cannot undo the service effect or discard its token.
func createHostedTeamInvite(request teamInviteMintRequest) (*awid.SpawnCreateInviteResponse, error) {
	if err := validateInviteMemberScope(request.Scope); err != nil {
		return nil, err
	}
	if request.ForHuman != nil {
		if err := validateInviteHuman(*request.ForHuman); err != nil {
			return nil, err
		}
	}
	if request.ExpiresAfter != 0 {
		return nil, usageError("--expires selects a local controller invite lifetime; the hosted service sets its own expiry")
	}
	source := request.Plan.Source
	workingDir, identityHome := source.WorkingDir, externalIdentityHomeRoot(source.Home)
	teamID := awid.BuildTeamID(source.Domain, source.Team)
	requested := request.ForHuman
	var client *aweb.Client
	var selected *awconfig.Selection
	var err error
	if strings.TrimSpace(identityHome) != "" {
		home := awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
		client, selected, err = resolveClientSelectionAtIdentityHomeWithTeamOverride(workingDir, teamID, home)
	} else {
		client, selected, err = resolveClientSelectionForDirWithTeamOverride(workingDir, teamID)
	}
	if err != nil {
		return nil, fmt.Errorf(
			"no local team controller key for %s and cloud-hosted invite authority is unavailable: %w",
			teamID,
			err,
		)
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	chain, err := awconfig.LoadInstalledIDChain(selected.IdentityHome)
	if err != nil {
		return nil, err
	}
	var bundle map[string]any
	var issuerID, issuerDomain string
	var link *awconfig.TeamInviteIDChild
	if chain != nil {
		leaf, err := chain.Leaf()
		if err != nil {
			return nil, err
		}
		issuerID, issuerDomain = leaf.ID(), leaf.Domain()
		subject := selected.StableID
		if subject == "" {
			subject = selected.DID
		}
		if issuerID != subject || leaf.Kind() != awid.IDCertificateKindAgent {
			return nil, errors.New("hosted invites require the selected agent's own chain")
		}
		bundle = chain.Bundle
		link, _, err = prepareTeamInviteAuthority(ctx, teamInviteAuthorityRequest{
			Issuer: idChildOptions{WorkingDir: workingDir, IdentityHome: selected.IdentityHome, Now: time.Now},
			Child:  inviteCreatesChild, ForHuman: requested,
		})
		if err != nil {
			return nil, err
		}
	}
	created, err := client.CreateSpawnInvite(ctx, &awid.SpawnCreateInviteRequest{
		IDChain:    bundle,
		ForHuman:   requested,
		AccessMode: "open",
		MaxUses:    1,
	})
	if err != nil {
		return nil, fmt.Errorf("create hosted team invite: %w", err)
	}
	if requested != nil && (created.ForHuman == nil || *created.ForHuman != *requested) {
		return nil, errors.New("hosted service did not retain --for-human; upgrade the service before issuing this invite")
	}
	if chain != nil && (created.IDTree != nil || requested == nil) {
		if created.IDTree == nil || created.IDTree.V != 1 || created.IDTree.IssuerID != issuerID || created.IDTree.Domain != issuerDomain || awid.IDCertificateKind(created.IDTree.ChildKind) != awid.IDCertificateKindAgent || (created.IDTree.Mode != awid.IDInvitationHostManaged && created.IDTree.Mode != awid.IDInvitationSelfCustodial) {
			return nil, errors.New("hosted invite did not retain the selected agent issuer binding")
		}
	}
	if strings.TrimSpace(created.Token) == "" {
		return nil, fmt.Errorf("hosted team invite response is missing token")
	}
	if chain != nil && created.IDTree != nil && created.IDTree.Mode == awid.IDInvitationSelfCustodial {
		if link == nil || link.Parent != created.IDTree.IssuerID || link.Domain != created.IDTree.Domain {
			return nil, errors.New("hosted invite child link differs from the selected issuer")
		}
		if err := awconfig.SaveTeamInvite(&awconfig.TeamInvite{
			InviteID: hostedTeamInviteRecordID(created.Token),
			Domain:   source.Domain, TeamName: source.Team,
			IdentityScope: string(request.Scope), IDChild: link,
		}); err != nil {
			log.New(os.Stderr, "", 0).Printf("Hosted invite created; local creator link could not be saved: %v. Keep the returned invite; the joiner can select this creator with --parent %s or complete the parent request/import exchange.", err, selected.IdentityHome)
		}
	}
	return created, nil
}
