package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// createHostedTeamInvite creates a single-use hosted invite and returns the
// service's response, which carries its expiry.
func createHostedTeamInvite(workingDir, identityHome, teamID string, localMember bool, forHuman ...string) (*awid.SpawnCreateInviteResponse, error) {
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
	if chain != nil {
		bundle = chain.Bundle
		certificates := bundle["certificates"].([]any)
		leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
		subject := selected.StableID
		if subject == "" {
			subject = selected.DID
		}
		if leaf["id"] != subject || leaf["kind"] != "agent" {
			return nil, errors.New("hosted invites require the selected agent's own chain")
		}
	}
	requested, err := requestedInviteHuman(forHuman)
	if err != nil {
		return nil, err
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
		certificates := bundle["certificates"].([]any)
		leaf := certificates[len(certificates)-1].(map[string]any)["certificate"].(map[string]any)
		if created.IDTree == nil || created.IDTree.V != 1 || created.IDTree.IssuerID != leaf["id"] || created.IDTree.Domain != leaf["domain"] || created.IDTree.ChildKind != "agent" || (created.IDTree.Mode != "host_managed" && created.IDTree.Mode != "self_custodial") {
			return nil, errors.New("hosted invite did not retain the selected agent issuer binding")
		}
	}
	if strings.TrimSpace(created.Token) == "" {
		return nil, fmt.Errorf("hosted team invite response is missing token")
	}
	if chain != nil && created.IDTree != nil && created.IDTree.Mode == "self_custodial" {
		link, err := prepareTeamInviteIDChild(ctx, idChildOptions{WorkingDir: workingDir, IdentityHome: selected.IdentityHome, Now: time.Now})
		if err != nil {
			return nil, err
		}
		if link == nil || link.Parent != created.IDTree.IssuerID || link.Domain != created.IDTree.Domain {
			return nil, errors.New("hosted invite child link differs from the selected issuer")
		}
		domain, name, err := awid.ParseTeamID(teamID)
		if err != nil {
			return nil, err
		}
		if err := awconfig.SaveTeamInvite(&awconfig.TeamInvite{
			InviteID: hostedTeamInviteRecordID(created.Token),
			Domain:   domain, TeamName: name,
			IdentityScope: teamAcceptScopeFromGlobal(!localMember), IDChild: link,
		}); err != nil {
			return nil, err
		}
	}
	return created, nil
}
