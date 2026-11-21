package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
)

type teamAgentProfileSetup struct {
	Plan *teamHumanAddedAgent
	Home awconfig.IdentityHome
}

func completePlannedTeamAgentProfile(request teamAgentProfileSetup) error {
	if request.Plan == nil || strings.TrimSpace(request.Home.Root) == "" {
		return errors.New("profile completion requires its member plan and identity home")
	}
	plan := request.Plan
	if plan.Profile == nil {
		return nil
	}
	if strings.TrimSpace(plan.LocalBlueprintDir) != "" {
		if _, _, err := applyLocalBlueprintProfileToHome(plan.HomeDir, *plan.Profile, plan.LocalBlueprintDir, true); err != nil {
			return err
		}
	} else if _, _, err := applyTeamLibraryProfileToHome(plan.HomeDir, *plan.Profile, plan.Source, true); err != nil {
		return err
	}
	if !plan.ProfileRoleConnected {
		selected, err := resolveSelectionAtIdentityHome(plan.HomeDir, "", request.Home)
		if err != nil {
			return err
		}
		if selected == nil || strings.TrimSpace(selected.AwebURL) == "" {
			return errors.New("profile completion requires the admitted member's service URL")
		}
		if _, err := initCertificateConnectWithOptions(plan.HomeDir, strings.TrimSpace(selected.AwebURL), certificateConnectOptions{Role: strings.TrimSpace(plan.Profile.ProfileRef), IdentityHome: request.Home.Root}); err != nil {
			return fmt.Errorf("connect agent to aweb service: %w", err)
		}
	}
	return configureMaterializedAgentHome(plan.HomeDir, request.Home)
}
