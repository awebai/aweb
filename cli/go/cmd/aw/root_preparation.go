package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type rootPreparationMode string

const (
	rootPreparationOffline   rootPreparationMode = "offline"
	rootPreparationNeutral   rootPreparationMode = "identity-neutral"
	rootPreparationLocalOnly rootPreparationMode = "local-only"
	rootPreparationNoRenewal rootPreparationMode = "no-renewal"
	rootPreparationFull      rootPreparationMode = "full"

	rootPreparationAnnotation = "aw.root-preparation"
	rootLocalFlagsAnnotation  = "aw.root-local-flags"
	rootNeutralFlagAnnotation = "aw.root-neutral-flag"
)

func init() {
	// These capabilities apply to a command's descendants unless a leaf
	// declares another mode. They do not alter its own admission or authority.
	for command, mode := range map[*cobra.Command]rootPreparationMode{
		activityCmd:          rootPreparationLocalOnly,
		statusCmd:            rootPreparationLocalOnly,
		statusHostCmd:        rootPreparationLocalOnly,
		teamInstallCertCmd:   rootPreparationLocalOnly,
		teamInviteInspectCmd: rootPreparationNoRenewal,
	} {
		if command.Annotations == nil {
			command.Annotations = make(map[string]string)
		}
		command.Annotations[rootPreparationAnnotation] = string(mode)
	}
	idCreateCmd.Annotations[rootLocalFlagsAnnotation] = "org owner-identity-home no-address local"
	initCmd.Annotations[rootNeutralFlagAnnotation] = "remove-notify-hook"
}

// rootPreparationForCommand assigns identity and maintenance behavior before
// execution. Offline artifacts never select an actor; neutral operations keep
// their explicit human selection but do not load a principal (CLI identity
// selection §State classification). Local producers retain home admission.
func rootPreparationForCommand(command *cobra.Command) (rootPreparationMode, error) {
	if _, independent := offlineCommands[command]; independent {
		return rootPreparationOffline, nil
	}
	if isIdentityHomeNeutralCommand(command) {
		return rootPreparationNeutral, nil
	}
	if flag := command.Annotations[rootNeutralFlagAnnotation]; flag != "" {
		enabled, err := command.Flags().GetBool(flag)
		if err != nil {
			return "", err
		}
		if enabled {
			return rootPreparationNeutral, nil
		}
	}
	if flag := command.Annotations[identityKeyPreparationAnnotation]; flag != "" && command.Flags().Changed(flag) {
		enabled, err := command.Flags().GetBool(flag)
		if err != nil {
			return "", err
		}
		if enabled {
			return rootPreparationNeutral, nil
		}
	}
	for _, flag := range strings.Fields(command.Annotations[rootLocalFlagsAnnotation]) {
		if command.Flags().Changed(flag) {
			return rootPreparationLocalOnly, nil
		}
	}
	for current := command; current != nil; current = current.Parent() {
		mode := rootPreparationMode(current.Annotations[rootPreparationAnnotation])
		switch mode {
		case "":
			continue
		case rootPreparationOffline, rootPreparationNeutral, rootPreparationLocalOnly, rootPreparationNoRenewal, rootPreparationFull:
			return mode, nil
		default:
			return "", fmt.Errorf("invalid command preparation mode %q for %s", mode, current.CommandPath())
		}
	}
	if command.Annotations[identityNoRenewalAnnotation] == "true" {
		return rootPreparationLocalOnly, nil
	}
	if flag := command.Annotations[identityReadOnlyFlagAnnotation]; flag != "" {
		readOnly, err := command.Flags().GetBool(flag)
		if err != nil {
			return "", err
		}
		if readOnly {
			return rootPreparationLocalOnly, nil
		}
	}
	if command.Name() == "help" {
		return rootPreparationNoRenewal, nil
	}
	return rootPreparationFull, nil
}

func prepareRootCommand(command *cobra.Command, args []string) error {
	if command.Annotations[offlineIdentityInspectionAnnotation] == "true" {
		return prepareOfflineIdentityInspection(command, args)
	}
	mode, err := rootPreparationForCommand(command)
	if err != nil || mode == rootPreparationOffline {
		return err
	}
	humanSelected, err := prepareRootHuman(command)
	if err != nil || humanSelected == rootHumanSelected || mode == rootPreparationNeutral {
		return err
	}
	selected, err := prepareRootIdentityHome(command)
	if err != nil || selected.PendingExchange {
		return err
	}
	switch mode {
	case rootPreparationLocalOnly:
		return nil
	case rootPreparationFull:
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("read working directory: %w", err)
		}
		maybeRenewIdentityEncryptionAssertion(command.Context(), workingDir, currentEncryptionKeyIdentityHome(), command.ErrOrStderr())
	}
	maybeCheckLatestVersion(command)
	return nil
}

type rootHumanSelection uint8

const (
	rootHumanNotSelected rootHumanSelection = iota
	rootHumanSelected
)

func prepareRootHuman(command *cobra.Command) (rootHumanSelection, error) {
	idSelection, err := prepareIDHumanSelection(command)
	if err != nil {
		return rootHumanNotSelected, err
	}
	if idSelection && humanFlag != "" {
		return rootHumanSelected, nil
	}
	if command.Annotations[humanCommandAnnotation] != "" && !humanSelectionRequested() {
		return rootHumanNotSelected, usageError("select your human key with --human ID --human-domain DOMAIN; prepare it with aw id human init")
	}
	if humanSelectionRequested() && !idSelection {
		return rootHumanSelected, prepareHumanParticipation(command)
	}
	return rootHumanNotSelected, nil
}

type rootIdentitySelection struct {
	Home            awconfig.IdentityHome
	PendingExchange bool
}

func prepareRootIdentityHome(command *cobra.Command) (rootIdentitySelection, error) {
	if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
		debugFlag = true
	}
	if traceFlag {
		if err := os.Setenv("AW_TRACE", "1"); err != nil {
			return rootIdentitySelection{}, err
		}
	}
	home, err := awconfig.ResolveIdentityHome("", identityHomeFlag)
	if err != nil {
		return rootIdentitySelection{}, err
	}
	pending, err := pendingHostedExchangeTarget(command, home)
	if err != nil {
		return rootIdentitySelection{}, err
	}
	selected := rootIdentitySelection{Home: home, PendingExchange: pending}
	if err := validateRootIdentityTarget(command, selected); err != nil {
		return rootIdentitySelection{}, err
	}
	previous := captureIdentityHomeEnvironment()
	if home.External() {
		if err := os.Setenv(awconfig.IdentityHomeEnv, home.Root); err != nil {
			return rootIdentitySelection{}, err
		}
		activeIdentityHome = home
	} else {
		activeIdentityHome = awconfig.IdentityHome{}
	}
	restoreIdentityHomeAfterCommand(command, previous)
	return selected, nil
}

// validateRootIdentityTarget preserves the explicit empty/key-only destination
// exceptions in docs/cli-identity-selection.md. An inherited home is always an
// actor, never an implicit creation target.
func validateRootIdentityTarget(command *cobra.Command, selected rootIdentitySelection) error {
	home := selected.Home
	if !home.External() || selected.PendingExchange {
		return nil
	}
	if home.Source == awconfig.IdentityHomeFlag {
		if command.Annotations[identityCreationTargetAnnotation] == "true" {
			return nil
		}
		if command.Annotations[identityKeyOnlyTargetAnnotation] == "true" {
			path, err := awconfig.IdentityHomePath(home, "signing.key")
			if err != nil {
				return err
			}
			keyOnly, err := teamRequestKeyOnly(home.Root, path)
			if err == nil && keyOnly {
				return nil
			}
			// A complete existing principal is also a valid fetch target. The
			// key-only classifier's structural refusal does not reject it;
			// normal home validation owns the existing-principal error.
			if err != nil {
				return validateSelectedIdentityHome(home)
			}
		}
	}
	return validateSelectedIdentityHome(home)
}
