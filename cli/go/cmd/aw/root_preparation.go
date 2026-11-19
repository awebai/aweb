package main

import (
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
	"os"
)

func prepareRootCommand(cmd *cobra.Command, args []string) error {
	if _, independent := offlineCommands[cmd]; independent {
		return nil // Export verification never selects or unlocks an acting human.
	}
	idSelection, err := prepareIDHumanSelection(cmd)
	if err != nil {
		return err
	}
	if idSelection && humanFlag != "" {
		return nil
	}
	if cmd.Annotations[humanCommandAnnotation] != "" && !humanSelectionRequested() {
		return usageError("select your human key with --human ID --human-domain DOMAIN; prepare it with aw id human init")
	}
	if humanSelectionRequested() && !idSelection {
		return prepareHumanParticipation(cmd)
	}
	// Offline key preparation validates its explicit destination itself.
	// Do not renew keys or contact update services before its two-state
	// check, including on a refusal.
	if flag := cmd.Annotations[identityKeyPreparationAnnotation]; flag != "" && cmd.Flags().Changed(flag) {
		enabled, _ := cmd.Flags().GetBool(flag)
		if enabled {
			return nil
		}
	}
	// Explicit Claude settings cleanup uses cwd only; no credential selection,
	// assertion renewal or update checks are needed for this local action.
	if isIdentityHomeNeutralCommand(cmd) || (cmd == initCmd && initRemoveNotifyHook) {
		return nil
	}
	if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
		debugFlag = true
	}
	if traceFlag {
		_ = os.Setenv("AW_TRACE", "1")
	}
	identityHomeEnv, hadIdentityHomeEnv := os.LookupEnv(awconfig.IdentityHomeEnv)
	previousActiveIdentityHome := activeIdentityHome
	home, err := awconfig.ResolveIdentityHome("", identityHomeFlag)
	if err != nil {
		return err
	}
	pendingExchange, err := pendingHostedExchangeTarget(cmd, home)
	if err != nil {
		return err
	}
	if home.External() {
		// A fresh destination is meaningful only when explicitly named for an
		// operation which creates identity state. An inherited selector is
		// always an acting principal, never an implicit creation destination.
		freshTarget := home.Source == awconfig.IdentityHomeFlag && cmd.Annotations[identityCreationTargetAnnotation] == "true"
		keyOnlyTarget := false
		if home.Source == awconfig.IdentityHomeFlag && cmd.Annotations[identityKeyOnlyTargetAnnotation] == "true" {
			path, pathErr := awconfig.IdentityHomePath(home, "signing.key")
			if pathErr == nil {
				keyOnlyTarget, _ = teamRequestKeyOnly(home.Root, path)
			}
		}
		if !freshTarget && !keyOnlyTarget && !pendingExchange {
			if err := validateSelectedIdentityHome(home); err != nil {
				return err
			}
		}
	}
	activeIdentityHome = awconfig.IdentityHome{}
	if home.External() {
		_ = os.Setenv(awconfig.IdentityHomeEnv, home.Root)
		activeIdentityHome = home
	}
	restoreIdentityHomeAfterCommand(cmd, identityHomeEnv, hadIdentityHomeEnv, previousActiveIdentityHome)
	if pendingExchange {
		return nil
	}
	if cmd == idCreateCmd && (cmd.Flags().Changed("org") || cmd.Flags().Changed("owner-identity-home") || cmd.Flags().Changed("no-address") || cmd.Flags().Changed("local")) {
		// Validate the original creation association before any key renewal or network work.
		return nil
	}
	if cmd == teamInstallCertCmd {
		// Check the certificate before any key renewal or network work; a
		// verified install ensures the encryption key itself.
		return nil
	}
	if isAgentStatusCommand(cmd) || isActivityCommand(cmd) {
		return nil // Producer commands never renew encryption keys or check updates.
	}
	if !isTeamInviteInspectCommand(cmd) && cmd.Name() != "help" {
		maybeRenewIdentityEncryptionAssertion(cmd.Context(), mustGetwd(), currentEncryptionKeyIdentityHome(), cmd.ErrOrStderr())
	}
	maybeCheckLatestVersion(cmd)
	return nil
}
