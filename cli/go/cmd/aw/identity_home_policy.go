package main

import "github.com/spf13/cobra"

// identityHomeNeutralCommandExemptions is the complete pointer-identity set of
// commands that never access principal state and therefore skip initialization.
// Its exact population and real-binary behavior are guarded in tests.
var identityHomeNeutralCommandExemptions = map[*cobra.Command]struct{}{
	pinStoreCompareAndSetCmd: {},
	versionCmd:               {},
	upgradeCmd:               {},
}

// offlineCommands is the complete pointer-identity set of commands that verify
// exported inputs without principal state (aw verify also reads DNS/public status).
// No identity home is resolved for them, not
// even the pre-dispatch selector that plugins need, so no principal selector,
// however stale or malformed, can stop them. Each is also identity-home neutral.
var offlineCommands = map[*cobra.Command]struct{}{}

// namesOfflineCommand is whether argv names an offline command.
func namesOfflineCommand(args []string) bool {
	cmd, _, err := rootCmd.Find(args)
	if err != nil {
		return false
	}
	_, ok := offlineCommands[cmd]
	return ok || answersOfflineAsJSON(cmd, argsContainJSONFlag(args))
}

// offlineJSONCommands answer under --json before any identity exists: the
// framework reads aw's JSON version from the binary it will run, with no
// identity, update check or network. Their text output keeps root preparation.
var offlineJSONCommands = map[*cobra.Command]struct{}{versionCmd: {}}

func answersOfflineAsJSON(cmd *cobra.Command, asJSON bool) bool {
	_, ok := offlineJSONCommands[cmd]
	return ok && asJSON
}

func isIdentityHomeNeutralCommand(cmd *cobra.Command) bool {
	_, ok := identityHomeNeutralCommandExemptions[cmd]
	return ok || (cmd.Annotations[hostHumanOrgAnnotation] == "true" && cmd.Flags().Changed("org"))
}

// Creation targets may be fresh only when explicitly selected by flag. This
// does not confer command authority or permit overwriting an inherited actor.
const identityCreationTargetAnnotation = "aw.identity-creation-target"

// Only explicit organization selection uses host-human authority without a principal.
const hostHumanOrgAnnotation = "aw.host-human-org"

// A marked preparation flag validates an empty/key-only destination itself and
// must not run optional renewal or update traffic before that validation.
const identityKeyPreparationAnnotation = "aw.identity-key-preparation-flag"

// Only marked commands may take the explicit key-only -> certificate transition.
// This never relaxes identity selection for an inherited home or other commands.
const identityKeyOnlyTargetAnnotation = "aw.identity-key-only-target"

// Lifecycle cleanup must not renew the credential it is about to retire.
const identityNoRenewalAnnotation = "aw.identity-no-renewal"
