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

func isIdentityHomeNeutralCommand(cmd *cobra.Command) bool {
	_, ok := identityHomeNeutralCommandExemptions[cmd]
	return ok || (cmd.Annotations[hostHumanOrgAnnotation] == "true" && cmd.Flags().Changed("org"))
}

// Creation targets may be fresh only when explicitly selected by flag. This
// does not confer command authority or permit overwriting an inherited actor.
const identityCreationTargetAnnotation = "aw.identity-creation-target"

// Only explicit organization selection uses host-human authority without a principal.
const hostHumanOrgAnnotation = "aw.host-human-org"
