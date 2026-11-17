package main

import (
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

// The ID-tree commands validate their command-specific record (prepared child
// or registered issuer) themselves, using the same command-owned sign closure.
// Namespace-only agent/root operations do not select a human key.
func prepareIDHumanSelection(cmd *cobra.Command) (bool, error) {
	tree := cmd.Parent() == idParentCmd || cmd.Parent() == idChildCmd || cmd == idRevokeCmd
	create := cmd == idCreateCmd && !cmd.Flags().Changed("org") && (humanSelectionRequested() || idCreateHumanParent != "")
	if !create && !(tree && humanSelectionRequested()) {
		return false, nil
	}
	if tree && humanFlag == "" {
		return true, nil
	}
	if humanFlag == "" || humanDomainFlag == "" {
		return true, usageError("select the person who signs with --human ID --human-domain DOMAIN")
	}
	if !create && (identityHomeFlag != "" || strings.TrimSpace(os.Getenv(awconfig.IdentityHomeEnv)) != "") {
		return true, usageError("--human conflicts with --identity-home or AWEB_IDENTITY_HOME; select one principal")
	}
	if create {
		if idCreateLocal || idCreateNoAddress {
			return true, usageError("key preparation does not issue a parent certificate; omit --human and --human-domain")
		}
		if idCreateHumanParent == "" || idCreateRootParent || strings.TrimSpace(idCreateHumanParent) != strings.TrimSpace(humanFlag) {
			return true, usageError("--human-parent names the parent person; --human must select that same person to sign")
		}
		domain, err := normalizeIDCreateDomain(idCreateDomain, false)
		if err != nil {
			return true, err
		}
		humanDomain, err := normalizeIDCreateDomain(humanDomainFlag, false)
		if err != nil {
			return true, err
		}
		if domain != humanDomain {
			return true, usageError("--human-domain must equal the child's --domain; ID chains cannot cross domains")
		}
	}
	return true, humanAtTerminal()
}

func removedIDDomainFlag(_ *cobra.Command, err error) error {
	if err.Error() == "unknown flag: --domain" {
		return usageError("--domain was removed from id parent, id child and id revoke; use --human-domain DOMAIN (with --human ID for a person, or --as-root for the namespace root)")
	}
	return err
}
