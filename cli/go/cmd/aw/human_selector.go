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
	if tree {
		if humanDomainFlag != "" && humanFlag == "" {
			return true, usageError("--human-domain requires --human ID; use --domain for an agent or --as-root organization")
		}
		if humanFlag != "" && cmd.Flags().Changed("domain") {
			// The released per-command form --human ID --domain DOMAIN keeps
			// working: --domain is then the person's domain. Both flags may
			// be given only when they name the same domain.
			domain, _ := cmd.Flags().GetString("domain")
			switch {
			case strings.TrimSpace(humanDomainFlag) == "":
				humanDomainFlag = strings.TrimSpace(domain)
			case !strings.EqualFold(strings.TrimSpace(domain), strings.TrimSpace(humanDomainFlag)):
				return true, usageError("--domain and --human-domain name different domains; with --human, both name the person's domain")
			}
		}
		if humanFlag != "" {
			asRoot, _ := cmd.Flags().GetBool("as-root")
			if asRoot {
				return true, usageError("--human and --as-root name different actors; choose one")
			}
		}
	}
	if create && strings.TrimSpace(idCreateHumanParent) != "" {
		// The released form aw id create --human-parent ID --domain DOMAIN
		// (aw 1.36.58) keeps working: the parent person signs, in the
		// child's domain. The checks below still apply when either is named.
		if humanFlag == "" {
			humanFlag = strings.TrimSpace(idCreateHumanParent)
		}
		if humanDomainFlag == "" {
			humanDomainFlag = strings.TrimSpace(idCreateDomain)
		}
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

// Organization input and person selection are different questions. With
// --human, the person's domain is --human-domain, or --domain in the released
// per-command form (prepareIDHumanSelection copies it).
func idCommandDomain(organization string) string {
	if humanFlag != "" {
		return humanDomainFlag
	}
	return organization
}
