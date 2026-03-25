package main

import (
	"github.com/spf13/cobra"
)

var projectCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a project and initialize its first workspace",
	RunE:  runProjectCreate,
}

func init() {
	projectCreateCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	projectCreateCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	projectCreateCmd.Flags().StringVar(&initProjectSlug, "project", "", "Project slug (default: AWEB_PROJECT_SLUG, AWEB_PROJECT, or prompt in TTY)")
	projectCreateCmd.Flags().StringVar(&initNamespaceSlug, "namespace", "", "Authoritative namespace slug when it differs from the project slug (default: project slug)")
	projectCreateCmd.Flags().StringVar(&initNamespaceSlug, "namespace-slug", "", "Authoritative namespace slug (alias for --namespace)")
	projectCreateCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	projectCreateCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent)")
	projectCreateCmd.Flags().StringVar(&initReachability, "reachability", "", "Permanent address reachability (private|org-visible|contacts-only|public)")
	projectCreateCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	projectCreateCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	projectCreateCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	projectCreateCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	projectCreateCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	projectCreateCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	projectCreateCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	projectCreateCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	projectCreateCmd.Flags().StringVar(&initRole, "role", "", "Workspace role (must match a role in the active project policy)")
	projectCreateCmd.Flags().BoolVar(&initPermanent, "permanent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")
	projectCmd.AddCommand(projectCreateCmd)
}

func runProjectCreate(cmd *cobra.Command, args []string) error {
	opts, err := collectInitOptionsForFlow(flowHeadless)
	if err != nil {
		return err
	}
	result, err := executeInit(opts)
	if err != nil {
		return err
	}

	if jsonFlag {
		printJSON(result.Response)
	} else {
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, "Created project and initialized workspace")
	}
	printPostInitActions(result, opts.WorkingDir)
	return nil
}
