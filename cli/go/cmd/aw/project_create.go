package main

import (
	"github.com/spf13/cobra"
)

var projectCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a project and initialize this directory as its first agent",
	Long: `Create a new aweb project and initialize the current directory as the
first agent workspace in it.

Human users normally start with aw run <provider>; aw project create is
the explicit create-project bootstrap primitive.`,
	RunE: runProjectCreate,
}

func init() {
	projectCreateCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	projectCreateCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	projectCreateCmd.Flags().StringVar(&initProjectSlug, "project", "", "Project slug (default: AWEB_PROJECT_SLUG, AWEB_PROJECT, or prompt in TTY)")
	projectCreateCmd.Flags().StringVar(&initNamespaceSlug, "namespace", "", "Authoritative namespace slug when it differs from the project slug (default: project slug)")
	projectCreateCmd.Flags().StringVar(&initNamespaceSlug, "namespace-slug", "", "Authoritative namespace slug (alias for --namespace)")
	projectCreateCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	projectCreateCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)")
	projectCreateCmd.Flags().StringVar(&initReachability, "reachability", "", "Permanent address reachability (private|org-visible|contacts-only|public)")
	projectCreateCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	projectCreateCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	projectCreateCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code channel MCP server for real-time coordination")
	projectCreateCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	projectCreateCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	projectCreateCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Ensure .aw/context exists in the current directory")
	projectCreateCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(projectCreateCmd, &initRole, "Workspace role name (must match a role in the active project roles bundle)")
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
		printInitSummary(result.Response, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, opts.WorkingDir, "Created project and initialized workspace")
	}
	printPostInitActions(result, opts.WorkingDir)
	return nil
}
