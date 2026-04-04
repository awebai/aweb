package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	inviteAlias   string
	inviteAccess  string
	inviteExpires string
	inviteUses    int
)

type inviteCreateOutput struct {
	*awid.SpawnInviteCreateResponse
	InitCommand string `json:"init_command"`
}

type inviteRevokeOutput struct {
	Status      string `json:"status"`
	TokenPrefix string `json:"token_prefix"`
}

var spawnCmd = &cobra.Command{
	Use:   "spawn",
	Short: "Authorize another workspace to join this project",
}

var spawnCreateInviteCmd = &cobra.Command{
	Use:   "create-invite",
	Short: "Create a spawn invite for another workspace",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		if inviteUses < 1 {
			return usageError("--uses must be >= 1")
		}
		expiresInSeconds, err := parseInviteExpirySeconds(inviteExpires)
		if err != nil {
			return err
		}
		accessMode, err := mapInviteAccessMode(inviteAccess)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.SpawnCreateInvite(ctx, &awid.SpawnInviteCreateRequest{
			AliasHint:        strings.TrimSpace(inviteAlias),
			AccessMode:       accessMode,
			MaxUses:          inviteUses,
			ExpiresInSeconds: expiresInSeconds,
		})
		if err != nil {
			return err
		}

		out := inviteCreateOutput{
			SpawnInviteCreateResponse: resp,
			InitCommand:               buildInviteInitCommand(resp.ServerURL, resp.Token, resp.AliasHint),
		}
		printOutput(out, formatInviteCreate)
		return nil
	},
}

var spawnListInvitesCmd = &cobra.Command{
	Use:   "list-invites",
	Short: "List active spawn invites",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.ListSpawnInvites(ctx)
		if err != nil {
			return err
		}
		printOutput(resp, formatInviteList)
		return nil
	},
}

var spawnRevokeInviteCmd = &cobra.Command{
	Use:   "revoke-invite <prefix>",
	Short: "Revoke a spawn invite by token prefix",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		prefix := strings.TrimSpace(args[0])
		if prefix == "" {
			return usageError("invite prefix is required")
		}

		client, err := resolveCloudClient()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		list, err := client.ListSpawnInvites(ctx)
		if err != nil {
			return err
		}
		match, err := findInviteByPrefix(list.Invites, prefix)
		if err != nil {
			return err
		}
		if err := client.RevokeSpawnInvite(ctx, match.InviteID); err != nil {
			return err
		}
		printOutput(inviteRevokeOutput{
			Status:      "revoked",
			TokenPrefix: match.TokenPrefix,
		}, formatInviteRevoke)
		return nil
	},
}

var spawnAcceptInviteCmd = &cobra.Command{
	Use:   "accept-invite <token>",
	Short: "Join an existing project in this directory from a spawn invite",
	Long: `Accept a spawn invite and initialize the current directory as a new
agent workspace in the target project.

In a TTY, aw will prompt for any missing alias, name, or role
information before initializing the workspace. Identities are
ephemeral by default; pass --permanent to create a durable
self-custodial identity instead.`,
	Args: cobra.ExactArgs(1),
	RunE: runSpawnAcceptInvite,
}

func init() {
	spawnCreateInviteCmd.Flags().StringVar(&inviteAlias, "alias", "", "Pre-assign a routing alias hint for the child workspace")
	spawnCreateInviteCmd.Flags().StringVar(&inviteAccess, "access", "open", "Access mode: project|owner|contacts|open")
	spawnCreateInviteCmd.Flags().StringVar(&inviteExpires, "expires", "24h", "Invite lifetime (examples: 24h, 7d)")
	spawnCreateInviteCmd.Flags().IntVar(&inviteUses, "uses", 1, "Maximum number of invite uses")

	spawnAcceptInviteCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	spawnAcceptInviteCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	spawnAcceptInviteCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: invite or server-suggested)")
	spawnAcceptInviteCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)")
	spawnAcceptInviteCmd.Flags().StringVar(&initReachability, "reachability", "", "Permanent address reachability (private|org-visible|contacts-only|public)")
	spawnAcceptInviteCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	spawnAcceptInviteCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	spawnAcceptInviteCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code channel MCP server for real-time coordination")
	spawnAcceptInviteCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	spawnAcceptInviteCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	spawnAcceptInviteCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	spawnAcceptInviteCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	spawnAcceptInviteCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	spawnAcceptInviteCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(spawnAcceptInviteCmd, &initRole, "Workspace role name (must match a role in the active project roles bundle)")
	spawnAcceptInviteCmd.Flags().BoolVar(&initPermanent, "permanent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")

	spawnCmd.AddCommand(spawnCreateInviteCmd)
	spawnCmd.AddCommand(spawnListInvitesCmd)
	spawnCmd.AddCommand(spawnRevokeInviteCmd)
	spawnCmd.AddCommand(spawnAcceptInviteCmd)
	rootCmd.AddCommand(spawnCmd)
}

func parseInviteExpirySeconds(raw string) (int, error) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		value = "24h"
	}
	if strings.HasSuffix(value, "d") {
		days := strings.TrimSuffix(value, "d")
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil || n <= 0 {
			return 0, usageError("invalid --expires value (examples: 24h, 7d)")
		}
		return n * 24 * 60 * 60, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, usageError("invalid --expires value (examples: 24h, 7d)")
	}
	return int(d.Seconds()), nil
}

func mapInviteAccessMode(raw string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "", "open":
		return "open", nil
	case "project", "project_only":
		return "project_only", nil
	case "owner", "owner_only":
		return "owner_only", nil
	case "contacts", "contacts_only":
		return "contacts_only", nil
	default:
		return "", usageError("invalid --access value (use project|owner|contacts|open)")
	}
}

func inviteTTLLabel(seconds int) string {
	if seconds%(24*60*60) == 0 {
		days := seconds / (24 * 60 * 60)
		if days == 1 {
			return "24h"
		}
		return fmt.Sprintf("%dd", days)
	}
	return formatDuration(seconds)
}

func buildInviteInitCommand(serverURL, token, alias string) string {
	var parts []string
	parts = append(parts, "aw", "spawn", "accept-invite", token)
	if rootURL, err := cloudRootBaseURL(serverURL); err == nil && strings.TrimSpace(rootURL) != "" {
		if strings.TrimSuffix(rootURL, "/") != strings.TrimSuffix(DefaultServerURL, "/") {
			parts = append(parts, "--server", rootURL)
		}
	}
	if strings.TrimSpace(alias) != "" {
		parts = append(parts, "--alias", alias)
	} else {
		parts = append(parts, "--alias", "<choose-an-alias>")
	}
	return strings.Join(parts, " ")
}

func formatInviteCreate(v any) string {
	out := v.(inviteCreateOutput)
	usesText := "single use"
	if out.MaxUses != 1 {
		usesText = fmt.Sprintf("%d uses", out.MaxUses)
	}
	ttl := inviteTTLLabel(ttlRemainingSeconds(out.ExpiresAt, time.Now().UTC()))
	if ttl == "0s" {
		ttl = out.ExpiresAt
	}
	return fmt.Sprintf("Spawn invite created (expires in %s, %s)\n\nRun this in the child workspace:\n  %s\n", ttl, usesText, out.InitCommand)
}

func formatInviteList(v any) string {
	resp := v.(*awid.SpawnInviteListResponse)
	if len(resp.Invites) == 0 {
		return "No spawn invites.\n"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%-10s %-16s %-6s %-12s %s\n", "PREFIX", "ALIAS HINT", "USES", "EXPIRES", "CREATED")
	for _, invite := range resp.Invites {
		alias := strings.TrimSpace(invite.AliasHint)
		if alias == "" {
			alias = "—"
		}
		fmt.Fprintf(&b, "%-10s %-16s %-6s %-12s %s\n",
			invite.TokenPrefix,
			alias,
			fmt.Sprintf("%d/%d", invite.CurrentUses, invite.MaxUses),
			formatInviteDate(invite.ExpiresAt),
			formatInviteDate(invite.CreatedAt),
		)
	}
	return b.String()
}

func formatInviteDate(timestamp string) string {
	ts, ok := parseTimeBestEffort(timestamp)
	if !ok {
		return timestamp
	}
	return ts.UTC().Format("2006-01-02")
}

func formatInviteRevoke(v any) string {
	out := v.(inviteRevokeOutput)
	return fmt.Sprintf("Spawn invite %s revoked\n", out.TokenPrefix)
}

func findInviteByPrefix(invites []awid.SpawnInviteListItem, prefix string) (*awid.SpawnInviteListItem, error) {
	var matches []awid.SpawnInviteListItem
	for i := range invites {
		if strings.HasPrefix(invites[i].TokenPrefix, prefix) {
			matches = append(matches, invites[i])
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("invite prefix %s not found", prefix)
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("invite prefix %s is ambiguous", prefix)
	}
	return &matches[0], nil
}

func newUnauthenticatedCloudClient(baseURL string) (*aweb.Client, error) {
	rootURL, err := cloudRootBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	return aweb.New(rootURL)
}

func runSpawnAcceptInvite(cmd *cobra.Command, args []string) error {
	token := strings.TrimSpace(args[0])
	if err := validateInitIdentityFlags(); err != nil {
		return err
	}
	permanent := initPermanent

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	opts, err := collectInviteInitOptionsWithInput(token, initCollectionInput{
		WorkingDir:  workingDir,
		Interactive: isTTY() && !jsonFlag,
		JSONOutput:  jsonFlag,
		PromptIn:    os.Stdin,
		PromptOut:   os.Stderr,
		ServerURL:   initServerURL,
		ServerName:  serverFlag,
		Alias: func() string {
			if permanent {
				return strings.TrimSpace(initAlias)
			}
			return resolveAliasValue(strings.TrimSpace(initAlias))
		}(),
		Name:            strings.TrimSpace(initName),
		Reachability:    strings.TrimSpace(initReachability),
		HumanName:       resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType:       resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		SaveConfig:      initSaveConfig,
		SetDefault:      initSetDefault,
		WriteContext:    initWriteContext,
		Role:            resolveRequestedRole(strings.TrimSpace(initRole)),
		Permanent:       permanent,
		PromptName:      isTTY() && !jsonFlag,
		DeferRolePrompt: isTTY() && !jsonFlag,
	})
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
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, opts.WorkingDir, "Accepted spawn invite")
	}
	printPostInitActions(result, opts.WorkingDir)
	return nil
}
