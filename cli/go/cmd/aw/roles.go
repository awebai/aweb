package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Read and manage team roles bundles and role definitions",
}

var rolesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show role guidance from the active team roles bundle",
	RunE:  runTeamRolesShow,
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles defined in the active team roles bundle",
	RunE:  runRolesList,
}

var rolesHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List team roles history",
	RunE:  runRolesHistory,
}

var rolesSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create and activate a new team roles bundle version",
	RunE:  runRolesSet,
}

var rolesActivateCmd = &cobra.Command{
	Use:   "activate <team-roles-id>",
	Short: "Activate an existing team roles bundle version",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesActivate,
}

var rolesResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset team roles to the server default bundle",
	RunE:  runRolesReset,
}

var rolesDeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate team roles by replacing the active bundle with an empty bundle",
	RunE:  runRolesDeactivate,
}

var (
	rolesShowRoleNameFlag string
	rolesShowAllFlag      bool
	rolesHistoryLimit     int
	rolesSetBundleJSON    string
	rolesSetBundleFile    string
)

type teamRolesShowOutput struct {
	RoleName     string                        `json:"role_name,omitempty"`
	Role         string                        `json:"role,omitempty"`
	OnlySelected bool                          `json:"only_selected"`
	TeamRoles    *aweb.ActiveTeamRolesResponse `json:"team_roles"`
}

type teamRolesListOutput struct {
	Roles []teamRoleItem `json:"roles"`
}

type teamRolesSetOutput struct {
	TeamRolesID string `json:"team_roles_id"`
	Version     int    `json:"version"`
	Activated   bool   `json:"activated"`
}

type teamRolesActivateOutput struct {
	TeamRolesID string `json:"team_roles_id"`
	Activated   bool   `json:"activated"`
}

type teamRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

func init() {
	addRolesShowFlags(rolesShowCmd)
	rolesHistoryCmd.Flags().IntVar(&rolesHistoryLimit, "limit", 20, "Max role bundle versions")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleJSON, "bundle-json", "", "Team roles bundle JSON")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleFile, "bundle-file", "", "Read team roles bundle JSON from file ('-' for stdin)")

	rolesCmd.AddCommand(rolesShowCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesHistoryCmd)
	rolesCmd.AddCommand(rolesSetCmd)
	rolesCmd.AddCommand(rolesActivateCmd)
	rolesCmd.AddCommand(rolesResetCmd)
	rolesCmd.AddCommand(rolesDeactivateCmd)
	rootCmd.AddCommand(rolesCmd)
	rolesCmd.GroupID = groupCoordination
}

func addRolesShowFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&rolesShowRoleNameFlag, "role-name", "", "Preview a specific role name")
	cmd.Flags().StringVar(&rolesShowRoleNameFlag, "role", "", "Compatibility alias for --role-name")
	cmd.Flags().BoolVar(&rolesShowAllFlag, "all-roles", false, "Include all role playbooks instead of only the selected role")
}

func runTeamRolesShow(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	roleName := resolveRequestedRoleName(sel, rolesShowRoleNameFlag)
	if rolesShowAllFlag {
		roleName = ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{
		RoleName:     roleName,
		OnlySelected: !rolesShowAllFlag,
	})
	if err != nil {
		return err
	}

	printOutput(teamRolesShowOutput{
		RoleName:     roleName,
		Role:         roleName,
		OnlySelected: !rolesShowAllFlag,
		TeamRoles:    resp,
	}, formatTeamRolesShow)
	return nil
}

func runRolesList(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}
	roles, err := fetchAvailableRoleItems(client)
	if err != nil {
		return err
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	printOutput(teamRolesListOutput{Roles: roles}, formatTeamRolesList)
	return nil
}

func runRolesHistory(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TeamRolesHistory(ctx, rolesHistoryLimit)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesHistory)
	return nil
}

func runRolesSet(cmd *cobra.Command, args []string) error {
	bundle, err := resolveRolesBundle(cmd.InOrStdin(), rolesSetBundleJSON, rolesSetBundleFile)
	if err != nil {
		return err
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	active, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{OnlySelected: false})
	if err != nil {
		return err
	}

	created, err := client.CreateTeamRoles(ctx, &aweb.CreateTeamRolesRequest{
		Bundle:          bundle,
		BaseTeamRolesID: active.TeamRolesID,
	})
	if err != nil {
		return err
	}

	if _, err := client.ActivateTeamRoles(ctx, created.TeamRolesID); err != nil {
		return err
	}

	printOutput(teamRolesSetOutput{
		TeamRolesID: created.TeamRolesID,
		Version:     created.Version,
		Activated:   true,
	}, formatTeamRolesSet)
	return nil
}

func runRolesActivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivateTeamRoles(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}

	printOutput(teamRolesActivateOutput{
		TeamRolesID: resp.ActiveTeamRolesID,
		Activated:   resp.Activated,
	}, formatTeamRolesActivate)
	return nil
}

func runRolesReset(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ResetTeamRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesReset)
	return nil
}

func runRolesDeactivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.DeactivateTeamRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesDeactivate)
	return nil
}

func fetchAvailableRoleItems(client *aweb.Client) ([]teamRoleItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{
		OnlySelected: false,
	})
	if err != nil {
		return nil, err
	}

	roles := make([]teamRoleItem, 0, len(resp.Roles))
	for name, info := range resp.Roles {
		title := strings.TrimSpace(info.Title)
		if title == "" {
			title = name
		}
		roles = append(roles, teamRoleItem{Name: name, Title: title})
	}
	return roles, nil
}

func resolveRequestedRoleName(sel *awconfig.Selection, explicit string) string {
	if roleName := strings.TrimSpace(explicit); roleName != "" {
		return roleName
	}
	wd, _ := os.Getwd()
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(wd); err == nil {
		if membership, err := workspaceMembershipForSelection(state, sel); err == nil && membership != nil {
			if roleName := strings.TrimSpace(membership.RoleName); roleName != "" {
				return roleName
			}
		}
	}
	_ = sel
	return "developer"
}

func resolveRolesBundle(stdin io.Reader, bundleJSON, bundleFile string) (aweb.TeamRolesBundle, error) {
	bundleJSON = strings.TrimSpace(bundleJSON)
	bundleFile = strings.TrimSpace(bundleFile)

	var raw []byte
	switch {
	case bundleJSON != "" && bundleFile != "":
		return aweb.TeamRolesBundle{}, usageError("use only one of --bundle-json or --bundle-file")
	case bundleJSON != "":
		raw = []byte(bundleJSON)
	case bundleFile == "":
		return aweb.TeamRolesBundle{}, usageError("missing required flag: --bundle-json or --bundle-file")
	case bundleFile == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		raw = data
	default:
		data, err := os.ReadFile(bundleFile)
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		raw = data
	}

	var bundle aweb.TeamRolesBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return aweb.TeamRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: %w", err)
	}
	if bundle.Roles == nil {
		bundle.Roles = map[string]aweb.RoleDefinition{}
	}
	return bundle, nil
}

func formatTeamRolesShow(v any) string {
	out := v.(teamRolesShowOutput)
	if out.TeamRoles == nil {
		return "No active team roles.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Team Roles v%d\n", out.TeamRoles.Version))
	if out.RoleName != "" {
		sb.WriteString(fmt.Sprintf("Role: %s\n", out.RoleName))
	}

	if out.TeamRoles.SelectedRole != nil {
		sb.WriteString(fmt.Sprintf("\n## Role: %s\n", out.TeamRoles.SelectedRole.Title))
		for _, line := range strings.Split(strings.TrimSpace(out.TeamRoles.SelectedRole.PlaybookMD), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}

	if len(out.TeamRoles.Roles) > 0 {
		names := make([]string, 0, len(out.TeamRoles.Roles))
		for name := range out.TeamRoles.Roles {
			names = append(names, name)
		}
		sort.Strings(names)
		sb.WriteString("\n## Roles\n")
		for _, name := range names {
			role := out.TeamRoles.Roles[name]
			title := strings.TrimSpace(role.Title)
			if title == "" {
				title = name
			}
			sb.WriteString(fmt.Sprintf("\n### %s\n", title))
			playbook := strings.TrimSpace(role.PlaybookMD)
			if playbook == "" {
				sb.WriteString("(no playbook)\n")
				continue
			}
			for _, line := range strings.Split(playbook, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				sb.WriteString(line + "\n")
			}
		}
	}

	return sb.String()
}

func formatTeamRolesList(v any) string {
	out := v.(teamRolesListOutput)
	if len(out.Roles) == 0 {
		return "No roles defined.\n"
	}
	var sb strings.Builder
	for _, role := range out.Roles {
		if role.Title != "" && role.Title != role.Name {
			sb.WriteString(fmt.Sprintf("%s\t%s\n", role.Name, role.Title))
		} else {
			sb.WriteString(role.Name + "\n")
		}
	}
	return sb.String()
}

func formatTeamRolesHistory(v any) string {
	out := v.(*aweb.TeamRolesHistoryResponse)
	if out == nil || len(out.TeamRolesVersions) == 0 {
		return "No team roles versions.\n"
	}

	var sb strings.Builder
	for _, item := range out.TeamRolesVersions {
		status := "inactive"
		if item.IsActive {
			status = "active"
		}
		sb.WriteString(fmt.Sprintf("v%d\t%s\t%s\t%s", item.Version, status, item.CreatedAt, item.TeamRolesID))
		if item.CreatedByAlias != nil && strings.TrimSpace(*item.CreatedByAlias) != "" {
			sb.WriteString("\t" + strings.TrimSpace(*item.CreatedByAlias))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatTeamRolesSet(v any) string {
	out := v.(teamRolesSetOutput)
	return fmt.Sprintf("Activated team roles v%d (%s)\n", out.Version, out.TeamRolesID)
}

func formatTeamRolesActivate(v any) string {
	out := v.(teamRolesActivateOutput)
	return fmt.Sprintf("Activated team roles %s\n", out.TeamRolesID)
}

func formatTeamRolesReset(v any) string {
	out := v.(*aweb.ResetTeamRolesResponse)
	if out == nil {
		return "Team roles reset.\n"
	}
	return fmt.Sprintf("Reset team roles to default (v%d, %s)\n", out.Version, out.ActiveTeamRolesID)
}

func formatTeamRolesDeactivate(v any) string {
	out := v.(*aweb.DeactivateTeamRolesResponse)
	if out == nil {
		return "Team roles deactivated.\n"
	}
	return fmt.Sprintf("Deactivated team roles (v%d, %s)\n", out.Version, out.ActiveTeamRolesID)
}
