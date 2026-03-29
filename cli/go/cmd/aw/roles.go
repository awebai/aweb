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
	Short: "Read and manage project roles bundles and role definitions",
}

var rolesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show role guidance from the active project roles bundle",
	RunE:  runProjectRolesShow,
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles defined in the active project roles bundle",
	RunE:  runRolesList,
}

var rolesHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List project roles history",
	RunE:  runRolesHistory,
}

var rolesSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create and activate a new project roles bundle version",
	RunE:  runRolesSet,
}

var rolesActivateCmd = &cobra.Command{
	Use:   "activate <project-roles-id>",
	Short: "Activate an existing project roles bundle version",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesActivate,
}

var rolesResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset project roles to the server default bundle",
	RunE:  runRolesReset,
}

var rolesDeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate project roles by replacing the active bundle with an empty bundle",
	RunE:  runRolesDeactivate,
}

var (
	rolesShowRoleNameFlag string
	rolesShowAllFlag      bool
	rolesHistoryLimit     int
	rolesSetBundleJSON    string
	rolesSetBundleFile    string
)

type projectRolesShowOutput struct {
	RoleName     string                           `json:"role_name,omitempty"`
	Role         string                           `json:"role,omitempty"`
	OnlySelected bool                             `json:"only_selected"`
	ProjectRoles *aweb.ActiveProjectRolesResponse `json:"project_roles"`
}

type projectRolesListOutput struct {
	Roles []projectRoleItem `json:"roles"`
}

type projectRolesSetOutput struct {
	ProjectRolesID string `json:"project_roles_id"`
	Version        int    `json:"version"`
	Activated      bool   `json:"activated"`
}

type projectRolesActivateOutput struct {
	ProjectRolesID string `json:"project_roles_id"`
	Activated      bool   `json:"activated"`
}

type projectRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

func init() {
	addRolesShowFlags(rolesShowCmd)
	rolesHistoryCmd.Flags().IntVar(&rolesHistoryLimit, "limit", 20, "Max role bundle versions")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleJSON, "bundle-json", "", "Project roles bundle JSON")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleFile, "bundle-file", "", "Read project roles bundle JSON from file ('-' for stdin)")

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

func runProjectRolesShow(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	roleName := resolveRequestedRoleName(sel, rolesShowRoleNameFlag)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{
		RoleName:     roleName,
		OnlySelected: !rolesShowAllFlag,
	})
	if err != nil {
		return err
	}

	printOutput(projectRolesShowOutput{
		RoleName:     roleName,
		Role:         roleName,
		OnlySelected: !rolesShowAllFlag,
		ProjectRoles: resp,
	}, formatProjectRolesShow)
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
	printOutput(projectRolesListOutput{Roles: roles}, formatProjectRolesList)
	return nil
}

func runRolesHistory(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ProjectRolesHistory(ctx, rolesHistoryLimit)
	if err != nil {
		return err
	}
	printOutput(resp, formatProjectRolesHistory)
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

	active, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{OnlySelected: false})
	if err != nil {
		return err
	}

	created, err := client.CreateProjectRoles(ctx, &aweb.CreateProjectRolesRequest{
		Bundle:             bundle,
		BaseProjectRolesID: active.ProjectRolesID,
	})
	if err != nil {
		return err
	}

	if _, err := client.ActivateProjectRoles(ctx, created.ProjectRolesID); err != nil {
		return err
	}

	printOutput(projectRolesSetOutput{
		ProjectRolesID: created.ProjectRolesID,
		Version:        created.Version,
		Activated:      true,
	}, formatProjectRolesSet)
	return nil
}

func runRolesActivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivateProjectRoles(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}

	printOutput(projectRolesActivateOutput{
		ProjectRolesID: resp.ActiveProjectRolesID,
		Activated:      resp.Activated,
	}, formatProjectRolesActivate)
	return nil
}

func runRolesReset(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ResetProjectRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatProjectRolesReset)
	return nil
}

func runRolesDeactivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.DeactivateProjectRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatProjectRolesDeactivate)
	return nil
}

func fetchAvailableRoleItems(client *aweb.Client) ([]projectRoleItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{
		OnlySelected: false,
	})
	if err != nil {
		return nil, err
	}

	roles := make([]projectRoleItem, 0, len(resp.Roles))
	for name, info := range resp.Roles {
		title := strings.TrimSpace(info.Title)
		if title == "" {
			title = name
		}
		roles = append(roles, projectRoleItem{Name: name, Title: title})
	}
	return roles, nil
}

func resolveRequestedRoleName(sel *awconfig.Selection, explicit string) string {
	if roleName := strings.TrimSpace(explicit); roleName != "" {
		return roleName
	}
	wd, _ := os.Getwd()
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(wd); err == nil {
		if roleName := strings.TrimSpace(state.RoleName); roleName != "" {
			return roleName
		}
		if role := strings.TrimSpace(state.Role); role != "" {
			return role
		}
	}
	_ = sel
	return "developer"
}

func resolveRolesBundle(stdin io.Reader, bundleJSON, bundleFile string) (aweb.ProjectRolesBundle, error) {
	bundleJSON = strings.TrimSpace(bundleJSON)
	bundleFile = strings.TrimSpace(bundleFile)

	var raw []byte
	switch {
	case bundleJSON != "" && bundleFile != "":
		return aweb.ProjectRolesBundle{}, usageError("use only one of --bundle-json or --bundle-file")
	case bundleJSON != "":
		raw = []byte(bundleJSON)
	case bundleFile == "":
		return aweb.ProjectRolesBundle{}, usageError("missing required flag: --bundle-json or --bundle-file")
	case bundleFile == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return aweb.ProjectRolesBundle{}, err
		}
		raw = data
	default:
		data, err := os.ReadFile(bundleFile)
		if err != nil {
			return aweb.ProjectRolesBundle{}, err
		}
		raw = data
	}

	var bundle aweb.ProjectRolesBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return aweb.ProjectRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: %w", err)
	}
	if bundle.Roles == nil {
		bundle.Roles = map[string]aweb.RoleDefinition{}
	}
	return bundle, nil
}

func formatProjectRolesShow(v any) string {
	out := v.(projectRolesShowOutput)
	if out.ProjectRoles == nil {
		return "No active project roles.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Project Roles v%d\n", out.ProjectRoles.Version))
	if out.RoleName != "" {
		sb.WriteString(fmt.Sprintf("Role: %s\n", out.RoleName))
	}

	if out.ProjectRoles.SelectedRole != nil {
		sb.WriteString(fmt.Sprintf("\n## Role: %s\n", out.ProjectRoles.SelectedRole.Title))
		for _, line := range strings.Split(strings.TrimSpace(out.ProjectRoles.SelectedRole.PlaybookMD), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}

	if len(out.ProjectRoles.Roles) > 0 {
		names := make([]string, 0, len(out.ProjectRoles.Roles))
		for name := range out.ProjectRoles.Roles {
			names = append(names, name)
		}
		sort.Strings(names)
		sb.WriteString("\n## Roles\n")
		for _, name := range names {
			role := out.ProjectRoles.Roles[name]
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

func formatProjectRolesList(v any) string {
	out := v.(projectRolesListOutput)
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

func formatProjectRolesHistory(v any) string {
	out := v.(*aweb.ProjectRolesHistoryResponse)
	if out == nil || len(out.ProjectRolesVersions) == 0 {
		return "No project roles versions.\n"
	}

	var sb strings.Builder
	for _, item := range out.ProjectRolesVersions {
		status := "inactive"
		if item.IsActive {
			status = "active"
		}
		sb.WriteString(fmt.Sprintf("v%d\t%s\t%s\t%s", item.Version, status, item.CreatedAt, item.ProjectRolesID))
		if item.CreatedByWorkspaceID != nil && strings.TrimSpace(*item.CreatedByWorkspaceID) != "" {
			sb.WriteString("\t" + strings.TrimSpace(*item.CreatedByWorkspaceID))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatProjectRolesSet(v any) string {
	out := v.(projectRolesSetOutput)
	return fmt.Sprintf("Activated project roles v%d (%s)\n", out.Version, out.ProjectRolesID)
}

func formatProjectRolesActivate(v any) string {
	out := v.(projectRolesActivateOutput)
	return fmt.Sprintf("Activated project roles %s\n", out.ProjectRolesID)
}

func formatProjectRolesReset(v any) string {
	out := v.(*aweb.ResetProjectRolesResponse)
	if out == nil {
		return "Project roles reset.\n"
	}
	return fmt.Sprintf("Reset project roles to default (v%d, %s)\n", out.Version, out.ActiveProjectRolesID)
}

func formatProjectRolesDeactivate(v any) string {
	out := v.(*aweb.DeactivateProjectRolesResponse)
	if out == nil {
		return "Project roles deactivated.\n"
	}
	return fmt.Sprintf("Deactivated project roles (v%d, %s)\n", out.Version, out.ActiveProjectRolesID)
}
