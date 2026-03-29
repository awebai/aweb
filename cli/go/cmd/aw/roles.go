package main

import (
	"context"
	"fmt"
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
	Short: "Read project roles bundles and role definitions",
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

var rolesSetCmd = &cobra.Command{
	Use:    "set [role-name]",
	Short:  "Compatibility alias for 'aw role-name set'",
	Args:   cobra.MaximumNArgs(1),
	RunE:   runRoleNameSet,
	Hidden: true,
}

var (
	rolesShowRoleNameFlag string
	rolesShowAllFlag      bool
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

type projectRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

func init() {
	addRolesShowFlags(rolesShowCmd)

	rolesCmd.AddCommand(rolesShowCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesSetCmd)
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
