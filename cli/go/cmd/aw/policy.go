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

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Compatibility alias for project roles commands",
}

var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active project roles invariants and selected role guidance",
	RunE:  runPolicyShow,
}

var policyRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Compatibility alias for 'aw roles list'",
	RunE:  runPolicyRoles,
}

var (
	policyRoleNameFlag string
	policyAllRolesFlag bool
)

type policyShowOutput struct {
	RoleName     string                           `json:"role_name,omitempty"`
	Role         string                           `json:"role,omitempty"`
	OnlySelected bool                             `json:"only_selected"`
	ProjectRoles *aweb.ActiveProjectRolesResponse `json:"project_roles"`
	Policy       *aweb.ActiveProjectRolesResponse `json:"policy,omitempty"`
}

type policyRolesOutput struct {
	Roles []policyRoleItem `json:"roles"`
}

type policyRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

func init() {
	addProjectRolesShowFlags(policyShowCmd)

	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyRolesCmd)
	rootCmd.AddCommand(policyCmd)
}

func addProjectRolesShowFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&policyRoleNameFlag, "role-name", "", "Preview a specific role name")
	cmd.Flags().StringVar(&policyRoleNameFlag, "role", "", "Compatibility alias for --role-name")
	cmd.Flags().BoolVar(&policyAllRolesFlag, "all-roles", false, "Include all role playbooks instead of only the selected role")
}

func runPolicyShow(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	roleName := resolvePolicyRoleName(sel, policyRoleNameFlag)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{
		RoleName:     roleName,
		OnlySelected: !policyAllRolesFlag,
	})
	if err != nil {
		return err
	}

	printOutput(policyShowOutput{
		RoleName:     roleName,
		Role:         roleName,
		OnlySelected: !policyAllRolesFlag,
		ProjectRoles: resp,
		Policy:       resp,
	}, formatPolicyShow)
	return nil
}

func runPolicyRoles(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{
		OnlySelected: false,
	})
	if err != nil {
		return err
	}

	roles := make([]policyRoleItem, 0, len(resp.Roles))
	for name, info := range resp.Roles {
		title := strings.TrimSpace(info.Title)
		if title == "" {
			title = name
		}
		roles = append(roles, policyRoleItem{Name: name, Title: title})
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	printOutput(policyRolesOutput{Roles: roles}, formatPolicyRoles)
	return nil
}

func resolvePolicyRoleName(sel *awconfig.Selection, explicit string) string {
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

func formatPolicyShow(v any) string {
	out := v.(policyShowOutput)
	if out.ProjectRoles == nil {
		return "No active policy.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Project Roles v%d\n", out.ProjectRoles.Version))
	if out.RoleName != "" {
		sb.WriteString(fmt.Sprintf("Role: %s\n", out.RoleName))
	}

	if len(out.ProjectRoles.Invariants) > 0 {
		sb.WriteString("\n## Invariants\n")
		for _, inv := range out.ProjectRoles.Invariants {
			title := strings.TrimSpace(inv.Title)
			if title == "" {
				title = strings.TrimSpace(inv.ID)
			}
			sb.WriteString(fmt.Sprintf("- %s\n", title))
			body := strings.TrimSpace(inv.BodyMD)
			if body != "" {
				for _, line := range strings.Split(body, "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					sb.WriteString("  " + line + "\n")
				}
			}
		}
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
			sb.WriteString(fmt.Sprintf("- %s\n", title))
		}
	}

	return sb.String()
}

func formatPolicyRoles(v any) string {
	out := v.(policyRolesOutput)
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
