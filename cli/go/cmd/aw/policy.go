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
	Short: "Read project policy and role playbooks",
}

var policyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active policy invariants and role guidance",
	RunE:  runPolicyShow,
}

var policyRolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "List roles defined in the active policy",
	RunE:  runPolicyRoles,
}

var (
	policyRoleFlag     string
	policyAllRolesFlag bool
)

type policyShowOutput struct {
	Role         string                     `json:"role"`
	OnlySelected bool                       `json:"only_selected"`
	Policy       *aweb.ActivePolicyResponse `json:"policy"`
}

type policyRolesOutput struct {
	Roles []policyRoleItem `json:"roles"`
}

type policyRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

func init() {
	policyShowCmd.Flags().StringVar(&policyRoleFlag, "role", "", "Preview a specific role")
	policyShowCmd.Flags().BoolVar(&policyAllRolesFlag, "all-roles", false, "Include all role playbooks instead of only the selected role")

	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyRolesCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyShow(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	role := resolvePolicyRole(sel, policyRoleFlag)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivePolicy(ctx, aweb.ActivePolicyParams{
		Role:         role,
		OnlySelected: !policyAllRolesFlag,
	})
	if err != nil {
		return err
	}

	printOutput(policyShowOutput{
		Role:         role,
		OnlySelected: !policyAllRolesFlag,
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

	resp, err := client.ActivePolicy(ctx, aweb.ActivePolicyParams{
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

func resolvePolicyRole(sel *awconfig.Selection, explicit string) string {
	if role := strings.TrimSpace(explicit); role != "" {
		return role
	}
	wd, _ := os.Getwd()
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(wd); err == nil {
		if role := strings.TrimSpace(state.Role); role != "" {
			return role
		}
	}
	_ = sel
	return "developer"
}

func formatPolicyShow(v any) string {
	out := v.(policyShowOutput)
	if out.Policy == nil {
		return "No active policy.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Policy v%d\n", out.Policy.Version))
	if out.Role != "" {
		sb.WriteString(fmt.Sprintf("Role: %s\n", out.Role))
	}

	if len(out.Policy.Invariants) > 0 {
		sb.WriteString("\n## Invariants\n")
		for _, inv := range out.Policy.Invariants {
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

	if out.Policy.SelectedRole != nil {
		sb.WriteString(fmt.Sprintf("\n## Role: %s\n", out.Policy.SelectedRole.Title))
		for _, line := range strings.Split(strings.TrimSpace(out.Policy.SelectedRole.PlaybookMD), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}

	if len(out.Policy.Roles) > 0 {
		names := make([]string, 0, len(out.Policy.Roles))
		for name := range out.Policy.Roles {
			names = append(names, name)
		}
		sort.Strings(names)
		sb.WriteString("\n## Roles\n")
		for _, name := range names {
			role := out.Policy.Roles[name]
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
