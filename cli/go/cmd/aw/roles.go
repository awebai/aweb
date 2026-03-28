package main

import (
	"context"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Read project roles bundles and role definitions",
}

var rolesShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show active project roles invariants and selected role guidance",
	RunE:  runPolicyShow,
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

func init() {
	addProjectRolesShowFlags(rolesShowCmd)

	rolesCmd.AddCommand(rolesShowCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesSetCmd)
	rootCmd.AddCommand(rolesCmd)
	rolesCmd.GroupID = groupCoordination
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
	printOutput(policyRolesOutput{Roles: roles}, formatPolicyRoles)
	return nil
}

func fetchAvailableRoleItems(client *aweb.Client) ([]policyRoleItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{
		OnlySelected: false,
	})
	if err != nil {
		return nil, err
	}

	roles := make([]policyRoleItem, 0, len(resp.Roles))
	for name, info := range resp.Roles {
		title := strings.TrimSpace(info.Title)
		if title == "" {
			title = name
		}
		roles = append(roles, policyRoleItem{Name: name, Title: title})
	}
	return roles, nil
}
