package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Manage workspace roles",
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available roles from the project policy",
	RunE:  runRolesList,
}

var rolesSetCmd = &cobra.Command{
	Use:   "set [role]",
	Short: "Set the current workspace's role",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRolesSet,
}

func init() {
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

	roles, err := fetchAvailableRoles(client)
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		fmt.Println("No roles defined in the active project policy.")
		return nil
	}

	if jsonFlag {
		printJSON(roles)
		return nil
	}

	for i, role := range roles {
		fmt.Printf("  %d. %s\n", i+1, role)
	}
	return nil
}

func runRolesSet(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	requested := ""
	if len(args) > 0 {
		requested = strings.TrimSpace(args[0])
	}

	role, err := resolveRole(client, requested, isTTY() && requested == "", os.Stdin, os.Stderr)
	if err != nil {
		return err
	}

	wd, _ := os.Getwd()
	_, err = autoAttachContext(wd, client, role)
	if err != nil {
		return fmt.Errorf("setting role: %w", err)
	}
	fmt.Printf("Role set to %s\n", role)
	return nil
}
