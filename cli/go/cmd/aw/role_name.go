package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var roleNameCmd = &cobra.Command{
	Use:   "role-name",
	Short: "Manage the current workspace role name",
}

var roleNameSetCmd = &cobra.Command{
	Use:   "set [role-name]",
	Short: "Set the current workspace role name",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRoleNameSet,
}

func init() {
	roleNameCmd.AddCommand(roleNameSetCmd)
	rootCmd.AddCommand(roleNameCmd)
	roleNameCmd.GroupID = groupCoordination
}

func runRoleNameSet(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	requested := ""
	if len(args) > 0 {
		requested = strings.TrimSpace(args[0])
	}

	roleName, err := resolveRole(client, requested, isTTY() && requested == "", os.Stdin, os.Stderr)
	if err != nil {
		return err
	}

	wd, _ := os.Getwd()
	_, err = autoAttachContext(wd, client, roleName)
	if err != nil {
		return fmt.Errorf("setting role name: %w", err)
	}
	fmt.Printf("Role name set to %s\n", roleName)
	return nil
}
