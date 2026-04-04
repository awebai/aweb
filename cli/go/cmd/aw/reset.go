package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove the local workspace binding in the current directory",
	Long:  "Removes the local .aw/context and .aw/workspace.yaml files in the current directory without mutating any server-side identity state.",
	RunE:  runReset,
}

func init() {
	rootCmd.AddCommand(resetCmd)
}

func runReset(cmd *cobra.Command, args []string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	removed := make([]string, 0, 2)
	ctxPath, ctxErr := awconfig.FindWorktreeContextPath(wd)
	if ctxErr == nil {
		if err := os.Remove(ctxPath); err != nil {
			return err
		}
		removed = append(removed, ctxPath)
	} else if !os.IsNotExist(ctxErr) {
		return ctxErr
	}

	workspacePath, wsErr := awconfig.FindWorktreeWorkspacePath(wd)
	if wsErr == nil {
		if err := os.Remove(workspacePath); err != nil {
			return err
		}
		removed = append(removed, workspacePath)
	} else if !os.IsNotExist(wsErr) {
		return wsErr
	}

	if len(removed) == 0 {
		fmt.Fprintln(os.Stderr, "No local .aw binding found in current directory.")
		return nil
	}

	awDir := filepath.Join(wd, ".aw")
	entries, readErr := os.ReadDir(awDir)
	if readErr == nil && len(entries) == 0 {
		_ = os.Remove(awDir)
	}

	for _, path := range removed {
		fmt.Fprintf(os.Stderr, "Removed %s\n", path)
	}
	return nil
}
