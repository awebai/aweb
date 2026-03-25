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
	Long:  "Removes the local .aw/context file in the current directory without mutating any server-side identity state.",
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

	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "No .aw/context found in current directory tree.")
		return nil
	}

	if err := os.Remove(ctxPath); err != nil {
		return err
	}

	awDir := filepath.Dir(ctxPath)
	entries, readErr := os.ReadDir(awDir)
	if readErr == nil && len(entries) == 0 {
		_ = os.Remove(awDir)
	}

	fmt.Fprintf(os.Stderr, "Removed %s\n", ctxPath)
	return nil
}
