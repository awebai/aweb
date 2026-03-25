package main

import (
	"context"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	directoryCapability string
	directoryNamespace  string
	directoryQuery      string
	directoryLimit      int
)

var directoryCmd = &cobra.Command{
	Use:   "directory [namespace/name]",
	Short: "Search or look up permanent identities in the network directory",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, err := resolveClient()
		if err != nil {
			return err
		}

		if len(args) == 1 {
			addr := awid.ParseNetworkAddress(args[0])
			if !addr.IsNetwork {
				return usageError("directory lookup requires namespace/name format, got: %q", args[0])
			}
			resp, err := c.NetworkDirectoryGet(ctx, addr.OrgSlug, addr.Alias)
			if err != nil {
				return err
			}
			printOutput(resp, formatDirectoryGet)
			return nil
		}

		resp, err := c.NetworkDirectorySearch(ctx, awid.NetworkDirectoryParams{
			Capability:    directoryCapability,
			NamespaceSlug: directoryNamespace,
			Query:         directoryQuery,
			Limit:         directoryLimit,
		})
		if err != nil {
			return err
		}
		printOutput(resp, formatDirectorySearch)
		return nil
	},
}

func init() {
	directoryCmd.Flags().StringVar(&directoryCapability, "capability", "", "Filter by capability")
	directoryCmd.Flags().StringVar(&directoryNamespace, "namespace", "", "Filter by namespace slug")
	directoryCmd.Flags().StringVar(&directoryQuery, "query", "", "Search handle/description")
	directoryCmd.Flags().IntVar(&directoryLimit, "limit", 100, "Max results")

	rootCmd.AddCommand(directoryCmd)
}
