package main

import (
	"context"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	directoryCapability string
	directoryDomain     string
	directoryQuery      string
	directoryLimit      int
)

var directoryCmd = &cobra.Command{
	Use:   "directory [domain/name]",
	Short: "Search or look up persistent identities in the network directory",
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
				return usageError("directory lookup requires domain/name format, got: %q", args[0])
			}
			resp, err := c.NetworkDirectoryGet(ctx, addr.Domain, addr.Alias)
			if err != nil {
				return err
			}
			printOutput(resp, formatDirectoryGet)
			return nil
		}

		resp, err := c.NetworkDirectorySearch(ctx, awid.NetworkDirectoryParams{
			Capability: directoryCapability,
			Domain:     directoryDomain,
			Query:      directoryQuery,
			Limit:      directoryLimit,
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
	directoryCmd.Flags().StringVar(&directoryDomain, "domain", "", "Filter by domain")
	directoryCmd.Flags().StringVar(&directoryQuery, "query", "", "Search handle/description")
	directoryCmd.Flags().IntVar(&directoryLimit, "limit", 100, "Max results")

	rootCmd.AddCommand(directoryCmd)
}
