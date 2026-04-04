package main

import (
	"context"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// introspectOutput combines the server's introspect response with local identity fields.
type introspectOutput struct {
	awid.IntrospectResponse
	DID      string `json:"did,omitempty"`
	StableID string `json:"stable_id,omitempty"`
	Custody  string `json:"custody,omitempty"`
	Lifetime string `json:"lifetime,omitempty"`
}

var introspectCmd = &cobra.Command{
	Use:     "whoami",
	Aliases: []string{"introspect"},
	Short:   "Show the current identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, sel, err := resolveAPIKeyOnly()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := client.Introspect(ctx)
		if err != nil {
			return err
		}

		alias := resp.IdentityHandle()
		if alias == "" {
			alias = sel.IdentityHandle
		}

		out := introspectOutput{
			IntrospectResponse: *resp,
			DID:                sel.DID,
			StableID:           sel.StableID,
			Custody:            sel.Custody,
			Lifetime:           sel.Lifetime,
		}
		// Prefer server-returned values; fall back to local config.
		if out.NamespaceSlug == "" {
			out.NamespaceSlug = sel.NamespaceSlug
		}
		if out.Address == "" {
			out.Address = deriveIdentityAddress(sel.NamespaceSlug, sel.DefaultProject, alias)
		}
		printOutput(out, formatIntrospect)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
