package main

import (
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

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
		_, sel, err := resolveClientSelection()
		if err != nil {
			return err
		}

		alias := sel.IdentityHandle

		out := introspectOutput{
			IntrospectResponse: awid.IntrospectResponse{
				Alias:         alias,
				NamespaceSlug: sel.NamespaceSlug,
				Address:       selectionAddress(sel),
			},
			DID:      sel.DID,
			StableID: sel.StableID,
			Custody:  sel.Custody,
			Lifetime: sel.Lifetime,
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
