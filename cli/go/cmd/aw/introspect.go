package main

import (
	"github.com/spf13/cobra"
)

type introspectOutput struct {
	Alias      string `json:"alias,omitempty"`
	HumanName  string `json:"human_name,omitempty"`
	AgentType  string `json:"agent_type,omitempty"`
	AccessMode string `json:"access_mode,omitempty"`
	Address    string `json:"address,omitempty"`
	Domain     string `json:"domain,omitempty"`
	DID        string `json:"did,omitempty"`
	StableID   string `json:"stable_id,omitempty"`
	Custody    string `json:"custody,omitempty"`
	Lifetime   string `json:"lifetime,omitempty"`
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

		alias := sel.Alias

		out := introspectOutput{
			Alias:    alias,
			Domain:   sel.Domain,
			Address:  selectionAddress(sel),
			DID:      sel.DID,
			StableID: sel.StableID,
			Custody:  sel.Custody,
			Lifetime: sel.Lifetime,
		}
		if out.Address == "" {
			out.Address = deriveIdentityAddress(sel.Domain, alias)
		}
		printOutput(out, formatIntrospect)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(introspectCmd)
}
